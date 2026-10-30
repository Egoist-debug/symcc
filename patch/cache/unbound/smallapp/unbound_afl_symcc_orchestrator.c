#include "config.h"

#include "smallapp/unbound_afl_symcc_orchestrator.h"
#include "smallapp/unbound_afl_symcc_mutator_server.h"

#include "daemon/cachedump.h"
#include "daemon/worker.h"
#include "libunbound/context.h"
#include "libunbound/unbound.h"
#include "sldns/sbuffer.h"
#include "sldns/wire2str.h"
#include "util/data/dname.h"
#include "util/data/msgparse.h"
#include "util/regional.h"

#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define UNBOUND_AFL_SYMCC_FWD_STR_MAX 64
#define UNBOUND_AFL_SYMCC_TRANSCRIPT_MAGIC "DST1"
#define UNBOUND_AFL_SYMCC_TRANSCRIPT_MAX_RESPONSES 16
#define UNBOUND_AFL_SYMCC_MAX_TRANSCRIPT_INPUT 16384

typedef struct unbound_afl_symcc_transcript {
	const uint8_t *client_query;
	size_t client_query_len;
	const uint8_t *post_check_query;
	size_t post_check_query_len;
	const uint8_t *responses[UNBOUND_AFL_SYMCC_TRANSCRIPT_MAX_RESPONSES];
	size_t response_lens[UNBOUND_AFL_SYMCC_TRANSCRIPT_MAX_RESPONSES];
	size_t response_count;
} unbound_afl_symcc_transcript_t;

static unbound_afl_symcc_oracle_t *g_active_oracle = NULL;

int
ssl_printf(RES *stream, const char *format, ...)
{
	char buffer[4096];
	va_list args;
	int written = 0;

	if (stream == NULL || stream->fd < 0 || format == NULL) {
		return 0;
	}

	va_start(args, format);
	written = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	if (written < 0) {
		return 0;
	}
	if (written >= (int)sizeof(buffer)) {
		written = (int)sizeof(buffer) - 1;
	}

	return write(stream->fd, buffer, (size_t)written) == written;
}

int
ssl_read_line(RES *stream, char *buffer, size_t max)
{
	size_t len = 0;

	if (stream == NULL || stream->fd < 0 || buffer == NULL || max == 0) {
		return 0;
	}

	while (len + 1 < max) {
		ssize_t n = read(stream->fd, buffer + len, 1);
		if (n == 0) {
			buffer[len] = '\0';
			return 1;
		}
		if (n < 0) {
			return 0;
		}
		if (buffer[len] == '\n') {
			len++;
			buffer[len] = '\0';
			return 1;
		}
		len++;
	}

	buffer[len] = '\0';
	return 1;
}

static bool
logging_enabled(void)
{
	const char *env = getenv("UNBOUND_RESOLVER_AFL_SYMCC_LOG");
	return env != NULL && strcmp(env, "0") != 0;
}

static bool
debug_enabled(void)
{
	const char *env = getenv("UNBOUND_RESOLVER_AFL_SYMCC_DEBUG");
	return env != NULL && strcmp(env, "0") != 0;
}

static void
log_result(const unbound_afl_symcc_oracle_t *oracle)
{
	if (!logging_enabled()) {
		return;
	}

	fprintf(stderr,
		"ORACLE_SUMMARY parse_ok=%u resolver_fetch_started=%u "
		"fake_reply_dispatched=%u response_accepted=%u second_query_hit=%u "
		"cache_entry_created=%u timeout=%u\n",
		oracle->parse_ok ? 1U : 0U,
		oracle->resolver_fetch_started ? 1U : 0U,
		oracle->fake_reply_dispatched ? 1U : 0U,
		oracle->response_accepted ? 1U : 0U,
		oracle->second_query_hit ? 1U : 0U,
		oracle->cache_entry_created ? 1U : 0U,
		oracle->timeout ? 1U : 0U);

	fprintf(stderr, "Requests sent: %u\n",
		oracle->resolver_fetch_started ? 1U : 0U);
	fprintf(stderr, "Replies received: %u\n",
		oracle->response_accepted ? 1U : 0U);
	fprintf(stderr, "Oracle parse_ok: %u\n",
		oracle->parse_ok ? 1U : 0U);
	fprintf(stderr, "Oracle resolver_fetch_started: %u\n",
		oracle->resolver_fetch_started ? 1U : 0U);
	fprintf(stderr, "Oracle response_accepted: %u\n",
		oracle->response_accepted ? 1U : 0U);
	fprintf(stderr, "Oracle second_query_hit: %u\n",
		oracle->second_query_hit ? 1U : 0U);
	fprintf(stderr, "Oracle cache_entry_created: %u\n",
		oracle->cache_entry_created ? 1U : 0U);
	fprintf(stderr, "Oracle timeout: %u\n",
		oracle->timeout ? 1U : 0U);
}

static void
log_stage_failure(const char *stage)
{
	if (!logging_enabled()) {
		return;
	}
	fprintf(stderr, "Stage failure: %s\n", stage);
}

static int
configure_ctx(struct ub_ctx *ctx, const char *forwarder, bool disable_cache)
{
	if (ub_ctx_set_option(ctx, "module-config:", "iterator") != UB_NOERROR) {
		return 1;
	}
	if (ub_ctx_set_option(ctx, "do-ip6:", "no") != UB_NOERROR) {
		return 1;
	}
	if (ub_ctx_set_option(ctx, "do-ip4:", "yes") != UB_NOERROR) {
		return 1;
	}
	if (ub_ctx_set_option(ctx, "tcp-upstream:", "no") != UB_NOERROR) {
		return 1;
	}
	if (ub_ctx_set_option(ctx, "target-fetch-policy:", "0 0 0 0 0") !=
		UB_NOERROR)
	{
		return 1;
	}
	if (disable_cache) {
		/* parser-lite 阶段显式关缓存，避免把 query fuzz 误解释成 cache hit */
		if (ub_ctx_set_option(ctx, "msg-cache-size:", "0") != UB_NOERROR) {
			return 1;
		}
		if (ub_ctx_set_option(ctx, "rrset-cache-size:", "0") != UB_NOERROR) {
			return 1;
		}
	}
	if (ub_ctx_set_fwd(ctx, forwarder) != UB_NOERROR) {
		return 1;
	}
	return 0;
}

static uint16_t
read_u16le(const uint8_t *data)
{
	return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static bool
looks_like_transcript(const uint8_t *input, size_t input_len)
{
	return input_len >= 4 &&
		memcmp(input, UNBOUND_AFL_SYMCC_TRANSCRIPT_MAGIC, 4) == 0;
}

static bool
parse_transcript_input(const uint8_t *input, size_t input_len,
	unbound_afl_symcc_transcript_t *transcript)
{
	size_t cursor = 0;
	size_t header_len = 0;
	size_t index;

	if (transcript != NULL) {
		memset(transcript, 0, sizeof(*transcript));
	}

	if (input == NULL || transcript == NULL || input_len < 10 ||
		input_len > UNBOUND_AFL_SYMCC_MAX_TRANSCRIPT_INPUT ||
		!looks_like_transcript(input, input_len))
	{
		return false;
	}

	transcript->response_count = input[4];
	if (transcript->response_count >
		UNBOUND_AFL_SYMCC_TRANSCRIPT_MAX_RESPONSES)
	{
		return false;
	}

	header_len = 10 + transcript->response_count * 2;
	if (header_len > input_len) {
		return false;
	}

	cursor = header_len;
	transcript->client_query_len = read_u16le(input + 6);
	transcript->post_check_query_len = read_u16le(input + 8);
	if (transcript->client_query_len == 0 ||
		cursor + transcript->client_query_len > input_len)
	{
		return false;
	}

	transcript->client_query = input + cursor;
	cursor += transcript->client_query_len;

	for (index = 0; index < transcript->response_count; index++) {
		size_t response_len = read_u16le(input + 10 + index * 2);

		if (response_len == 0 || cursor + response_len > input_len) {
			return false;
		}

		transcript->responses[index] = input + cursor;
		transcript->response_lens[index] = response_len;
		cursor += response_len;
	}

	if (transcript->post_check_query_len > 0) {
		if (cursor + transcript->post_check_query_len != input_len) {
			return false;
		}

		transcript->post_check_query = input + cursor;
	} else if (cursor != input_len) {
		return false;
	}

	return true;
}

static bool
write_file_bytes(const char *path, const uint8_t *data, size_t data_len)
{
	FILE *fp = NULL;
	size_t written = 0;

	if (path == NULL || data == NULL || data_len == 0) {
		return false;
	}

	fp = fopen(path, "wb");
	if (fp == NULL) {
		return false;
	}

	written = fwrite(data, 1, data_len, fp);
	fclose(fp);
	return written == data_len;
}

static bool
materialize_transcript_responses(const unbound_afl_symcc_transcript_t *transcript,
	char *dir_path, size_t dir_path_size)
{
	const char *tmp_root = getenv("TMPDIR");
	size_t index;
	size_t created = 0;

	if (transcript == NULL || dir_path == NULL || dir_path_size == 0) {
		return false;
	}

	if (transcript->response_count == 0) {
		dir_path[0] = '\0';
		return true;
	}

	if (tmp_root == NULL || *tmp_root == '\0') {
		tmp_root = "/tmp";
	}

	if (snprintf(dir_path, dir_path_size,
		"%s/unbound-resolver-afl-symcc-XXXXXX", tmp_root) >=
		(int)dir_path_size)
	{
		return false;
	}

	if (mkdtemp(dir_path) == NULL) {
		return false;
	}

	for (index = 0; index < transcript->response_count; index++) {
		char file_path[PATH_MAX];

		if (snprintf(file_path, sizeof(file_path), "%s/resp-%04zu.bin",
			dir_path, index) >= (int)sizeof(file_path))
		{
			break;
		}
		if (!write_file_bytes(file_path, transcript->responses[index],
				transcript->response_lens[index]))
		{
			break;
		}
		created++;
	}

	if (created == transcript->response_count) {
		return true;
	}

	while (created > 0) {
		char file_path[PATH_MAX];

		created--;
		if (snprintf(file_path, sizeof(file_path), "%s/resp-%04zu.bin",
			dir_path, created) >= (int)sizeof(file_path))
		{
			continue;
		}
		(void)unlink(file_path);
	}
	(void)rmdir(dir_path);
	dir_path[0] = '\0';
	return false;
}

static void
cleanup_transcript_responses(const char *dir_path, size_t response_count)
{
	size_t index;

	if (dir_path == NULL || *dir_path == '\0') {
		return;
	}

	for (index = 0; index < response_count; index++) {
		char file_path[PATH_MAX];

		if (snprintf(file_path, sizeof(file_path), "%s/resp-%04zu.bin",
			dir_path, index) >= (int)sizeof(file_path))
		{
			continue;
		}
		(void)unlink(file_path);
	}

	(void)rmdir(dir_path);
}

static void
restore_env_var(const char *name, char *value)
{
	if (value != NULL) {
		setenv(name, value, 1);
		free(value);
		return;
	}

	unsetenv(name);
}

static void
maybe_dump_cache(struct ub_ctx *ctx)
{
	const char *dump_path = getenv("UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH");
	struct worker dump_worker;
	struct remote_stream stream;
	struct timeval now_tv;
	time_t now = 0;
	int fd = -1;

	if (ctx == NULL || ctx->env == NULL || dump_path == NULL || *dump_path == '\0') {
		return;
	}

	fd = open(dump_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0) {
		log_stage_failure("open_cache_dump");
		return;
	}

	memset(&dump_worker, 0, sizeof(dump_worker));
	dump_worker.scratchpad = regional_create();
	if (dump_worker.scratchpad == NULL) {
		close(fd);
		(void)unlink(dump_path);
		log_stage_failure("alloc_cache_dump_scratch");
		return;
	}
	dump_worker.env = *ctx->env;
	dump_worker.env.worker = &dump_worker;
	(void)gettimeofday(&now_tv, NULL);
	now = now_tv.tv_sec;
	dump_worker.env.now = &now;
	dump_worker.env.now_tv = &now_tv;

	memset(&stream, 0, sizeof(stream));
	stream.fd = fd;

	if (!dump_cache(&stream, &dump_worker)) {
		(void)unlink(dump_path);
		log_stage_failure("dump_cache");
	}

	regional_destroy(dump_worker.scratchpad);
	close(fd);
}

static bool
complete_rdata(sldns_buffer *pkt, const struct rrset_parse *rrset,
	const struct rr_parse *rr)
{
	size_t length = sldns_read_uint16(rr->ttl_data + 4);
	size_t start = (size_t)(rr->ttl_data + 6 - sldns_buffer_begin(pkt));
	size_t end = start + length;
	const uint8_t *data = rr->ttl_data + 6;

	/* msgparse 保留部分不完整的已知 RDATA；oracle 不能把它们当完整响应。 */
	switch (rrset->type) {
	case LDNS_RR_TYPE_A:
		return length == 4;
	case LDNS_RR_TYPE_AAAA:
		return length == 16;
	case LDNS_RR_TYPE_NS:
	case LDNS_RR_TYPE_CNAME:
	case LDNS_RR_TYPE_SOA:
	case LDNS_RR_TYPE_PTR:
	case LDNS_RR_TYPE_MX:
	case LDNS_RR_TYPE_SRV:
	case LDNS_RR_TYPE_DNAME:
		start += rrset->type == LDNS_RR_TYPE_MX ? 2 :
			(rrset->type == LDNS_RR_TYPE_SRV ? 6 : 0);
		if (start >= end) {
			return false;
		}
		sldns_buffer_set_position(pkt, start);
		if (!pkt_dname_len(pkt)) {
			return false;
		}
		if (rrset->type == LDNS_RR_TYPE_SOA) {
			if (sldns_buffer_position(pkt) >= end || !pkt_dname_len(pkt)) {
				return false;
			}
			return sldns_buffer_position(pkt) + 20 == end;
		}
		return sldns_buffer_position(pkt) == end;
	case LDNS_RR_TYPE_TXT:
		if (length == 0) {
			return false;
		}
		for (size_t pos = 0; pos < length;) {
			pos += 1 + data[pos];
			if (pos > length) {
				return false;
			}
		}
		return true;
	case LDNS_RR_TYPE_OPT:
		if (rr->ttl_data[0] != 0) {
			return false;
		}
		for (size_t pos = 0; pos < length;) {
			if (length - pos < 4) {
				return false;
			}
			pos += 4 + sldns_read_uint16(data + pos + 2);
			if (pos > length) {
				return false;
			}
		}
		return true;
	default:
		return true;
	}
}

static bool
parse_query_packet(const uint8_t *input, size_t input_len,
	const char *parse_stage, const char *qname_stage, char **qname_out,
	uint16_t *qtype_out, uint16_t *qclass_out, uint16_t *flags_out)
{
	sldns_buffer *pkt = NULL;
	struct regional *region = NULL;
	struct msg_parse msg;
	char *qname = NULL;
	bool ok = false;
	size_t rr_count = 0;

	if (input == NULL || input_len < 12 || input_len > 65535 ||
		qname_out == NULL || qtype_out == NULL || qclass_out == NULL)
	{
		return false;
	}

	memset(&msg, 0, sizeof(msg));
	*qname_out = NULL;
	*qtype_out = 0;
	*qclass_out = 0;

	pkt = sldns_buffer_new(input_len);
	region = regional_create();
	if (pkt == NULL || region == NULL) {
		log_stage_failure("alloc_parse_state");
		goto cleanup;
	}
	memcpy(sldns_buffer_begin(pkt), input, input_len);
	sldns_buffer_set_position(pkt, 0);
	if (parse_packet(pkt, &msg, region) != LDNS_RCODE_NOERROR || msg.qdcount != 1 ||
		msg.qname == NULL || sldns_buffer_remaining(pkt) != 0)
	{
		log_stage_failure(parse_stage);
		goto cleanup;
	}

	/* parse_packet 宽容缺失末尾 OPT；oracle 仍要求声明的 RR 全部存在。 */
	for (struct rrset_parse *rrset = msg.rrset_first; rrset != NULL;
	     rrset = rrset->rrset_all_next)
	{
		rr_count += rrset->rr_count + rrset->rrsig_count;
		for (struct rr_parse *rr = rrset->rr_first; rr != NULL; rr = rr->next) {
			if (!complete_rdata(pkt, rrset, rr)) {
				goto cleanup;
			}
		}
	}
	if (rr_count != (size_t)msg.ancount + msg.nscount + msg.arcount) {
		goto cleanup;
	}
	if (flags_out != NULL) {
		*flags_out = msg.flags;
	}

	qname = sldns_wire2str_dname(msg.qname, msg.qname_len);
	if (qname == NULL) {
		log_stage_failure(qname_stage);
		goto cleanup;
	}

	*qname_out = qname;
	*qtype_out = msg.qtype;
	*qclass_out = msg.qclass;
	qname = NULL;
	ok = true;

cleanup:
	free(qname);
	if (region != NULL) {
		regional_destroy(region);
	}
	if (pkt != NULL) {
		sldns_buffer_free(pkt);
	}
	return ok;
}

typedef struct query_observation {
	const char *qname;
	uint16_t qtype;
	uint16_t qclass;
	bool fetched;
	bool dispatched;
} query_observation_t;

static void
observe_query(const uint8_t *query, size_t query_len, bool dispatched, void *arg)
{
	query_observation_t *observation = arg;
	char *qname = NULL;
	uint16_t qtype, qclass, flags;
	if (parse_query_packet(query, query_len, "parse_fetch", "fetch_qname",
		&qname, &qtype, &qclass, &flags))
	{
		if ((flags & 0xf800) == 0 &&
			strcasecmp(qname, observation->qname) == 0 &&
			qtype == observation->qtype && qclass == observation->qclass)
		{
			observation->fetched = true;
			observation->dispatched |= dispatched;
		}
	}
	free(qname);
}

static bool
acceptable_result(const struct ub_result *result, const char *qname,
	uint16_t qtype, uint16_t qclass)
{
	char *answer_name = NULL;
	uint16_t answer_type, answer_class, flags;
	bool valid;
	if (result == NULL || result->bogus || result->qname == NULL ||
		strcasecmp(result->qname, qname) != 0 || result->qtype != qtype ||
		result->qclass != qclass || result->answer_packet == NULL ||
		result->answer_len < 12 ||
		((const uint8_t *)result->answer_packet)[0] != 0 ||
		((const uint8_t *)result->answer_packet)[1] != 0 ||
		!((result->rcode == 0 && !result->nxdomain) ||
		  (result->rcode == 3 && result->nxdomain && !result->havedata)) ||
		(result->havedata && (result->data == NULL || result->data[0] == NULL)))
	{
		return false;
	}
	/* libworker_fg 固定 qid=0；核对 API 的映射 ID，而非 transcript 原始 ID。 */
	if (!parse_query_packet(result->answer_packet, (size_t)result->answer_len,
		"parse_answer", "answer_qname", &answer_name, &answer_type,
		&answer_class, &flags))
	{
		return false;
	}
	valid = (flags & 0xfa00) == 0x8000 && (flags & 0xf) == result->rcode &&
		strcasecmp(answer_name, qname) == 0 && answer_type == qtype && answer_class == qclass;
	free(answer_name);
	return valid;
}

static bool
execute_query_packet(struct ub_ctx *ctx, const uint8_t *input, size_t input_len,
	const char *parse_stage, const char *qname_stage, bool *answer_valid,
	int *resolve_result_out, bool *fetch_started, bool *dispatched)
{
	char *qname = NULL;
	uint16_t qtype = 0;
	uint16_t qclass = 0;
	struct ub_result *result = NULL;
	query_observation_t observation = { 0 };
	bool ok = false;

	if (ctx == NULL || answer_valid == NULL || resolve_result_out == NULL) {
		return false;
	}

	*answer_valid = false;
	*fetch_started = false;
	*dispatched = false;
	*resolve_result_out = UB_NOERROR;
	if (!parse_query_packet(input, input_len, parse_stage, qname_stage, &qname,
		&qtype, &qclass, NULL))
	{
		return false;
	}

	observation.qname = qname;
	observation.qtype = qtype;
	observation.qclass = qclass;
	unbound_afl_symcc_mutator_server_set_observer(observe_query, &observation);
	*resolve_result_out = ub_resolve(ctx, qname, qtype, qclass, &result);
	/* 注销会等待正在执行的回调，随后才可读取局部事实并释放 qname。 */
	unbound_afl_symcc_mutator_server_set_observer(NULL, NULL);
	*fetch_started = observation.fetched;
	*dispatched = observation.dispatched;
	*answer_valid = *resolve_result_out == UB_NOERROR &&
		acceptable_result(result, qname, qtype, qclass);
	ok = true;

	if (result != NULL) {
		ub_resolve_free(result);
	}
	free(qname);
	return ok;
}

static int
execute_query_case(const uint8_t *input, size_t input_len,
	unbound_afl_symcc_oracle_t *oracle)
{
	char forwarder[UNBOUND_AFL_SYMCC_FWD_STR_MAX];
	struct ub_ctx *ctx = NULL;
	uint16_t port = 0;
	bool answer_valid = false;
	int resolve_result = UB_NOERROR;
	int rc = 1;

	if (!unbound_afl_symcc_mutator_server_start(0, &port)) {
		log_stage_failure("mutator_start");
		goto cleanup;
	}
	snprintf(forwarder, sizeof(forwarder), "127.0.0.1@%u", (unsigned)port);

	ctx = ub_ctx_create();
	if (ctx == NULL) {
		log_stage_failure("ub_ctx_create");
		goto cleanup;
	}
	if (configure_ctx(ctx, forwarder, true) != 0) {
		log_stage_failure("configure_ctx");
		goto cleanup;
	}

	unbound_afl_symcc_oracle_set_active(oracle);
	if (!execute_query_packet(ctx, input, input_len, "parse_query",
		"wire2str_qname", &answer_valid, &resolve_result, &oracle->resolver_fetch_started,
		&oracle->fake_reply_dispatched))
	{
		goto cleanup;
	}

	oracle->parse_ok = true;
	oracle->response_accepted =
		oracle->resolver_fetch_started && oracle->fake_reply_dispatched && answer_valid;
	rc = oracle->parse_ok ? 0 : 1;

cleanup:
	unbound_afl_symcc_oracle_clear_active();
	unbound_afl_symcc_mutator_server_stop();
	if (ctx != NULL) {
		maybe_dump_cache(ctx);
		ub_ctx_delete(ctx);
	}
	return rc;
}

static int
execute_transcript_case(const uint8_t *input, size_t input_len,
	unbound_afl_symcc_oracle_t *oracle)
{
	unbound_afl_symcc_transcript_t transcript = { 0 };
	unbound_afl_symcc_mutator_stats_t counters_before = { 0 };
	unbound_afl_symcc_mutator_stats_t counters_after_first = { 0 };
	unbound_afl_symcc_mutator_stats_t counters_after_second = { 0 };
	char forwarder[UNBOUND_AFL_SYMCC_FWD_STR_MAX];
	struct ub_ctx *ctx = NULL;
	char response_dir[PATH_MAX] = { 0 };
	char *saved_tail = NULL;
	char *saved_tail_dir = NULL;
	const char *tail_env = getenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL");
	const char *tail_dir_env =
		getenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR");
	uint16_t port = 0;
	bool answer_valid = false;
	int resolve_result = UB_NOERROR;
	int rc = 1;

	if (!parse_transcript_input(input, input_len, &transcript)) {
		log_stage_failure("parse_transcript");
		goto cleanup;
	}
	if (debug_enabled()) {
		fprintf(stderr,
			"[unbound-afl-symcc][debug] transcript parsed responses=%zu "
			"client_len=%zu post_len=%zu\n",
			transcript.response_count, transcript.client_query_len,
			transcript.post_check_query_len);
	}
	response_dir[0] = '\0';

	if (tail_env != NULL) {
		saved_tail = strdup(tail_env);
	}
	if (tail_dir_env != NULL) {
		saved_tail_dir = strdup(tail_dir_env);
	}

	if (!materialize_transcript_responses(&transcript, response_dir,
		sizeof(response_dir)))
	{
		log_stage_failure("materialize_transcript_responses");
		goto cleanup;
	}

	unsetenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL");
	if (transcript.response_count > 0) {
		setenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR", response_dir,
			1);
	} else {
		unsetenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR");
	}

	if (!unbound_afl_symcc_mutator_server_start(0, &port)) {
		log_stage_failure("mutator_start");
		goto cleanup;
	}
	unbound_afl_symcc_mutator_server_set_responses(
		transcript.responses, transcript.response_lens,
		transcript.response_count);
	unbound_afl_symcc_mutator_server_reset_response_sequence();
	snprintf(forwarder, sizeof(forwarder), "127.0.0.1@%u", (unsigned)port);

	ctx = ub_ctx_create();
	if (ctx == NULL) {
		log_stage_failure("ub_ctx_create");
		goto cleanup;
	}
	if (configure_ctx(ctx, forwarder, false) != 0) {
		log_stage_failure("configure_ctx");
		goto cleanup;
	}

	unbound_afl_symcc_oracle_set_active(oracle);
	if (!unbound_afl_symcc_mutator_server_get_stats(&counters_before)) {
		log_stage_failure("get_stats_before");
		goto cleanup;
	}
	if (!execute_query_packet(ctx, transcript.client_query,
		transcript.client_query_len, "parse_query", "wire2str_qname",
		&answer_valid, &resolve_result, &oracle->resolver_fetch_started,
		&oracle->fake_reply_dispatched))
	{
		goto cleanup;
	}
	oracle->parse_ok = true;
	if (!unbound_afl_symcc_mutator_server_get_stats(&counters_after_first)) {
		log_stage_failure("get_stats_after_first");
		goto cleanup;
	}
	oracle->response_accepted =
		oracle->resolver_fetch_started && oracle->fake_reply_dispatched &&
		resolve_result == UB_NOERROR && answer_valid;

	counters_after_second = counters_after_first;
	if (transcript.post_check_query != NULL &&
		transcript.post_check_query_len > 0)
	{
		bool post_answer_valid = false;
		int post_resolve_result = UB_NOERROR;
		bool post_fetch = false, post_dispatched = false;

		if (execute_query_packet(ctx, transcript.post_check_query,
			transcript.post_check_query_len, "parse_post_check_query",
			"wire2str_post_check_qname", &post_answer_valid,
			&post_resolve_result, &post_fetch, &post_dispatched))
		{
			if (!unbound_afl_symcc_mutator_server_get_stats(
					&counters_after_second))
			{
				log_stage_failure("get_stats_after_second");
				goto cleanup;
			}
			if (oracle->response_accepted && post_answer_valid &&
				post_resolve_result == UB_NOERROR &&
				counters_after_second.received ==
					counters_after_first.received &&
				counters_after_second.replied ==
					counters_after_first.replied &&
				counters_after_second.parse_errors ==
					counters_after_first.parse_errors)
			{
				/* 实际 post-check 的无上游代理指标，不证明真实缓存项或投毒。 */
				oracle->second_query_hit = true;
				oracle->cache_entry_created = true;
			}
		}
	}

	rc = oracle->parse_ok ? 0 : 1;

cleanup:
	unbound_afl_symcc_mutator_server_clear_responses();
	unbound_afl_symcc_oracle_clear_active();
	unbound_afl_symcc_mutator_server_stop();
	restore_env_var("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL", saved_tail);
	restore_env_var("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR",
		saved_tail_dir);
	if (response_dir[0] != '\0' && transcript.response_count > 0) {
		cleanup_transcript_responses(response_dir,
			transcript.response_count);
	}
	if (ctx != NULL) {
		maybe_dump_cache(ctx);
		ub_ctx_delete(ctx);
	}
	return rc;
}

void
unbound_afl_symcc_oracle_set_active(unbound_afl_symcc_oracle_t *oracle)
{
	g_active_oracle = oracle;
}

void
unbound_afl_symcc_oracle_clear_active(void)
{
	g_active_oracle = NULL;
}

void
unbound_afl_symcc_oracle_note_fetch_started(void)
{
	/* libworker 的提交事件没有 Question；只由 observer 证明匹配的 fetch。 */
}

void
unbound_afl_symcc_oracle_note_timeout(void)
{
	if (g_active_oracle != NULL) {
		g_active_oracle->timeout = true;
	}
}

int
unbound_afl_symcc_run_case(const uint8_t *input, size_t input_len,
	unbound_afl_symcc_oracle_t *oracle)
{
	int rc = 1;

	memset(oracle, 0, sizeof(*oracle));

	if (looks_like_transcript(input, input_len)) {
		if (debug_enabled()) {
			fprintf(stderr,
				"[unbound-afl-symcc][debug] input mode=transcript len=%zu "
				"head=%02x%02x%02x%02x\n",
				input_len,
				input_len > 0 ? input[0] : 0,
				input_len > 1 ? input[1] : 0,
				input_len > 2 ? input[2] : 0,
				input_len > 3 ? input[3] : 0);
		}
		rc = execute_transcript_case(input, input_len, oracle);
	} else {
		if (debug_enabled()) {
			fprintf(stderr,
				"[unbound-afl-symcc][debug] input mode=query len=%zu "
				"head=%02x%02x%02x%02x\n",
				input_len,
				input_len > 0 ? input[0] : 0,
				input_len > 1 ? input[1] : 0,
				input_len > 2 ? input[2] : 0,
				input_len > 3 ? input[3] : 0);
		}
		rc = execute_query_case(input, input_len, oracle);
	}

	log_result(oracle);
	return rc;
}

int
unbound_afl_symcc_dump_empty_cache(void)
{
	const char *dump_path = getenv("UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH");
	FILE *fp = NULL;

	if (dump_path == NULL || *dump_path == '\0') {
		return 1;
	}

	fp = fopen(dump_path, "w");
	if (fp == NULL) {
		log_stage_failure("open_empty_cache_dump");
		return 1;
	}

	fputs("START_RRSET_CACHE\n", fp);
	fputs("END_RRSET_CACHE\n", fp);
	fputs("START_MSG_CACHE\n", fp);
	fputs("END_MSG_CACHE\n", fp);
	fputs("EOF\n", fp);
	fclose(fp);
	return 0;
}
