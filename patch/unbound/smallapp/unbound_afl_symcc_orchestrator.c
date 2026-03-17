#include "config.h"

#include "smallapp/unbound_afl_symcc_orchestrator.h"
#include "smallapp/unbound_afl_symcc_mutator_server.h"

#include "libunbound/unbound.h"
#include "sldns/sbuffer.h"
#include "sldns/wire2str.h"
#include "util/data/msgparse.h"
#include "util/regional.h"

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

	if (input == NULL || transcript == NULL || input_len < 10 ||
		input_len > UNBOUND_AFL_SYMCC_MAX_TRANSCRIPT_INPUT ||
		!looks_like_transcript(input, input_len))
	{
		return false;
	}

	memset(transcript, 0, sizeof(*transcript));
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

static bool
parse_query_packet(const uint8_t *input, size_t input_len,
	const char *parse_stage, const char *qname_stage, char **qname_out,
	uint16_t *qtype_out, uint16_t *qclass_out)
{
	uint8_t *input_copy = NULL;
	sldns_buffer *pkt = NULL;
	struct regional *region = NULL;
	struct msg_parse msg;
	char *qname = NULL;
	bool ok = false;

	if (qname_out == NULL || qtype_out == NULL || qclass_out == NULL) {
		return false;
	}

	memset(&msg, 0, sizeof(msg));
	*qname_out = NULL;
	*qtype_out = 0;
	*qclass_out = 0;

	input_copy = malloc(input_len);
	if (input_copy == NULL) {
		log_stage_failure("malloc_input");
		goto cleanup;
	}
	memcpy(input_copy, input, input_len);

	pkt = sldns_buffer_new(input_len);
	region = regional_create();
	if (pkt == NULL || region == NULL) {
		log_stage_failure("alloc_parse_state");
		goto cleanup;
	}
	sldns_buffer_init_frm_data(pkt, input_copy, input_len);
	sldns_buffer_set_position(pkt, 0);
	if (parse_packet(pkt, &msg, region) != LDNS_RCODE_NOERROR || msg.qdcount != 1 ||
		msg.qname == NULL)
	{
		log_stage_failure(parse_stage);
		goto cleanup;
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
	free(input_copy);
	return ok;
}

static bool
execute_query_packet(struct ub_ctx *ctx, const uint8_t *input, size_t input_len,
	const char *parse_stage, const char *qname_stage, bool *answer_nonempty,
	int *resolve_result_out)
{
	char *qname = NULL;
	uint16_t qtype = 0;
	uint16_t qclass = 0;
	struct ub_result *result = NULL;
	bool ok = false;

	if (ctx == NULL || answer_nonempty == NULL || resolve_result_out == NULL) {
		return false;
	}

	*answer_nonempty = false;
	*resolve_result_out = UB_NOERROR;
	if (!parse_query_packet(input, input_len, parse_stage, qname_stage, &qname,
		&qtype, &qclass))
	{
		return false;
	}

	*resolve_result_out = ub_resolve(ctx, qname, qtype, qclass, &result);
	*answer_nonempty = *resolve_result_out == UB_NOERROR && result != NULL &&
		result->answer_len > 0;
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
	bool answer_nonempty = false;
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
		"wire2str_qname", &answer_nonempty, &resolve_result))
	{
		goto cleanup;
	}

	oracle->parse_ok = true;
	oracle->response_accepted =
		oracle->resolver_fetch_started && answer_nonempty;
	rc = oracle->parse_ok ? 0 : 1;

cleanup:
	unbound_afl_symcc_oracle_clear_active();
	unbound_afl_symcc_mutator_server_stop();
	if (ctx != NULL) {
		ub_ctx_delete(ctx);
	}
	return rc;
}

static int
execute_transcript_case(const uint8_t *input, size_t input_len,
	unbound_afl_symcc_oracle_t *oracle)
{
	unbound_afl_symcc_transcript_t transcript;
	unbound_afl_symcc_mutator_stats_t counters_before = { 0 };
	unbound_afl_symcc_mutator_stats_t counters_after_first = { 0 };
	unbound_afl_symcc_mutator_stats_t counters_after_second = { 0 };
	char forwarder[UNBOUND_AFL_SYMCC_FWD_STR_MAX];
	struct ub_ctx *ctx = NULL;
	char response_dir[PATH_MAX];
	char *saved_tail = NULL;
	char *saved_tail_dir = NULL;
	const char *tail_env = getenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL");
	const char *tail_dir_env =
		getenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR");
	uint16_t port = 0;
	bool answer_nonempty = false;
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
		&answer_nonempty, &resolve_result))
	{
		goto cleanup;
	}
	oracle->parse_ok = true;
	if (!unbound_afl_symcc_mutator_server_get_stats(&counters_after_first)) {
		log_stage_failure("get_stats_after_first");
		goto cleanup;
	}
	oracle->resolver_fetch_started =
		counters_after_first.received > counters_before.received;
	oracle->response_accepted =
		oracle->resolver_fetch_started &&
		resolve_result == UB_NOERROR && answer_nonempty;

	counters_after_second = counters_after_first;
	if (transcript.post_check_query != NULL &&
		transcript.post_check_query_len > 0)
	{
		bool post_answer_nonempty = false;
		int post_resolve_result = UB_NOERROR;

		if (execute_query_packet(ctx, transcript.post_check_query,
			transcript.post_check_query_len, "parse_post_check_query",
			"wire2str_post_check_qname", &post_answer_nonempty,
			&post_resolve_result))
		{
			if (!unbound_afl_symcc_mutator_server_get_stats(
					&counters_after_second))
			{
				log_stage_failure("get_stats_after_second");
				goto cleanup;
			}
				if (post_resolve_result == UB_NOERROR &&
					counters_after_second.received ==
						counters_after_first.received &&
					counters_after_second.replied ==
						counters_after_first.replied &&
					counters_after_second.parse_errors ==
						counters_after_first.parse_errors)
				{
					oracle->second_query_hit =
						oracle->resolver_fetch_started;
					oracle->cache_entry_created =
						oracle->second_query_hit &&
						oracle->response_accepted;
				}
			}
		}

	rc = oracle->parse_ok ? 0 : 1;

cleanup:
	unbound_afl_symcc_oracle_clear_active();
	unbound_afl_symcc_mutator_server_stop();
	restore_env_var("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL", saved_tail);
	restore_env_var("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR",
		saved_tail_dir);
	cleanup_transcript_responses(response_dir, transcript.response_count);
	if (ctx != NULL) {
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
	if (g_active_oracle != NULL) {
		g_active_oracle->resolver_fetch_started = true;
	}
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
