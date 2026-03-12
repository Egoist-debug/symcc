#include "config.h"

#include "smallapp/unbound_afl_symcc_orchestrator.h"
#include "smallapp/unbound_afl_symcc_mutator_server.h"

#include "libunbound/unbound.h"
#include "sldns/sbuffer.h"
#include "sldns/wire2str.h"
#include "util/data/msgparse.h"
#include "util/regional.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNBOUND_AFL_SYMCC_FWD_STR_MAX 64

static unbound_afl_symcc_oracle_t *g_active_oracle = NULL;

static bool
logging_enabled(void)
{
	const char *env = getenv("UNBOUND_RESOLVER_AFL_SYMCC_LOG");
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
configure_ctx(struct ub_ctx *ctx, const char *forwarder)
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
	/* 避免命中缓存导致不走 fetch 路径 */
	if (ub_ctx_set_option(ctx, "msg-cache-size:", "0") != UB_NOERROR) {
		return 1;
	}
	if (ub_ctx_set_option(ctx, "rrset-cache-size:", "0") != UB_NOERROR) {
		return 1;
	}
	if (ub_ctx_set_fwd(ctx, forwarder) != UB_NOERROR) {
		return 1;
	}
	return 0;
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
	uint8_t *input_copy = NULL;
	sldns_buffer *pkt = NULL;
	struct regional *region = NULL;
	struct msg_parse msg;
	char *qname = NULL;
	char forwarder[UNBOUND_AFL_SYMCC_FWD_STR_MAX];
	struct ub_ctx *ctx = NULL;
	struct ub_result *result = NULL;
	int resolve_result = UB_NOERROR;
	uint16_t port = 0;
	int rc = 1;

	memset(oracle, 0, sizeof(*oracle));
	memset(&msg, 0, sizeof(msg));

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
		log_stage_failure("parse_query");
		goto cleanup;
	}

	qname = sldns_wire2str_dname(msg.qname, msg.qname_len);
	if (qname == NULL) {
		log_stage_failure("wire2str_qname");
		goto cleanup;
	}

	oracle->parse_ok = true;

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
	if (configure_ctx(ctx, forwarder) != 0) {
		log_stage_failure("configure_ctx");
		goto cleanup;
	}

	unbound_afl_symcc_oracle_set_active(oracle);
	resolve_result = ub_resolve(ctx, qname, msg.qtype, msg.qclass, &result);
	oracle->response_accepted =
		oracle->resolver_fetch_started &&
		resolve_result == UB_NOERROR && result != NULL &&
		result->answer_len > 0;
	rc = oracle->parse_ok ? 0 : 1;

cleanup:
	unbound_afl_symcc_oracle_clear_active();
	unbound_afl_symcc_mutator_server_stop();
	log_result(oracle);
	if (result != NULL) {
		ub_resolve_free(result);
	}
	if (ctx != NULL) {
		ub_ctx_delete(ctx);
	}
	free(qname);
	if (region != NULL) {
		regional_destroy(region);
	}
	if (pkt != NULL) {
		sldns_buffer_free(pkt);
	}
	free(input_copy);
	return rc;
}
