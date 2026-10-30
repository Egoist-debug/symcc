/* 直接编译生产 orchestrator，网络/完成事件替身不启动 resolver。 */
#ifdef TEST_BIND
#include <isc/async.h>
static void test_async_run(void *arg);
#define isc_async_run(loop, callback, arg) test_async_run(arg)
#include NATIVE_SOURCE
#undef isc_async_run
#else
#define ub_resolve test_resolve
#define ub_resolve_free test_resolve_free
#define sendto test_sendto
#define unbound_afl_symcc_mutator_server_start test_server_start
#define unbound_afl_symcc_mutator_server_stop test_server_stop
#include "patch/cache/unbound/smallapp/unbound_afl_symcc_orchestrator.c"
#undef unbound_afl_symcc_mutator_server_start
#undef unbound_afl_symcc_mutator_server_stop
#include "patch/cache/unbound/smallapp/unbound_afl_symcc_mutator_server.c"
#undef sendto
#endif

#undef NDEBUG
#include <assert.h>

static const uint8_t query[] = {
	0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1
};
static const uint8_t answer[] = {
	0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
	7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
	0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1
};
static uint8_t packet[512], fetch[sizeof(query)];
static size_t packet_len;
static bool do_fetch = true, send_ok = true;
static bool post_check = false, post_fetch = false, post_invalid = false;
static bool have_reply = true;
#ifndef TEST_BIND
static bool short_send = false;
static bool wrong_result_id = false;
#endif
static unsigned query_calls;
static unsigned checks;
static int completed = 0;

#ifdef TEST_BIND
isc_mem_t *named_g_mctx;
in_port_t named_g_port;
static named_resolver_afl_symcc_mutator_counters_t counters;

void ns_query_cancel(ns_client_t *client) { (void)client; abort(); }

void named_resolver_afl_symcc_mutator_server_reset_response_sequence(void) {}
void named_resolver_afl_symcc_mutator_server_clear_responses(void) {}
void named_resolver_afl_symcc_mutator_server_set_responses(
	const uint8_t *const *responses, const size_t *lengths, size_t count)
{
	(void)responses; (void)lengths; (void)count;
}

void named_resolver_afl_symcc_mutator_server_get_counters(
	named_resolver_afl_symcc_mutator_counters_t *out)
{
	*out = counters;
}

isc_result_t
named_resolver_afl_symcc_mutator_dispatch_hook(
	dns_dispentry_t *resp, const isc_region_t *request,
	unsigned char *response_buf, size_t response_buf_size,
	isc_region_t *response, void *arg)
{
	(void)resp; (void)request; (void)response_buf_size; (void)arg;
	response->base = response_buf;
	response->length = have_reply ? 1 : 0;
	counters.received++;
	counters.replied += send_ok && have_reply;
	return send_ok ? ISC_R_SUCCESS : ISC_R_TIMEDOUT;
}

static void test_async_run(void *arg)
{
	named_resolver_afl_symcc_request_context_t *ctx = arg;
	unsigned char reply[512];
	isc_region_t request = { fetch, sizeof(fetch) }, injected = { 0 };
	isc_buffer_t buffer;
	bool second = query_calls++ > 0;
	if (second ? post_fetch : do_fetch) {
		observed_dispatch_hook(NULL, &request, reply, sizeof(reply), &injected, NULL);
	}
	if (completed) {
		finish_request_context(ctx, ISC_R_FAILURE);
		return;
	}
	isc_buffer_init(&buffer, packet, sizeof(packet));
	isc_buffer_add(&buffer, packet_len - (second && post_invalid));
	resolver_afl_symcc_client_sendcb(&buffer);
}
#else
static unbound_afl_symcc_mutator_server_t server;

int dump_cache(RES *stream, struct worker *worker)
{
	(void)stream; (void)worker;
	abort(); /* 本测试不能把替身 dump 当成真实缓存观测。 */
}

ssize_t test_sendto(int fd, const void *buf, size_t len, int flags,
	const struct sockaddr *addr, socklen_t addr_len)
{
	(void)fd; (void)buf; (void)flags; (void)addr; (void)addr_len;
	return send_ok ? (ssize_t)len - short_send : -1;
}

bool test_server_start(uint16_t requested_port, uint16_t *bound_port)
{
	(void)requested_port;
	memset(&server, 0, sizeof(server));
	g_server = &server;
	*bound_port = 53000;
	return true;
}

void test_server_stop(void)
{
	g_server = NULL;
}

int ub_resolve(struct ub_ctx *ctx, const char *name, int type, int rrclass,
	struct ub_result **result)
{
	(void)ctx;
	bool second = query_calls++ > 0;
	if (second ? post_fetch : do_fetch) {
		dispatch_query(&server, fetch, sizeof(fetch), NULL, 0);
	}
	*result = calloc(1, sizeof(**result));
	(*result)->qname = strdup(name);
	(*result)->qtype = type;
	(*result)->qclass = rrclass;
	(*result)->rcode = packet[3] & 15;
	(*result)->nxdomain = (*result)->rcode == 3;
	if ((*result)->rcode == 0 && packet[7] > 0) {
		(*result)->havedata = 1;
		(*result)->data = calloc(2, sizeof(char *));
		(*result)->data[0] = strdup("data");
	}
	(*result)->answer_packet = malloc(packet_len);
	memcpy((*result)->answer_packet, packet, packet_len);
	((uint8_t *)(*result)->answer_packet)[0] = wrong_result_id;
	((uint8_t *)(*result)->answer_packet)[1] = 0;
	(*result)->answer_len = (int)packet_len - (second && post_invalid);
	return completed;
}

void ub_resolve_free(struct ub_result *result)
{
	free(result->qname);
	if (result->data != NULL) {
		free(result->data[0]);
		free(result->data);
	}
	free(result->answer_packet);
	free(result);
}

#endif

static bool run_case(void)
{
	uint8_t transcript[1024] = { 'D', 'S', 'T', '1', 1, 0,
		sizeof(query), 0, 0, 0, sizeof(answer), 0 };
	size_t length = 12 + sizeof(query) + sizeof(answer);
	bool accepted, hit;
	query_calls = 0;
	checks++;
	memcpy(transcript + 12, query, sizeof(query));
	memcpy(transcript + 12 + sizeof(query), answer, sizeof(answer));
	if (post_check) {
		transcript[8] = sizeof(query);
		memcpy(transcript + length, query, sizeof(query));
		length += sizeof(query);
	}
#ifdef TEST_BIND
	named_resolver_afl_symcc_orchestrator_t orchestrator = { 0 };
	memset(&counters, 0, sizeof(counters));
	isc_result_t status = execute_transcript_case(&orchestrator,
		transcript, length, 100);
	assert(status == (completed ? ISC_R_FAILURE : ISC_R_SUCCESS));
	accepted = orchestrator.oracle_response_accepted != 0;
	hit = orchestrator.oracle_second_query_hit != 0;
	assert(orchestrator.oracle_cache_entry_created == (unsigned)hit);
#else
	unbound_afl_symcc_oracle_t oracle = { 0 };
	if (!have_reply) {
		/* 完整 header 以下的注入被 mutator 拒绝，不补空回复。 */
		transcript[10] = 1;
		length -= sizeof(answer) - 1;
	}
	assert(execute_transcript_case(transcript, length, &oracle) == 0);
	log_result(&oracle);
	accepted = oracle.response_accepted;
	hit = oracle.second_query_hit;
	assert(oracle.cache_entry_created == hit);
	assert(server.observer == NULL);
#endif
	assert(hit == (post_check && accepted && !post_fetch && !post_invalid));
	assert(query_calls == (post_check && !completed ? 2U : 1U));
	fprintf(stderr, "ORACLE_EXPECT response_accepted=%u second_query_hit=%u\n",
		accepted, hit);
	return accepted;
}

int main(void)
{
	alarm(5); /* 死锁必须令测试失败，不能无限等待。 */
	unsetenv("UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH");
#ifdef TEST_BIND
	isc_mem_create(&named_g_mctx);
	setenv("NAMED_RESOLVER_AFL_SYMCC_LOG", "1", 1);
#else
	setenv("UNBOUND_RESOLVER_AFL_SYMCC_LOG", "1", 1);
#endif
	memcpy(packet, answer, sizeof(answer));
	packet_len = sizeof(answer);
	memcpy(fetch, query, sizeof(query));
	assert(run_case());
	do_fetch = false;
	assert(!run_case());
	do_fetch = true;
	send_ok = false;
	assert(!run_case());
	send_ok = true;
	have_reply = false;
	assert(!run_case());
	have_reply = true;
#ifndef TEST_BIND
	short_send = true;
	assert(!run_case());
	short_send = false;
#endif
	for (size_t i = 13; i <= 28; i += i == 13 ? 13 : 1) {
		fetch[i] ^= 1;
		assert(!run_case());
		fetch[i] ^= 1;
		packet[i] ^= 1;
		assert(!run_case());
		packet[i] ^= 1;
	}
	packet_len--;
	assert(!run_case());
	packet_len++;
	packet[packet_len++] = 0;
	assert(!run_case());
	packet_len--;
	packet[11] = 1;
	assert(!run_case());
	packet[11] = 0;
	packet[40] = 3;
	packet_len--;
	assert(!run_case());
	packet_len++;
	packet[40] = 4;
	packet[32] = 5;
	packet[40] = 0;
	packet_len = 41;
	assert(!run_case());
	packet[32] = 6;
	packet[40] = 1;
	packet[41] = 0;
	packet_len = 42;
	assert(!run_case());
	packet[32] = 16;
	packet[40] = 2;
	packet[41] = 3;
	packet[42] = 'a';
	packet_len = 43;
	assert(!run_case());
	memcpy(packet, answer, sizeof(answer));
	packet_len = sizeof(answer);
	packet[11] = 1;
	/* OPT 的扩展 RCODE 不能被低四位 NOERROR 掩盖。 */
	const uint8_t opt[] = { 0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0 };
	memcpy(packet + packet_len, opt, sizeof(opt));
	packet_len += sizeof(opt);
	assert(!run_case());
	memcpy(packet, answer, sizeof(answer));
	packet_len = sizeof(answer);
	packet[29] = 0xff;
	assert(!run_case());
	packet[29] = 0xc0;
	packet[30] = 29;
	assert(!run_case());
	packet[30] = 12;
	packet[2] |= 2;
	assert(!run_case());
	packet[2] &= ~2;
	post_check = true;
	assert(run_case());
	post_fetch = true;
	assert(run_case());
	post_fetch = false;
	post_invalid = true;
	assert(run_case());
	post_invalid = false;
	post_check = false;
	packet_len = sizeof(query);
	packet[7] = 0;
	for (int rcode = 0; rcode <= 5; rcode++) {
		packet[3] = 0x80 | rcode;
		assert(run_case() == (rcode == 0 || rcode == 3));
		post_check = true;
		assert(run_case() == (rcode == 0 || rcode == 3));
		post_check = false;
	}
	const uint8_t soa[] = {
		0xc0, 12, 0, 6, 0, 1, 0, 0, 1, 44, 0, 24,
		0xc0, 12, 0xc0, 12,
		0, 0, 0, 1, 0, 0, 0, 60, 0, 0, 0, 60, 0, 0, 1, 44, 0, 0, 0, 60
	};
	packet[9] = 1;
	memcpy(packet + sizeof(query), soa, sizeof(soa));
	packet_len = sizeof(query) + sizeof(soa);
	for (int rcode = 0; rcode <= 3; rcode += 3) {
		packet[3] = 0x80 | rcode;
		assert(run_case());
		post_check = true;
		assert(run_case());
		post_check = false;
	}
#ifdef TEST_BIND
	packet[0] ^= 1;
	assert(!run_case());
	isc_mem_detach(&named_g_mctx);
#else
	packet[3] = 0x80;
	wrong_result_id = true;
	assert(!run_case());
	wrong_result_id = false;
	completed = UB_SERVFAIL;
	assert(!run_case());
#endif
	printf("PASS: native replay oracle (%u checks)\n", checks);
	return 0;
}
