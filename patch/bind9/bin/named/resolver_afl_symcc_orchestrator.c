/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <isc/app.h>
#include <isc/netmgr.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/dispatch.h>
#include <dns/view.h>

#include <ns/client.h>
#include <ns/interfacemgr.h>
#include <ns/query.h>

#include <named/globals.h>
#include <named/resolver_afl_symcc_mutator_server.h>
#include <named/resolver_afl_symcc_orchestrator.h>
#include <named/server.h>

#ifndef __AFL_FUZZ_TESTCASE_LEN
#define NAMED_AFL_FUZZ_FALLBACK 1
static ssize_t named_afl_fuzz_len __attribute__((unused));
static unsigned char named_afl_fuzz_buf[65536];
#define __AFL_FUZZ_TESTCASE_LEN named_afl_fuzz_len
#define __AFL_FUZZ_TESTCASE_BUF named_afl_fuzz_buf
#define __AFL_FUZZ_INIT() void sync(void)
#define __AFL_LOOP(_max)                                                   \
	((named_afl_fuzz_len =                                            \
		  read(STDIN_FILENO, named_afl_fuzz_buf,                  \
		       sizeof(named_afl_fuzz_buf))) > 0)
#define __AFL_INIT() sync()
#endif

__AFL_FUZZ_INIT();

#define NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_MAGIC "DST1"
#define NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_MAX_RESPONSES 16
#define NAMED_RESOLVER_AFL_SYMCC_MAX_LEGACY_INPUT 4096
#define NAMED_RESOLVER_AFL_SYMCC_MAX_TRANSCRIPT_INPUT 16384

typedef struct named_resolver_afl_symcc_request_context {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	const uint8_t *request;
	size_t request_len;
	ns_client_t *client;
	bool finished;
	bool reply_sent;
	bool timed_out;
	isc_result_t result;
} named_resolver_afl_symcc_request_context_t;

typedef struct named_resolver_afl_symcc_transcript {
	const uint8_t *client_query;
	size_t client_query_len;
	const uint8_t *post_check_query;
	size_t post_check_query_len;
	const uint8_t *responses[NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_MAX_RESPONSES];
	size_t response_lens[NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_MAX_RESPONSES];
	size_t response_count;
} named_resolver_afl_symcc_transcript_t;

typedef struct named_resolver_afl_symcc_transcript_oracle {
	bool parse_ok;
	bool resolver_fetch_started;
	bool response_accepted;
	bool second_query_hit;
	bool cache_entry_created;
	bool timeout;
} named_resolver_afl_symcc_transcript_oracle_t;

typedef struct named_resolver_afl_symcc_orchestrator {
	pthread_t injector_thread_id;
	bool injector_thread_started;
	char *config;
	isc_fuzztype_t saved_fuzztype;
	ns_fuzzcb_t saved_fuzznotify;
	bool hooks_installed;
	uint64_t requests_sent;
	uint64_t replies_received;
	uint64_t reply_timeouts;
	uint64_t send_failures;
	uint64_t transcript_cases;
	uint64_t transcript_parse_errors;
	uint64_t oracle_parse_ok;
	uint64_t oracle_fetch_started;
	uint64_t oracle_response_accepted;
	uint64_t oracle_second_query_hit;
	uint64_t oracle_cache_entry_created;
	uint64_t oracle_timeouts;
} named_resolver_afl_symcc_orchestrator_t;

static bool g_initialized = false;
static named_resolver_afl_symcc_orchestrator_t g_orchestrator = { 0 };
static pthread_mutex_t g_request_context_lock = PTHREAD_MUTEX_INITIALIZER;
static named_resolver_afl_symcc_request_context_t *g_request_context = NULL;

static void
maybe_dump_cache(void) {
	const char *dump_path = getenv("NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH");
	FILE *fp = NULL;
	dns_view_t *view = NULL;
	bool dumped_shared_cache = false;

	if (dump_path == NULL || *dump_path == '\0' || named_g_server == NULL) {
		return;
	}

	fp = fopen(dump_path, "w");
	if (fp == NULL) {
		fprintf(stderr,
			"[resolver-afl-symcc] cache dump open failed: %s\n",
			dump_path);
		return;
	}

	for (view = ISC_LIST_HEAD(named_g_server->viewlist); view != NULL;
	     view = ISC_LIST_NEXT(view, link))
	{
		isc_result_t result;

		if (view->cachedb == NULL) {
			continue;
		}
		if (dns_view_iscacheshared(view)) {
			if (dumped_shared_cache) {
				continue;
			}
			dumped_shared_cache = true;
		}

		result = dns_view_dumpdbtostream(view, fp);
		if (result != ISC_R_SUCCESS) {
			fprintf(stderr,
				"[resolver-afl-symcc] cache dump failed: %s\n",
				isc_result_totext(result));
			break;
		}
	}

	fclose(fp);
}

static void
install_dispatch_hook_if_ready(dns_dispatchmgr_t *mgr) {
	if (!g_initialized || mgr == NULL) {
		return;
	}

	dns_dispatchmgr_setudpresphook(
		mgr, named_resolver_afl_symcc_mutator_dispatch_hook, NULL);
}

static named_resolver_afl_symcc_request_context_t *
get_request_context(void) {
	named_resolver_afl_symcc_request_context_t *ctx = NULL;

	pthread_mutex_lock(&g_request_context_lock);
	ctx = g_request_context;
	pthread_mutex_unlock(&g_request_context_lock);
	return ctx;
}

static void
set_request_context(named_resolver_afl_symcc_request_context_t *ctx) {
	pthread_mutex_lock(&g_request_context_lock);
	g_request_context = ctx;
	pthread_mutex_unlock(&g_request_context_lock);
}

static bool
parse_port_number(const char *text, int *port) {
	char *endp = NULL;
	long value;

	if (text == NULL || *text == '\0' || port == NULL) {
		return false;
	}

	errno = 0;
	value = strtol(text, &endp, 10);
	if (errno != 0 || endp == text || *endp != '\0' || value <= 0 ||
	    value > 65535)
	{
		return false;
	}

	*port = (int)value;
	return true;
}

static void
load_request_target(char *host, size_t host_size, int *port) {
	const char *env = getenv("NAMED_RESOLVER_AFL_SYMCC_TARGET");
	const char *colon = NULL;
	int default_port = (named_g_port != 0) ? (int)named_g_port : 53;

	snprintf(host, host_size, "%s", "127.0.0.1");
	*port = default_port;

	if (env == NULL || *env == '\0') {
		return;
	}

	colon = strrchr(env, ':');
	if (colon == NULL) {
		snprintf(host, host_size, "%s", env);
		return;
	}

	if ((size_t)(colon - env) >= host_size) {
		return;
	}

	if (!parse_port_number(colon + 1, port)) {
		*port = default_port;
		return;
	}

	memcpy(host, env, (size_t)(colon - env));
	host[colon - env] = '\0';
}

static long
load_reply_timeout_ms(void) {
	const char *env = getenv("NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS");
	char *endp = NULL;
	long value;

	if (env == NULL || *env == '\0') {
		return 1000;
	}

	errno = 0;
	value = strtol(env, &endp, 10);
	if (errno != 0 || endp == env || *endp != '\0' || value <= 0) {
		return 1000;
	}

	return value;
}

static bool
load_request_input_path(const char *config, char *path, size_t path_size) {
	const char *cursor = config;

	if (config == NULL || path == NULL || path_size == 0) {
		return false;
	}

	while (*cursor != '\0') {
		const char *segment = cursor;
		const char *comma = strchr(cursor, ',');
		size_t segment_len;

		if (comma == NULL) {
			segment_len = strlen(segment);
			cursor = segment + segment_len;
		} else {
			segment_len = (size_t)(comma - segment);
			cursor = comma + 1;
		}

		if (segment_len > 6 && strncmp(segment, "input=", 6) == 0) {
			size_t path_len = strlen(segment + 6);

			if (path_len >= path_size) {
				return false;
			}
			memcpy(path, segment + 6, path_len);
			path[path_len] = '\0';
			return true;
		}
	}

	return false;
}

static bool
use_afl_persistent_driver(void) {
	return getenv("__AFL_PERSISTENT") != NULL ||
	       getenv("__AFL_SHM_FUZZ_ID") != NULL ||
	       getenv("__AFL_SHM_ID") != NULL || getenv("AFL_CMIN") != NULL;
}

static bool
persistent_debug_enabled(void) {
	return getenv("NAMED_RESOLVER_AFL_SYMCC_DEBUG") != NULL;
}

static ssize_t
read_request_bytes(const char *config, uint8_t *request, size_t request_size) {
	char input_path[PATH_MAX];
	int fd;
	ssize_t length;

	if (!load_request_input_path(config, input_path, sizeof(input_path))) {
		return read(STDIN_FILENO, request, request_size);
	}

	fd = open(input_path, O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	length = read(fd, request, request_size);
	close(fd);
	return length;
}

static void
shutdown_named(void) {
	if (named_g_server != NULL) {
		named_server_flushonshutdown(named_g_server, false);
	}
	isc_app_shutdown();
}

static void
wait_until_named_running(void) {
#ifdef ENABLE_AFL
	while (!named_g_run_done) {
		usleep(10000);
	}
#endif /* ifdef ENABLE_AFL */
}

static void
restore_env_var(const char *name, char *value) {
	if (value != NULL) {
		setenv(name, value, 1);
		free(value);
		return;
	}

	unsetenv(name);
}

static uint16_t
read_u16le(const uint8_t *data) {
	return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static bool
looks_like_transcript(const uint8_t *input, size_t input_len) {
	return input_len >= 4 &&
	       memcmp(input, NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_MAGIC, 4) == 0;
}

static bool
input_length_supported(const uint8_t *input, size_t input_len) {
	if (looks_like_transcript(input, input_len)) {
		return input_len <= NAMED_RESOLVER_AFL_SYMCC_MAX_TRANSCRIPT_INPUT;
	}

	return input_len <= NAMED_RESOLVER_AFL_SYMCC_MAX_LEGACY_INPUT;
}

static bool
parse_transcript_input(const uint8_t *input, size_t input_len,
		       named_resolver_afl_symcc_transcript_t *transcript) {
	size_t cursor = 0;
	size_t header_len = 0;
	size_t index;

	if (input == NULL || transcript == NULL || input_len < 10 ||
	    !looks_like_transcript(input, input_len))
	{
		return false;
	}

	memset(transcript, 0, sizeof(*transcript));
	transcript->response_count = input[4];
	if (transcript->response_count >
	    NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_MAX_RESPONSES)
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
write_file_bytes(const char *path, const uint8_t *data, size_t data_len) {
	int fd;
	ssize_t written;

	if (path == NULL || data == NULL || data_len == 0) {
		return false;
	}

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		return false;
	}

	written = write(fd, data, data_len);
	close(fd);
	return written == (ssize_t)data_len;
}

static bool
materialize_transcript_responses(
	const named_resolver_afl_symcc_transcript_t *transcript, char *dir_path,
	size_t dir_path_size) {
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
		     "%s/named-resolver-afl-symcc-XXXXXX", tmp_root) >=
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
cleanup_transcript_responses(const char *dir_path, size_t response_count) {
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
update_basic_oracle_counters(named_resolver_afl_symcc_orchestrator_t *orchestrator,
			     bool parse_ok, bool resolver_fetch_started,
			     bool response_accepted, bool timeout) {
	if (orchestrator == NULL) {
		return;
	}

	if (parse_ok) {
		orchestrator->oracle_parse_ok++;
	}
	if (resolver_fetch_started) {
		orchestrator->oracle_fetch_started++;
	}
	if (response_accepted) {
		orchestrator->oracle_response_accepted++;
	}
	if (timeout) {
		orchestrator->oracle_timeouts++;
	}

	if (getenv("NAMED_RESOLVER_AFL_SYMCC_TRACE_ORACLE") != NULL) {
		fprintf(stderr,
			"[resolver-afl-symcc] oracle parse_ok=%d fetch_started=%d "
			"response_accepted=%d second_query_hit=0 "
			"cache_entry_created=0 timeout=%d\n",
			parse_ok, resolver_fetch_started, response_accepted,
			timeout);
	}
}

static void
update_transcript_oracle(
	named_resolver_afl_symcc_orchestrator_t *orchestrator,
	const named_resolver_afl_symcc_transcript_oracle_t *oracle) {
	if (orchestrator == NULL || oracle == NULL) {
		return;
	}

	orchestrator->transcript_cases++;
	update_basic_oracle_counters(orchestrator, oracle->parse_ok,
				     oracle->resolver_fetch_started,
				     oracle->response_accepted,
				     oracle->timeout);
	if (oracle->second_query_hit) {
		orchestrator->oracle_second_query_hit++;
	}
	if (oracle->cache_entry_created) {
		orchestrator->oracle_cache_entry_created++;
	}

	if (getenv("NAMED_RESOLVER_AFL_SYMCC_TRACE_ORACLE") != NULL) {
		fprintf(stderr,
			"[resolver-afl-symcc] oracle parse_ok=%d fetch_started=%d "
			"response_accepted=%d second_query_hit=%d "
			"cache_entry_created=%d timeout=%d\n",
			oracle->parse_ok, oracle->resolver_fetch_started,
			oracle->response_accepted, oracle->second_query_hit,
			oracle->cache_entry_created, oracle->timeout);
	}
}

static void
print_stats_and_exit(
	const named_resolver_afl_symcc_orchestrator_t *orchestrator) {
	named_resolver_afl_symcc_mutator_counters_t counters;

	named_resolver_afl_symcc_mutator_server_get_counters(&counters);
	fprintf(stderr,
		"[resolver-afl-symcc] Statistics:\n"
		"  Requests sent: %" PRIu64 "\n"
		"  Replies received: %" PRIu64 "\n"
		"  Reply timeouts: %" PRIu64 "\n"
		"  Send failures: %" PRIu64 "\n"
		"  Transcript cases: %" PRIu64 "\n"
		"  Transcript parse errors: %" PRIu64 "\n"
		"  Oracle parse_ok: %" PRIu64 "\n"
		"  Oracle resolver_fetch_started: %" PRIu64 "\n"
		"  Oracle response_accepted: %" PRIu64 "\n"
		"  Oracle second_query_hit: %" PRIu64 "\n"
		"  Oracle cache_entry_created: %" PRIu64 "\n"
		"  Oracle timeout: %" PRIu64 "\n"
		"  Received: %" PRIu64 "\n"
		"  Replied: %" PRIu64 "\n"
		"  Parse errors: %" PRIu64 "\n",
		orchestrator->requests_sent, orchestrator->replies_received,
		orchestrator->reply_timeouts, orchestrator->send_failures,
		orchestrator->transcript_cases,
		orchestrator->transcript_parse_errors,
		orchestrator->oracle_parse_ok,
		orchestrator->oracle_fetch_started,
		orchestrator->oracle_response_accepted,
		orchestrator->oracle_second_query_hit,
		orchestrator->oracle_cache_entry_created,
		orchestrator->oracle_timeouts,
		counters.received, counters.replied, counters.parse_errors);
	fflush(NULL);
	_exit(0);
}

static void
finish_request_context(named_resolver_afl_symcc_request_context_t *ctx,
		       isc_result_t result) {
	if (ctx == NULL) {
		return;
	}

	pthread_mutex_lock(&ctx->mutex);
	if (ctx->result == ISC_R_UNSET) {
		ctx->result = result;
	}
	ctx->finished = true;
	pthread_cond_signal(&ctx->cond);
	pthread_mutex_unlock(&ctx->mutex);
}

static void
cancel_request_client(ns_client_t *client) {
	if (client == NULL) {
		return;
	}

	if (client->state != NS_CLIENTSTATE_WORKING &&
	    client->state != NS_CLIENTSTATE_RECURSING)
	{
		return;
	}

	client->sendcb = NULL;
	client->shuttingdown = true;
	ns_query_cancel(client);
}

static void
resolver_afl_symcc_request_done_notify(void) {
	named_resolver_afl_symcc_request_context_t *ctx = get_request_context();

	finish_request_context(ctx, ISC_R_SUCCESS);
}

static void
resolver_afl_symcc_client_sendcb(isc_buffer_t *buffer) {
	named_resolver_afl_symcc_request_context_t *ctx = get_request_context();
	isc_region_t region;

	UNUSED(buffer);

	if (ctx == NULL) {
		return;
	}

	if (getenv("NAMED_RESOLVER_AFL_SYMCC_DEBUG") != NULL && buffer != NULL) {
		isc_buffer_usedregion(buffer, &region);
		if (region.length >= 12) {
			uint16_t flags = ((uint16_t)region.base[2] << 8) | region.base[3];
			uint16_t ancount =
				((uint16_t)region.base[6] << 8) | region.base[7];
			uint16_t nscount =
				((uint16_t)region.base[8] << 8) | region.base[9];
			uint16_t arcount =
				((uint16_t)region.base[10] << 8) | region.base[11];
			fprintf(stderr,
				"[resolver-afl-symcc][debug] client reply len=%u "
				"flags=0x%04x rcode=%u an=%u ns=%u ar=%u\n",
				region.length, flags, flags & 0x000f, ancount,
				nscount, arcount);
		} else {
			fprintf(stderr,
				"[resolver-afl-symcc][debug] client reply len=%u\n",
				region.length);
		}
	}

	pthread_mutex_lock(&ctx->mutex);
	ctx->reply_sent = true;
	pthread_mutex_unlock(&ctx->mutex);
}

static void
resolver_afl_symcc_request_connected(isc_nmhandle_t *handle,
					 isc_result_t result, void *arg) {
	named_resolver_afl_symcc_request_context_t *ctx =
		(named_resolver_afl_symcc_request_context_t *)arg;
	ns_interface_t ifp = { 0 };
	isc_region_t region;
	ns_client_t *client = NULL;
	ns_clientmgr_t *clientmgr = NULL;
	bool timed_out = false;

	if (result != ISC_R_SUCCESS) {
		finish_request_context(ctx, result);
		return;
	}

	ifp.mgr = named_g_server->interfacemgr;
	clientmgr = ns_interfacemgr_getclientmgr(ifp.mgr);
	client = isc_nmhandle_getextra(handle);
	result = ns__client_setup(client, clientmgr, true);
	if (result != ISC_R_SUCCESS) {
		finish_request_context(ctx, result);
		return;
	}
	isc_nmhandle_setdata(handle, client, ns__client_reset_cb,
			     ns__client_put_cb);
	client->handle = handle;

	pthread_mutex_lock(&ctx->mutex);
	ctx->client = client;
	timed_out = ctx->timed_out;
	if (ctx->result == ISC_R_UNSET) {
		ctx->result = ISC_R_SUCCESS;
	}
	pthread_mutex_unlock(&ctx->mutex);

	if (timed_out) {
		client->shuttingdown = true;
		isc_nmhandle_detach(&handle);
		finish_request_context(ctx, ISC_R_TIMEDOUT);
		return;
	}

	client->sendcb = resolver_afl_symcc_client_sendcb;
	region.base = (unsigned char *)ctx->request;
	region.length = (unsigned int)ctx->request_len;

	ns__client_request(handle, ISC_R_SUCCESS, &region, &ifp);
}

static isc_result_t
inject_request_bytes(const uint8_t *request, size_t request_len,
			 long timeout_ms) {
	named_resolver_afl_symcc_request_context_t *ctx = NULL;
	struct timespec deadline;
	char host[64];
	int port = 0;
	isc_sockaddr_t local;
	isc_sockaddr_t peer;
	struct sockaddr_in peer4;
	struct sockaddr_in6 peer6;
	isc_result_t result;
	ns_client_t *client = NULL;
	int rc;

	if (request == NULL || request_len == 0) {
		return ISC_R_FAILURE;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return ISC_R_NOMEMORY;
	}

	pthread_mutex_init(&ctx->mutex, NULL);
	pthread_cond_init(&ctx->cond, NULL);
	ctx->request = request;
	ctx->request_len = request_len;
	ctx->result = ISC_R_UNSET;

	load_request_target(host, sizeof(host), &port);

	memset(&peer4, 0, sizeof(peer4));
	peer4.sin_family = AF_INET;
	peer4.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, host, &peer4.sin_addr) == 1) {
		isc_sockaddr_fromin(&peer, &peer4.sin_addr,
				     ntohs(peer4.sin_port));
		isc_sockaddr_any(&local);
	} else {
		memset(&peer6, 0, sizeof(peer6));
		peer6.sin6_family = AF_INET6;
		peer6.sin6_port = htons((uint16_t)port);
		if (inet_pton(AF_INET6, host, &peer6.sin6_addr) != 1) {
			pthread_cond_destroy(&ctx->cond);
			pthread_mutex_destroy(&ctx->mutex);
			free(ctx);
			return ISC_R_FAILURE;
		}
		isc_sockaddr_fromin6(&peer, &peer6.sin6_addr,
				      ntohs(peer6.sin6_port));
		isc_sockaddr_any6(&local);
	}

	set_request_context(ctx);
	isc_nm_udpconnect(named_g_netmgr, &local, &peer,
			  resolver_afl_symcc_request_connected, ctx,
			  (unsigned int)timeout_ms, sizeof(ns_client_t));

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += timeout_ms / 1000;
	deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec += 1;
		deadline.tv_nsec -= 1000000000L;
	}

	pthread_mutex_lock(&ctx->mutex);
	while (!ctx->finished) {
		rc = pthread_cond_timedwait(&ctx->cond, &ctx->mutex, &deadline);
		if (rc == ETIMEDOUT) {
			ctx->timed_out = true;
			if (ctx->result == ISC_R_UNSET) {
				ctx->result = ISC_R_TIMEDOUT;
			}
			client = ctx->client;
			break;
		}
	}
	result = ctx->result;
	pthread_mutex_unlock(&ctx->mutex);

	if (ctx->timed_out) {
		cancel_request_client(client);
		set_request_context(NULL);
		return result;
	}

	set_request_context(NULL);

	pthread_cond_destroy(&ctx->cond);
	pthread_mutex_destroy(&ctx->mutex);
	free(ctx);

	if (result != ISC_R_SUCCESS) {
		return result;
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
execute_legacy_request(named_resolver_afl_symcc_orchestrator_t *orchestrator,
		       const uint8_t *input, size_t input_len, long timeout_ms) {
	isc_result_t result;

	orchestrator->requests_sent++;
	result = inject_request_bytes(input, input_len, timeout_ms);
	if (result == ISC_R_SUCCESS) {
		orchestrator->replies_received++;
	} else if (result == ISC_R_TIMEDOUT) {
		orchestrator->reply_timeouts++;
	} else {
		orchestrator->send_failures++;
	}

	return result;
}

static isc_result_t
execute_legacy_case(named_resolver_afl_symcc_orchestrator_t *orchestrator,
		    const uint8_t *input, size_t input_len, long timeout_ms) {
	named_resolver_afl_symcc_mutator_counters_t counters_before;
	named_resolver_afl_symcc_mutator_counters_t counters_after;
	isc_result_t result;
	bool parse_ok = false;
	bool resolver_fetch_started = false;
	bool response_accepted = false;
	bool timeout = false;

	named_resolver_afl_symcc_mutator_server_get_counters(&counters_before);
	result = execute_legacy_request(orchestrator, input, input_len, timeout_ms);
	named_resolver_afl_symcc_mutator_server_get_counters(&counters_after);

	resolver_fetch_started =
		counters_after.received > counters_before.received;
	parse_ok = resolver_fetch_started;
	response_accepted =
		result == ISC_R_SUCCESS &&
		counters_after.replied > counters_before.replied;
	timeout = result == ISC_R_TIMEDOUT;
	update_basic_oracle_counters(orchestrator, parse_ok,
				     resolver_fetch_started,
				     response_accepted, timeout);
	return result;
}

static isc_result_t
execute_transcript_case(named_resolver_afl_symcc_orchestrator_t *orchestrator,
			const uint8_t *input, size_t input_len, long timeout_ms) {
	named_resolver_afl_symcc_transcript_t transcript;
	named_resolver_afl_symcc_transcript_oracle_t oracle = { 0 };
	named_resolver_afl_symcc_mutator_counters_t counters_before;
	named_resolver_afl_symcc_mutator_counters_t counters_after_first;
	named_resolver_afl_symcc_mutator_counters_t counters_after_second;
	isc_result_t result = ISC_R_FAILURE;
	char response_dir[PATH_MAX];
	char *saved_tail = NULL;
	char *saved_tail_dir = NULL;
	const char *tail_env = getenv("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL");
	const char *tail_dir_env =
		getenv("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR");

	if (!parse_transcript_input(input, input_len, &transcript)) {
		orchestrator->transcript_parse_errors++;
		orchestrator->send_failures++;
		return ISC_R_FAILURE;
	}

	oracle.parse_ok = true;
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
		orchestrator->send_failures++;
		restore_env_var("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL",
				saved_tail);
		restore_env_var("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR",
				saved_tail_dir);
		return ISC_R_FAILURE;
	}

	unsetenv("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL");
	if (transcript.response_count > 0) {
		setenv("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR", response_dir,
		       1);
	} else {
		unsetenv("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR");
	}

	named_resolver_afl_symcc_mutator_server_reset_response_sequence();
	named_resolver_afl_symcc_mutator_server_get_counters(&counters_before);

	result = execute_legacy_request(orchestrator, transcript.client_query,
					transcript.client_query_len, timeout_ms);
	named_resolver_afl_symcc_mutator_server_get_counters(
		&counters_after_first);
	oracle.resolver_fetch_started =
		counters_after_first.received > counters_before.received;
	oracle.response_accepted =
		result == ISC_R_SUCCESS &&
		counters_after_first.replied > counters_before.replied;
	if (result != ISC_R_SUCCESS) {
		if (result == ISC_R_TIMEDOUT) {
			oracle.timeout = true;
		}
		goto done;
	}

	counters_after_second = counters_after_first;
	if (transcript.post_check_query != NULL &&
	    transcript.post_check_query_len > 0)
	{
		bool post_check_hit = false;

		result = execute_legacy_request(orchestrator,
						transcript.post_check_query,
						transcript.post_check_query_len,
						timeout_ms);
		named_resolver_afl_symcc_mutator_server_get_counters(
			&counters_after_second);
		post_check_hit =
			result == ISC_R_SUCCESS &&
			counters_after_second.received ==
				counters_after_first.received &&
			counters_after_second.replied ==
				counters_after_first.replied &&
			counters_after_second.parse_errors ==
				counters_after_first.parse_errors;
		if (post_check_hit) {
			/*
			 * second_query_hit 现在要求第一轮 query 至少发生过一次
			 * 上游抓取，避免把“从未进入 fetch 路径”误标成
			 * post-check 命中代理；cache_entry_created 则进一步要求
			 * 第一轮已接受过伪造响应。
			 */
			oracle.second_query_hit =
				oracle.resolver_fetch_started;
			oracle.cache_entry_created =
				oracle.second_query_hit &&
				oracle.response_accepted;
		}
		if (result == ISC_R_TIMEDOUT) {
			oracle.timeout = true;
		}
	}

done:
	update_transcript_oracle(orchestrator, &oracle);
	restore_env_var("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL", saved_tail);
	restore_env_var("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR",
			saved_tail_dir);
	cleanup_transcript_responses(response_dir, transcript.response_count);
	return result;
}

static isc_result_t
execute_input_case(named_resolver_afl_symcc_orchestrator_t *orchestrator,
		   const uint8_t *input, size_t input_len, long timeout_ms) {
	if (looks_like_transcript(input, input_len)) {
		return execute_transcript_case(orchestrator, input, input_len,
					       timeout_ms);
	}

	return execute_legacy_case(orchestrator, input, input_len, timeout_ms);
}

static void *
request_injector_thread(void *arg) {
	named_resolver_afl_symcc_orchestrator_t *orchestrator =
		(named_resolver_afl_symcc_orchestrator_t *)arg;
	uint8_t request[65536];
	const uint8_t *afl_request;
	long timeout_ms;
	ssize_t length;
	isc_result_t result;

	wait_until_named_running();

	timeout_ms = load_reply_timeout_ms();

	if (use_afl_persistent_driver()) {
		/*
		 * 这里保留现有的 SIGSTOP 持久化节奏，因为 testcase 注入运行在
		 * 独立线程里；只把输入来源切换到 AFL shared-memory buffer。
		 */
		if (persistent_debug_enabled()) {
			fprintf(stderr,
				"[resolver-afl-symcc][debug] persistent branch "
				"enabled shm_fuzz=%s shm=%s persistent=%s cmin=%s\n",
				getenv("__AFL_SHM_FUZZ_ID") != NULL ? "1" : "0",
				getenv("__AFL_SHM_ID") != NULL ? "1" : "0",
				getenv("__AFL_PERSISTENT") != NULL ? "1" : "0",
				getenv("AFL_CMIN") != NULL ? "1" : "0");
		}
#ifdef __AFL_HAVE_MANUAL_CONTROL
		if (persistent_debug_enabled()) {
			fprintf(stderr,
				"[resolver-afl-symcc][debug] deferred init skipped\n");
		}
#endif
		afl_request = __AFL_FUZZ_TESTCASE_BUF;
		if (persistent_debug_enabled()) {
			fprintf(stderr,
				"[resolver-afl-symcc][debug] testcase buffer ready\n");
		}

		for (int loop = 0; loop < 100000; loop++) {
#ifdef NAMED_AFL_FUZZ_FALLBACK
			length = read(STDIN_FILENO, (void *)afl_request, 65536);
#else
			length = (ssize_t)__AFL_FUZZ_TESTCASE_LEN;
#endif
			if (persistent_debug_enabled()) {
				fprintf(stderr,
					"[resolver-afl-symcc][debug] loop=%d len=%zd\n",
					loop, length);
			}
			if (length <= 0) {
#ifdef NAMED_AFL_FUZZ_FALLBACK
				usleep(1000000);
#else
				if (persistent_debug_enabled()) {
					fprintf(stderr,
						"[resolver-afl-symcc][debug] "
						"empty testcase, SIGSTOP\n");
				}
				raise(SIGSTOP);
#endif
				continue;
			}

			if (!input_length_supported(afl_request, (size_t)length)) {
				orchestrator->send_failures++;
				if (persistent_debug_enabled()) {
					fprintf(stderr,
						"[resolver-afl-symcc][debug] "
						"unsupported len=%zd, SIGSTOP\n",
						length);
				}
				raise(SIGSTOP);
				continue;
			}

			result = execute_input_case(orchestrator, afl_request,
						    (size_t)length, timeout_ms);
			if (persistent_debug_enabled()) {
				fprintf(stderr,
					"[resolver-afl-symcc][debug] execute "
					"result=%d\n",
					result);
			}
			if (result == ISC_R_TIMEDOUT) {
				shutdown_named();
				return NULL;
			}

			if (persistent_debug_enabled()) {
				fprintf(stderr,
					"[resolver-afl-symcc][debug] case done, "
					"SIGSTOP\n");
			}
			raise(SIGSTOP);
		}

		shutdown_named();
		return NULL;
	}

	length = read_request_bytes(orchestrator->config, request,
				      sizeof(request));
	if (length > 0 && input_length_supported(request, (size_t)length)) {
		(void)execute_input_case(orchestrator, request, (size_t)length,
					 timeout_ms);
		} else if (length > 0) {
			orchestrator->send_failures++;
		}

		maybe_dump_cache();
		print_stats_and_exit(orchestrator);
		return NULL;
	}

isc_result_t
named_resolver_afl_symcc_orchestrator_start(const char *config) {
	isc_result_t result;

	if (g_initialized) {
		return ISC_R_SUCCESS;
	}

	result = named_resolver_afl_symcc_mutator_server_start(config);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr,
			"[resolver-afl-symcc] mutator server start failed: %d\n",
			result);
		return result;
	}

	memset(&g_orchestrator, 0, sizeof(g_orchestrator));
	if (config != NULL) {
		g_orchestrator.config = strdup(config);
		if (g_orchestrator.config == NULL) {
			named_resolver_afl_symcc_mutator_server_stop();
			return ISC_R_NOMEMORY;
		}
	}

	if (named_g_server != NULL && named_g_server->sctx != NULL) {
		g_orchestrator.saved_fuzztype = named_g_server->sctx->fuzztype;
		g_orchestrator.saved_fuzznotify =
			named_g_server->sctx->fuzznotify;
		named_g_server->sctx->fuzztype = isc_fuzz_resolver;
		named_g_server->sctx->fuzznotify =
			resolver_afl_symcc_request_done_notify;
		g_orchestrator.hooks_installed = true;
	}

	if (pthread_create(&g_orchestrator.injector_thread_id, NULL,
			   request_injector_thread, &g_orchestrator) != 0)
	{
		fprintf(stderr,
			"[resolver-afl-symcc] injector thread create failed: %s\n",
			strerror(errno));
		if (named_g_dispatchmgr != NULL) {
			dns_dispatchmgr_setudpresphook(named_g_dispatchmgr, NULL,
							 NULL);
		}
		if (g_orchestrator.hooks_installed) {
			named_g_server->sctx->fuzztype =
				g_orchestrator.saved_fuzztype;
			named_g_server->sctx->fuzznotify =
				g_orchestrator.saved_fuzznotify;
		}
		free(g_orchestrator.config);
		g_orchestrator.config = NULL;
		named_resolver_afl_symcc_mutator_server_stop();
		return ISC_R_FAILURE;
	}

	g_orchestrator.injector_thread_started = true;
	g_initialized = true;
	install_dispatch_hook_if_ready(named_g_dispatchmgr);
	return ISC_R_SUCCESS;
}

void
named_resolver_afl_symcc_orchestrator_dispatchmgr_ready(dns_dispatchmgr_t *mgr) {
	install_dispatch_hook_if_ready(mgr);
}

void
named_resolver_afl_symcc_orchestrator_stop(void) {
	named_resolver_afl_symcc_mutator_counters_t counters;

	if (!g_initialized) {
		return;
	}

	if (g_orchestrator.injector_thread_started) {
		pthread_join(g_orchestrator.injector_thread_id, NULL);
		g_orchestrator.injector_thread_started = false;
	}

	if (named_g_dispatchmgr != NULL) {
		dns_dispatchmgr_setudpresphook(named_g_dispatchmgr, NULL, NULL);
	}
	if (g_orchestrator.hooks_installed && named_g_server != NULL &&
	    named_g_server->sctx != NULL)
	{
		named_g_server->sctx->fuzztype = g_orchestrator.saved_fuzztype;
		named_g_server->sctx->fuzznotify =
			g_orchestrator.saved_fuzznotify;
		g_orchestrator.hooks_installed = false;
	}

	named_resolver_afl_symcc_mutator_server_get_counters(&counters);

	fprintf(stderr,
		"[resolver-afl-symcc] Statistics:\n"
		"  Requests sent: %" PRIu64 "\n"
		"  Replies received: %" PRIu64 "\n"
		"  Reply timeouts: %" PRIu64 "\n"
		"  Send failures: %" PRIu64 "\n"
		"  Transcript cases: %" PRIu64 "\n"
		"  Transcript parse errors: %" PRIu64 "\n"
		"  Oracle parse_ok: %" PRIu64 "\n"
		"  Oracle resolver_fetch_started: %" PRIu64 "\n"
		"  Oracle response_accepted: %" PRIu64 "\n"
		"  Oracle second_query_hit: %" PRIu64 "\n"
		"  Oracle cache_entry_created: %" PRIu64 "\n"
		"  Oracle timeout: %" PRIu64 "\n"
		"  Received: %" PRIu64 "\n"
		"  Replied: %" PRIu64 "\n"
		"  Parse errors: %" PRIu64 "\n",
		g_orchestrator.requests_sent, g_orchestrator.replies_received,
		g_orchestrator.reply_timeouts, g_orchestrator.send_failures,
		g_orchestrator.transcript_cases,
		g_orchestrator.transcript_parse_errors,
		g_orchestrator.oracle_parse_ok,
		g_orchestrator.oracle_fetch_started,
		g_orchestrator.oracle_response_accepted,
		g_orchestrator.oracle_second_query_hit,
		g_orchestrator.oracle_cache_entry_created,
		g_orchestrator.oracle_timeouts,
		counters.received, counters.replied, counters.parse_errors);

	named_resolver_afl_symcc_mutator_server_stop();

	free(g_orchestrator.config);
	memset(&g_orchestrator, 0, sizeof(g_orchestrator));
	g_initialized = false;
	fflush(NULL);
	_exit(0);
}
