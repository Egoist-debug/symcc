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

#include <ns/client.h>
#include <ns/interfacemgr.h>

#include <named/globals.h>
#include <named/resolver_afl_symcc_mutator_server.h>
#include <named/resolver_afl_symcc_orchestrator.h>
#include <named/server.h>

typedef struct named_resolver_afl_symcc_request_context {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	const uint8_t *request;
	size_t request_len;
	ns_client_t *client;
	bool finished;
	bool reply_sent;
	isc_result_t result;
} named_resolver_afl_symcc_request_context_t;

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
} named_resolver_afl_symcc_orchestrator_t;

static bool g_initialized = false;
static named_resolver_afl_symcc_orchestrator_t g_orchestrator = { 0 };
static pthread_mutex_t g_request_context_lock = PTHREAD_MUTEX_INITIALIZER;
static named_resolver_afl_symcc_request_context_t *g_request_context = NULL;

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
	return getenv("__AFL_PERSISTENT") != NULL || getenv("AFL_CMIN") != NULL;
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
		"  Received: %" PRIu64 "\n"
		"  Replied: %" PRIu64 "\n"
		"  Parse errors: %" PRIu64 "\n",
		orchestrator->requests_sent, orchestrator->replies_received,
		orchestrator->reply_timeouts, orchestrator->send_failures,
		counters.received, counters.replied, counters.parse_errors);
	fflush(NULL);
	_exit(0);
}

static void
resolver_afl_symcc_request_done_notify(void) {
	named_resolver_afl_symcc_request_context_t *ctx = get_request_context();

	if (ctx == NULL) {
		return;
	}

	pthread_mutex_lock(&ctx->mutex);
	if (ctx->result == ISC_R_UNSET) {
		ctx->result = ISC_R_SUCCESS;
	}
	ctx->finished = true;
	pthread_cond_signal(&ctx->cond);
	pthread_mutex_unlock(&ctx->mutex);
}

static void
resolver_afl_symcc_client_sendcb(isc_buffer_t *buffer) {
	named_resolver_afl_symcc_request_context_t *ctx = get_request_context();

	UNUSED(buffer);

	if (ctx == NULL) {
		return;
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

	if (result != ISC_R_SUCCESS) {
		pthread_mutex_lock(&ctx->mutex);
		ctx->result = result;
		ctx->finished = true;
		pthread_cond_signal(&ctx->cond);
		pthread_mutex_unlock(&ctx->mutex);
		return;
	}

	ifp.mgr = named_g_server->interfacemgr;
	clientmgr = ns_interfacemgr_getclientmgr(ifp.mgr);
	client = isc_nmhandle_getextra(handle);
	result = ns__client_setup(client, clientmgr, true);
	if (result != ISC_R_SUCCESS) {
		pthread_mutex_lock(&ctx->mutex);
		ctx->result = result;
		ctx->finished = true;
		pthread_cond_signal(&ctx->cond);
		pthread_mutex_unlock(&ctx->mutex);
		return;
	}
	client->sendcb = resolver_afl_symcc_client_sendcb;
	isc_nmhandle_setdata(handle, client, ns__client_reset_cb,
			     ns__client_put_cb);
	client->handle = handle;
	region.base = (unsigned char *)ctx->request;
	region.length = (unsigned int)ctx->request_len;

	pthread_mutex_lock(&ctx->mutex);
	ctx->client = client;
	if (ctx->result == ISC_R_UNSET) {
		ctx->result = ISC_R_SUCCESS;
	}
	pthread_mutex_unlock(&ctx->mutex);

	ns__client_request(handle, ISC_R_SUCCESS, &region, &ifp);
}

static isc_result_t
inject_request_bytes(const uint8_t *request, size_t request_len,
			 long timeout_ms) {
	named_resolver_afl_symcc_request_context_t ctx;
	struct timespec deadline;
	char host[64];
	int port = 0;
	isc_sockaddr_t local;
	isc_sockaddr_t peer;
	struct sockaddr_in peer4;
	struct sockaddr_in6 peer6;
	int rc;

	if (request == NULL || request_len == 0) {
		return ISC_R_FAILURE;
	}

	memset(&ctx, 0, sizeof(ctx));
	pthread_mutex_init(&ctx.mutex, NULL);
	pthread_cond_init(&ctx.cond, NULL);
	ctx.request = request;
	ctx.request_len = request_len;
	ctx.result = ISC_R_UNSET;

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
			pthread_cond_destroy(&ctx.cond);
			pthread_mutex_destroy(&ctx.mutex);
			return ISC_R_FAILURE;
		}
		isc_sockaddr_fromin6(&peer, &peer6.sin6_addr,
				      ntohs(peer6.sin6_port));
		isc_sockaddr_any6(&local);
	}

	set_request_context(&ctx);
	isc_nm_udpconnect(named_g_netmgr, &local, &peer,
			  resolver_afl_symcc_request_connected, &ctx,
			  (unsigned int)timeout_ms, sizeof(ns_client_t));

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += timeout_ms / 1000;
	deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec += 1;
		deadline.tv_nsec -= 1000000000L;
	}

	pthread_mutex_lock(&ctx.mutex);
	while (!ctx.finished) {
		rc = pthread_cond_timedwait(&ctx.cond, &ctx.mutex, &deadline);
		if (rc == ETIMEDOUT) {
			ctx.result = ISC_R_TIMEDOUT;
			break;
		}
	}
	pthread_mutex_unlock(&ctx.mutex);

	set_request_context(NULL);

	pthread_cond_destroy(&ctx.cond);
	pthread_mutex_destroy(&ctx.mutex);

	if (ctx.result != ISC_R_SUCCESS) {
		return ctx.result;
	}
	return ISC_R_SUCCESS;
}

static void *
request_injector_thread(void *arg) {
	named_resolver_afl_symcc_orchestrator_t *orchestrator =
		(named_resolver_afl_symcc_orchestrator_t *)arg;
	uint8_t request[65536];
	long timeout_ms;
	ssize_t length;
	isc_result_t result;

	wait_until_named_running();

	timeout_ms = load_reply_timeout_ms();

	if (use_afl_persistent_driver()) {
		for (int loop = 0; loop < 100000; loop++) {
			length = read(STDIN_FILENO, request, sizeof(request));
			if (length <= 0) {
				usleep(1000000);
				continue;
			}

			if (length > 4096) {
				if (getenv("AFL_CMIN") != NULL) {
					shutdown_named();
					return NULL;
				}
				raise(SIGSTOP);
				continue;
			}

			orchestrator->requests_sent++;
			result = inject_request_bytes(request, (size_t)length,
						      timeout_ms);
			if (result == ISC_R_SUCCESS) {
				orchestrator->replies_received++;
			} else if (result == ISC_R_TIMEDOUT) {
				orchestrator->reply_timeouts++;
			} else {
				orchestrator->send_failures++;
			}

			raise(SIGSTOP);
		}

		shutdown_named();
		return NULL;
	}

	length = read_request_bytes(orchestrator->config, request,
				      sizeof(request));
	if (length > 0) {
		orchestrator->requests_sent++;
		result = inject_request_bytes(request, (size_t)length,
					      timeout_ms);
		if (result == ISC_R_SUCCESS) {
			orchestrator->replies_received++;
		} else if (result == ISC_R_TIMEDOUT) {
			orchestrator->reply_timeouts++;
		} else {
			orchestrator->send_failures++;
		}
	}

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

	if (named_g_dispatchmgr != NULL) {
		dns_dispatchmgr_setudpresphook(
			named_g_dispatchmgr,
			named_resolver_afl_symcc_mutator_dispatch_hook, NULL);
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
	return ISC_R_SUCCESS;
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
		"  Received: %" PRIu64 "\n"
		"  Replied: %" PRIu64 "\n"
		"  Parse errors: %" PRIu64 "\n",
		g_orchestrator.requests_sent, g_orchestrator.replies_received,
		g_orchestrator.reply_timeouts, g_orchestrator.send_failures,
		counters.received, counters.replied, counters.parse_errors);

	named_resolver_afl_symcc_mutator_server_stop();

	free(g_orchestrator.config);
	memset(&g_orchestrator, 0, sizeof(g_orchestrator));
	g_initialized = false;
	fflush(NULL);
	_exit(0);
}
