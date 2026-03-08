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
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <isc/app.h>
#include <isc/result.h>

#include <named/globals.h>
#include <named/resolver_afl_symcc_mutator_server.h>
#include <named/resolver_afl_symcc_orchestrator.h>
#include <named/server.h>

typedef struct named_resolver_afl_symcc_orchestrator {
	pthread_t injector_thread_id;
	bool injector_thread_started;
	char *config;
	uint64_t requests_sent;
	uint64_t replies_received;
	uint64_t reply_timeouts;
	uint64_t send_failures;
} named_resolver_afl_symcc_orchestrator_t;

static bool g_initialized = false;
static named_resolver_afl_symcc_orchestrator_t g_orchestrator = { 0 };

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
			if (segment_len - 6 >= path_size) {
				return false;
			}
			memcpy(path, segment + 6, segment_len - 6);
			path[segment_len - 6] = '\0';
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

static void *
request_injector_thread(void *arg) {
	named_resolver_afl_symcc_orchestrator_t *orchestrator =
		(named_resolver_afl_symcc_orchestrator_t *)arg;
	struct sockaddr_in server_addr;
	struct timeval timeout;
	uint8_t request[65536];
	uint8_t response[65536];
	char host[64];
	int port = 0;
	int sockfd = -1;
	long timeout_ms;
	ssize_t length;

	while (!named_g_run_done) {
		usleep(10000);
	}

	load_request_target(host, sizeof(host), &port);
	timeout_ms = load_reply_timeout_ms();

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		orchestrator->send_failures++;
		print_stats_and_exit(orchestrator);
	}

	timeout.tv_sec = timeout_ms / 1000;
	timeout.tv_usec = (timeout_ms % 1000) * 1000;
	(void)setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
			 sizeof(timeout));

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, host, &server_addr.sin_addr) != 1) {
		orchestrator->send_failures++;
		close(sockfd);
		print_stats_and_exit(orchestrator);
	}

	if (use_afl_persistent_driver()) {
		for (int loop = 0; loop < 100000; loop++) {
			ssize_t sent;

			length = read(STDIN_FILENO, request, sizeof(request));
			if (length <= 0) {
				usleep(1000000);
				continue;
			}

			if (length > 4096) {
				if (getenv("AFL_CMIN") != NULL) {
					close(sockfd);
					shutdown_named();
					return NULL;
				}
				raise(SIGSTOP);
				continue;
			}

			sent = sendto(sockfd, request, (size_t)length, 0,
				      (struct sockaddr *)&server_addr,
				      sizeof(server_addr));
			if (sent == length) {
				orchestrator->requests_sent++;
				if (recvfrom(sockfd, response, sizeof(response),
					     0, NULL, NULL) >= 0)
				{
					orchestrator->replies_received++;
				} else if (errno == EAGAIN ||
					   errno == EWOULDBLOCK)
				{
					orchestrator->reply_timeouts++;
				}
			} else {
				orchestrator->send_failures++;
			}

			raise(SIGSTOP);
		}

		close(sockfd);
		shutdown_named();
		return NULL;
	}

	length = read_request_bytes(orchestrator->config, request,
				      sizeof(request));
	if (length > 0) {
		ssize_t sent;

		sent = sendto(sockfd, request, (size_t)length, 0,
			      (struct sockaddr *)&server_addr,
			      sizeof(server_addr));
		if (sent == length) {
			orchestrator->requests_sent++;
			if (recvfrom(sockfd, response, sizeof(response), 0, NULL,
				     NULL) >= 0)
			{
				orchestrator->replies_received++;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				orchestrator->reply_timeouts++;
			}
		} else {
			orchestrator->send_failures++;
		}
	}

	close(sockfd);
	print_stats_and_exit(orchestrator);
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
	if (pthread_create(&g_orchestrator.injector_thread_id, NULL,
			   request_injector_thread, &g_orchestrator) != 0)
	{
		fprintf(stderr,
			"[resolver-afl-symcc] injector thread create failed: %s\n",
			strerror(errno));
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
