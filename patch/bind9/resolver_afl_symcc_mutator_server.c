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
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <isc/result.h>
#include <isc/util.h>

#include <named/resolver_afl_symcc_mutator_server.h>

/*
 * Minimal DNS packet structure for parsing and responding.
 */
typedef struct {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} dns_header_t;

typedef struct named_resolver_afl_symcc_mutator_server {
	int sockfd;
	pthread_t thread_id;
	volatile int running;
	pthread_mutex_t mutex;
	uint64_t received;
	uint64_t replied;
	uint64_t parse_errors;
} named_resolver_afl_symcc_mutator_server_t;

static named_resolver_afl_symcc_mutator_server_t *g_server = NULL;

/*
 * Parse DNS header from buffer.
 * Returns 0 on success, -1 on error.
 */
static int
parse_dns_header(const uint8_t *buf, size_t len, dns_header_t *hdr) {
	if (len < 12) {
		return -1;
	}

	hdr->id = (buf[0] << 8) | buf[1];
	hdr->flags = (buf[2] << 8) | buf[3];
	hdr->qdcount = (buf[4] << 8) | buf[5];
	hdr->ancount = (buf[6] << 8) | buf[7];
	hdr->nscount = (buf[8] << 8) | buf[9];
	hdr->arcount = (buf[10] << 8) | buf[11];

	return 0;
}

/*
 * Build minimal DNS response: copy header, set QR=1, clear counts.
 * Returns length of response packet, or -1 on error.
 */
static int
build_dns_response(const uint8_t *query, size_t query_len,
		   uint8_t *response, size_t response_max) {
	dns_header_t hdr;

	if (parse_dns_header(query, query_len, &hdr) != 0) {
		return -1;
	}

	if (response_max < 12) {
		return -1;
	}

	/* Copy header */
	memcpy(response, query, 12);

	/* Set QR bit (bit 7 of flags byte 2) */
	response[2] |= 0x80;

	/* Clear answer/authority/additional counts */
	response[6] = 0;
	response[7] = 0;
	response[8] = 0;
	response[9] = 0;
	response[10] = 0;
	response[11] = 0;

	return 12;
}

/*
 * UDP server thread function.
 */
static void *
mutator_server_thread(void *arg) {
	named_resolver_afl_symcc_mutator_server_t *server =
		(named_resolver_afl_symcc_mutator_server_t *)arg;
	uint8_t buf[65536];
	uint8_t response[65536];
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	int response_len;

	while (server->running) {
		client_addr_len = sizeof(client_addr);
		int n = recvfrom(server->sockfd, buf, sizeof(buf), 0,
				  (struct sockaddr *)&client_addr,
				  &client_addr_len);

		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}

		pthread_mutex_lock(&server->mutex);
		server->received++;
		pthread_mutex_unlock(&server->mutex);

		/* Try to build response */
		response_len = build_dns_response(buf, n, response,
						  sizeof(response));

		if (response_len < 0) {
			pthread_mutex_lock(&server->mutex);
			server->parse_errors++;
			pthread_mutex_unlock(&server->mutex);
			continue;
		}

		/* Send response */
		if (sendto(server->sockfd, response, response_len, 0,
			   (struct sockaddr *)&client_addr,
			   client_addr_len) >= 0) {
			pthread_mutex_lock(&server->mutex);
			server->replied++;
			pthread_mutex_unlock(&server->mutex);
		}
	}

	return NULL;
}

isc_result_t
named_resolver_afl_symcc_mutator_server_start(const char *config) {
	struct sockaddr_in addr;
	const char *host = "127.0.0.1";
	int port = 5300;
	int sockfd;
	int opt = 1;

	if (g_server != NULL) {
		return ISC_R_SUCCESS;
	}

	/* Parse config if provided (format: "host:port") */
	if (config != NULL) {
		char *config_copy = strdup(config);
		if (config_copy != NULL) {
			char *colon = strchr(config_copy, ':');
			if (colon != NULL) {
				*colon = '\0';
				host = config_copy;
				port = atoi(colon + 1);
			}
		}
	}

	/* Create UDP socket */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		return ISC_R_FAILURE;
	}

	/* Allow reuse of address */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt,
		       sizeof(opt)) < 0) {
		close(sockfd);
		return ISC_R_FAILURE;
	}

	/* Bind to address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
		close(sockfd);
		return ISC_R_FAILURE;
	}

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(sockfd);
		return ISC_R_FAILURE;
	}

	/* Allocate server structure */
	g_server = (named_resolver_afl_symcc_mutator_server_t *)malloc(
		sizeof(named_resolver_afl_symcc_mutator_server_t));
	if (g_server == NULL) {
		close(sockfd);
		return ISC_R_NOMEMORY;
	}

	memset(g_server, 0, sizeof(*g_server));
	g_server->sockfd = sockfd;
	g_server->running = 1;
	g_server->received = 0;
	g_server->replied = 0;
	g_server->parse_errors = 0;

	if (pthread_mutex_init(&g_server->mutex, NULL) != 0) {
		free(g_server);
		close(sockfd);
		g_server = NULL;
		return ISC_R_FAILURE;
	}

	/* Start server thread */
	if (pthread_create(&g_server->thread_id, NULL,
			   mutator_server_thread, g_server) != 0) {
		pthread_mutex_destroy(&g_server->mutex);
		free(g_server);
		close(sockfd);
		g_server = NULL;
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

void
named_resolver_afl_symcc_mutator_server_stop(void) {
	if (g_server == NULL) {
		return;
	}

	g_server->running = 0;

	/* Close socket to unblock recvfrom */
	if (g_server->sockfd >= 0) {
		close(g_server->sockfd);
		g_server->sockfd = -1;
	}

	/* Wait for thread to finish */
	pthread_join(g_server->thread_id, NULL);

	pthread_mutex_destroy(&g_server->mutex);
	free(g_server);
	g_server = NULL;
}

void
named_resolver_afl_symcc_mutator_server_add_received(uint64_t delta) {
	if (g_server != NULL) {
		pthread_mutex_lock(&g_server->mutex);
		g_server->received += delta;
		pthread_mutex_unlock(&g_server->mutex);
	}
}

void
named_resolver_afl_symcc_mutator_server_add_replied(uint64_t delta) {
	if (g_server != NULL) {
		pthread_mutex_lock(&g_server->mutex);
		g_server->replied += delta;
		pthread_mutex_unlock(&g_server->mutex);
	}
}

void
named_resolver_afl_symcc_mutator_server_add_parse_errors(uint64_t delta) {
	if (g_server != NULL) {
		pthread_mutex_lock(&g_server->mutex);
		g_server->parse_errors += delta;
		pthread_mutex_unlock(&g_server->mutex);
	}
}

void
named_resolver_afl_symcc_mutator_server_get_counters(
	named_resolver_afl_symcc_mutator_counters_t *counters) {
	if (counters == NULL) {
		return;
	}

	if (g_server != NULL) {
		pthread_mutex_lock(&g_server->mutex);
		counters->received = g_server->received;
		counters->replied = g_server->replied;
		counters->parse_errors = g_server->parse_errors;
		pthread_mutex_unlock(&g_server->mutex);
	} else {
		counters->received = 0;
		counters->replied = 0;
		counters->parse_errors = 0;
	}
}
