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
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
	uint64_t tail_pick_count;
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

static int
parse_dns_question_end(const uint8_t *packet, size_t packet_len,
		       const dns_header_t *hdr, size_t *question_end) {
	size_t pos = 12;
	uint16_t index;

	for (index = 0; index < hdr->qdcount; index++) {
		while (pos < packet_len) {
			uint8_t label_len = packet[pos];

			if (label_len == 0) {
				pos++;
				break;
			}

			if ((label_len & 0xC0) == 0xC0) {
				if (pos + 1 >= packet_len) {
					return -1;
				}
				pos += 2;
				break;
			}

			if (label_len > 63 || pos + 1 + label_len > packet_len) {
				return -1;
			}

			pos += 1 + label_len;
		}

		if (pos + 4 > packet_len) {
			return -1;
		}
		pos += 4;
	}

	*question_end = pos;
	return 0;
}

static bool
copy_path_string(char *dst, size_t dst_size, const char *src) {
	int written;

	if (dst == NULL || dst_size == 0 || src == NULL || *src == '\0') {
		return false;
	}

	written = snprintf(dst, dst_size, "%s", src);
	return written > 0 && (size_t)written < dst_size;
}

static bool
pick_response_tail_path(named_resolver_afl_symcc_mutator_server_t *server,
			char *path, size_t path_size) {
	const char *direct_path = getenv("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL");
	const char *dir_path =
		getenv("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR");
	DIR *dir = NULL;
	struct dirent *entry = NULL;
	struct stat st;
	uint64_t file_count = 0;
	uint64_t wanted_index = 0;
	uint64_t current_index = 0;
	char candidate[PATH_MAX];

	if (copy_path_string(path, path_size, direct_path)) {
		return true;
	}

	if (dir_path == NULL || *dir_path == '\0') {
		return false;
	}

	dir = opendir(dir_path);
	if (dir == NULL) {
		return false;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') {
			continue;
		}

		snprintf(candidate, sizeof(candidate), "%s/%s", dir_path,
			 entry->d_name);
		if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
			file_count++;
		}
	}

	if (file_count == 0) {
		closedir(dir);
		return false;
	}

	wanted_index = server->tail_pick_count % file_count;
	rewinddir(dir);

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') {
			continue;
		}

		snprintf(candidate, sizeof(candidate), "%s/%s", dir_path,
			 entry->d_name);
		if (stat(candidate, &st) != 0 || !S_ISREG(st.st_mode)) {
			continue;
		}

		if (current_index == wanted_index) {
			server->tail_pick_count++;
			closedir(dir);
			return copy_path_string(path, path_size, candidate);
		}

		current_index++;
	}

	closedir(dir);
	return false;
}

static int
load_file_bytes(const char *path, uint8_t *buf, size_t buf_size, size_t *len) {
	FILE *fp = fopen(path, "rb");
	size_t bytes_read;

	if (fp == NULL) {
		return -1;
	}

	bytes_read = fread(buf, 1, buf_size, fp);
	if (ferror(fp) != 0) {
		fclose(fp);
		return -1;
	}

	fclose(fp);
	*len = bytes_read;
	return 0;
}

static int
load_response_sections(named_resolver_afl_symcc_mutator_server_t *server,
		       uint8_t *sections, size_t sections_max,
		       size_t *sections_len, dns_header_t *tail_hdr,
		       uint8_t *tail_flags_hi, uint8_t *tail_flags_lo) {
	uint8_t packet[65536];
	size_t packet_len = 0;
	size_t question_end = 0;
	char path[PATH_MAX];

	*sections_len = 0;
	memset(tail_hdr, 0, sizeof(*tail_hdr));
	*tail_flags_hi = 0;
	*tail_flags_lo = 0;

	if (!pick_response_tail_path(server, path, sizeof(path))) {
		return 0;
	}

	if (load_file_bytes(path, packet, sizeof(packet), &packet_len) != 0) {
		return -1;
	}

	if (parse_dns_header(packet, packet_len, tail_hdr) != 0) {
		return -1;
	}

	if (parse_dns_question_end(packet, packet_len, tail_hdr, &question_end) !=
	    0)
	{
		return -1;
	}

	if (question_end > packet_len || packet_len - question_end > sections_max) {
		return -1;
	}

	memcpy(sections, packet + question_end, packet_len - question_end);
	*sections_len = packet_len - question_end;
	*tail_flags_hi = packet[2];
	*tail_flags_lo = packet[3];
	return 1;
}

static int
build_dns_response(named_resolver_afl_symcc_mutator_server_t *server,
		   const uint8_t *query, size_t query_len, uint8_t *response,
		   size_t response_max) {
	dns_header_t query_hdr;
	dns_header_t tail_hdr;
	uint8_t sections[65536];
	uint8_t tail_flags_hi = 0;
	uint8_t tail_flags_lo = 0;
	size_t question_end = 0;
	size_t sections_len = 0;
	int tail_status;

	if (parse_dns_header(query, query_len, &query_hdr) != 0) {
		return -1;
	}

	if (parse_dns_question_end(query, query_len, &query_hdr, &question_end) !=
	    0)
	{
		return -1;
	}

	if (question_end > response_max) {
		return -1;
	}

	memcpy(response, query, question_end);
	response[2] = (query[2] & 0x79) | 0x80;
	response[3] = 0;
	response[6] = 0;
	response[7] = 0;
	response[8] = 0;
	response[9] = 0;
	response[10] = 0;
	response[11] = 0;

	tail_status = load_response_sections(server, sections, sizeof(sections),
					     &sections_len, &tail_hdr,
					     &tail_flags_hi, &tail_flags_lo);
	if (tail_status < 0) {
		return (int)question_end;
	}

	if (tail_status > 0) {
		if (question_end + sections_len > response_max) {
			return -1;
		}

		memcpy(response + question_end, sections, sections_len);
		response[2] =
			(query[2] & 0x79) | 0x80 | (tail_flags_hi & 0x06);
		response[3] = tail_flags_lo;
		response[6] = (tail_hdr.ancount >> 8) & 0xff;
		response[7] = tail_hdr.ancount & 0xff;
		response[8] = (tail_hdr.nscount >> 8) & 0xff;
		response[9] = tail_hdr.nscount & 0xff;
		response[10] = (tail_hdr.arcount >> 8) & 0xff;
		response[11] = tail_hdr.arcount & 0xff;
		return (int)(question_end + sections_len);
	}

	return (int)question_end;
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
		response_len = build_dns_response(server, buf, (size_t)n, response,
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
	char *config_copy = NULL;

	if (g_server != NULL) {
		return ISC_R_SUCCESS;
	}

	/* Parse config if provided (format: "host:port") */
	if (config != NULL) {
		config_copy = strdup(config);
		if (config_copy != NULL) {
			char *comma = strchr(config_copy, ',');
			char *colon;

			if (comma != NULL) {
				*comma = '\0';
			}

			colon = strrchr(config_copy, ':');
			if (colon != NULL) {
				*colon = '\0';
				host = config_copy;
				if (!parse_port_number(colon + 1, &port)) {
					free(config_copy);
					return ISC_R_FAILURE;
				}
			}
		}
	}

	/* Create UDP socket */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		fprintf(stderr,
			"[resolver-afl-symcc] socket creation failed: %s\n",
			strerror(errno));
		return ISC_R_FAILURE;
	}

	/* Allow reuse of address */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt,
		       sizeof(opt)) < 0) {
		fprintf(stderr,
			"[resolver-afl-symcc] setsockopt failed: %s\n",
			strerror(errno));
		close(sockfd);
		return ISC_R_FAILURE;
	}

	/* Bind to address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
		fprintf(stderr,
			"[resolver-afl-symcc] invalid bind address: %s\n", host);
		free(config_copy);
		close(sockfd);
		return ISC_R_FAILURE;
	}

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr,
			"[resolver-afl-symcc] bind failed on %s:%d: %s\n", host,
			port, strerror(errno));
		free(config_copy);
		close(sockfd);
		return ISC_R_FAILURE;
	}
	free(config_copy);

	/* Allocate server structure */
	g_server = (named_resolver_afl_symcc_mutator_server_t *)malloc(
		sizeof(named_resolver_afl_symcc_mutator_server_t));
	if (g_server == NULL) {
		fprintf(stderr,
			"[resolver-afl-symcc] server allocation failed\n");
		close(sockfd);
		return ISC_R_NOMEMORY;
	}

	memset(g_server, 0, sizeof(*g_server));
	g_server->sockfd = sockfd;
	g_server->running = 1;
	g_server->tail_pick_count = 0;
	g_server->received = 0;
	g_server->replied = 0;
	g_server->parse_errors = 0;

	if (pthread_mutex_init(&g_server->mutex, NULL) != 0) {
		fprintf(stderr,
			"[resolver-afl-symcc] mutex init failed: %s\n",
			strerror(errno));
		free(g_server);
		close(sockfd);
		g_server = NULL;
		return ISC_R_FAILURE;
	}

	/* Start server thread */
	if (pthread_create(&g_server->thread_id, NULL,
			   mutator_server_thread, g_server) != 0) {
		fprintf(stderr,
			"[resolver-afl-symcc] server thread create failed: %s\n",
			strerror(errno));
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
