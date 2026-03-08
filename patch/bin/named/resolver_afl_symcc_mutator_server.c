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

#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <isc/result.h>
#include <isc/region.h>
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

isc_result_t
named_resolver_afl_symcc_mutator_server_start(const char *config) {
	UNUSED(config);

	if (g_server != NULL) {
		return ISC_R_SUCCESS;
	}

	g_server = (named_resolver_afl_symcc_mutator_server_t *)malloc(
		sizeof(named_resolver_afl_symcc_mutator_server_t));
	if (g_server == NULL) {
		return ISC_R_NOMEMORY;
	}

	memset(g_server, 0, sizeof(*g_server));
	g_server->tail_pick_count = 0;
	return ISC_R_SUCCESS;
}

isc_result_t
named_resolver_afl_symcc_mutator_dispatch_hook(
	dns_dispentry_t *resp, const isc_region_t *request,
	unsigned char *response_buf, size_t response_buf_size,
	isc_region_t *response, void *arg) {
	int response_len;

	UNUSED(resp);
	UNUSED(arg);

	if (g_server == NULL) {
		return ISC_R_NOTFOUND;
	}
	if (request == NULL || request->base == NULL || response == NULL ||
	    response_buf == NULL)
	{
		return ISC_R_TIMEDOUT;
	}

	g_server->received++;

	response_len = build_dns_response(g_server, request->base,
					  (size_t)request->length,
					  response_buf, response_buf_size);
	if (response_len < 0) {
		g_server->parse_errors++;
		return ISC_R_TIMEDOUT;
	}

	response->base = response_buf;
	response->length = (unsigned int)response_len;
	g_server->replied++;
	return ISC_R_SUCCESS;
}

void
named_resolver_afl_symcc_mutator_server_stop(void) {
	if (g_server == NULL) {
		return;
	}

	free(g_server);
	g_server = NULL;
}

void
named_resolver_afl_symcc_mutator_server_add_received(uint64_t delta) {
	if (g_server != NULL) {
		g_server->received += delta;
	}
}

void
named_resolver_afl_symcc_mutator_server_add_replied(uint64_t delta) {
	if (g_server != NULL) {
		g_server->replied += delta;
	}
}

void
named_resolver_afl_symcc_mutator_server_add_parse_errors(uint64_t delta) {
	if (g_server != NULL) {
		g_server->parse_errors += delta;
	}
}

void
named_resolver_afl_symcc_mutator_server_get_counters(
	named_resolver_afl_symcc_mutator_counters_t *counters) {
	if (counters == NULL) {
		return;
	}

	if (g_server != NULL) {
		counters->received = g_server->received;
		counters->replied = g_server->replied;
		counters->parse_errors = g_server->parse_errors;
	} else {
		counters->received = 0;
		counters->replied = 0;
		counters->parse_errors = 0;
	}
}
