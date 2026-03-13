#include "config.h"

#include "smallapp/unbound_afl_symcc_mutator_server.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define UNBOUND_AFL_SYMCC_MAX_PACKET 65536

/*
 * 用 BIND9 legacy-response-tail 的策略拼 reply:
 * - 复制 query 的 header+question（保证 ID 与 question 匹配）
 * - 从 response-tail 样本中取出 question_end 之后的 section bytes 作为尾段
 */
typedef struct {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} unbound_afl_symcc_dns_header_t;

typedef struct unbound_afl_symcc_mutator_server {
	pthread_t thread_id;
	bool thread_started;
	int sockfd;
	bool stop_requested;
	uint16_t bound_port;
	uint64_t tail_pick_count;
	uint64_t received;
	uint64_t replied;
	uint64_t parse_errors;
} unbound_afl_symcc_mutator_server_t;

static pthread_mutex_t g_server_lock = PTHREAD_MUTEX_INITIALIZER;
static unbound_afl_symcc_mutator_server_t *g_server = NULL;

static int
parse_dns_header(const uint8_t *buf, size_t len,
	unbound_afl_symcc_dns_header_t *hdr)
{
	if (len < 12) {
		return -1;
	}

	hdr->id = (uint16_t)((buf[0] << 8) | buf[1]);
	hdr->flags = (uint16_t)((buf[2] << 8) | buf[3]);
	hdr->qdcount = (uint16_t)((buf[4] << 8) | buf[5]);
	hdr->ancount = (uint16_t)((buf[6] << 8) | buf[7]);
	hdr->nscount = (uint16_t)((buf[8] << 8) | buf[9]);
	hdr->arcount = (uint16_t)((buf[10] << 8) | buf[11]);

	return 0;
}

static int
parse_dns_question_end(const uint8_t *packet, size_t packet_len,
	const unbound_afl_symcc_dns_header_t *hdr, size_t *question_end)
{
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

static int
parse_dns_name_end(const uint8_t *packet, size_t packet_len, size_t pos,
	size_t *name_end)
{
	size_t cursor = pos;

	while (cursor < packet_len) {
		uint8_t label_len = packet[cursor];

		if (label_len == 0) {
			cursor++;
			*name_end = cursor;
			return 0;
		}

		if ((label_len & 0xC0) == 0xC0) {
			if (cursor + 1 >= packet_len) {
				return -1;
			}
			cursor += 2;
			*name_end = cursor;
			return 0;
		}

		if ((label_len & 0xC0) != 0) {
			return -1;
		}

		if (label_len > 63 || cursor + 1 + label_len > packet_len) {
			return -1;
		}

		cursor += 1 + label_len;
	}

	return -1;
}

static int
parse_dns_rr_end(const uint8_t *packet, size_t packet_len, size_t pos,
	size_t *rr_end)
{
	size_t name_end = 0;
	size_t cursor = pos;
	uint16_t rdlen;

	if (parse_dns_name_end(packet, packet_len, cursor, &name_end) != 0) {
		return -1;
	}
	cursor = name_end;

	/* type(2) + class(2) + ttl(4) + rdlen(2) */
	if (cursor + 10 > packet_len) {
		return -1;
	}
	rdlen = (uint16_t)((packet[cursor + 8] << 8) | packet[cursor + 9]);
	cursor += 10;
	if (cursor + rdlen > packet_len) {
		return -1;
	}
	cursor += rdlen;

	*rr_end = cursor;
	return 0;
}

static bool
copy_path_string(char *dst, size_t dst_size, const char *src)
{
	int written;

	if (dst == NULL || dst_size == 0 || src == NULL || *src == '\0') {
		return false;
	}

	written = snprintf(dst, dst_size, "%s", src);
	return written > 0 && (size_t)written < dst_size;
}

static bool
pick_sorted_regular_file(const char *dir_path, uint64_t wanted_index,
	char *path, size_t path_size)
{
	uint64_t rank;
	char last_path[PATH_MAX];
	char candidate[PATH_MAX];

	last_path[0] = '\0';

	for (rank = 0; rank <= wanted_index; rank++) {
		DIR *dir = opendir(dir_path);
		struct dirent *entry = NULL;
		struct stat st;
		bool found = false;
		char best_path[PATH_MAX];

		if (dir == NULL) {
			return false;
		}

		best_path[0] = '\0';
		while ((entry = readdir(dir)) != NULL) {
			if (entry->d_name[0] == '.') {
				continue;
			}

			snprintf(candidate, sizeof(candidate), "%s/%s", dir_path,
				entry->d_name);
			if (stat(candidate, &st) != 0 || !S_ISREG(st.st_mode)) {
				continue;
			}
			if (last_path[0] != '\0' && strcmp(candidate, last_path) <= 0) {
				continue;
			}
			if (!found || strcmp(candidate, best_path) < 0) {
				snprintf(best_path, sizeof(best_path), "%s",
					candidate);
				found = true;
			}
		}

		closedir(dir);
		if (!found) {
			return false;
		}

		snprintf(last_path, sizeof(last_path), "%s", best_path);
	}

	return copy_path_string(path, path_size, last_path);
}

static bool
pick_response_tail_path(unbound_afl_symcc_mutator_server_t *server,
	char *path, size_t path_size)
{
	const char *direct_path =
		getenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL");
	const char *dir_path =
		getenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR");
	DIR *dir = NULL;
	struct dirent *entry = NULL;
	struct stat st;
	uint64_t file_count = 0;
	uint64_t wanted_index = 0;
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

	closedir(dir);
	if (file_count == 0) {
		return false;
	}

	wanted_index = server->tail_pick_count % file_count;
	server->tail_pick_count++;
	return pick_sorted_regular_file(dir_path, wanted_index, path, path_size);
}

static bool
load_file_bytes(const char *path, uint8_t *buf, size_t buf_size, size_t *len)
{
	FILE *fp = NULL;
	size_t bytes_read;

	fp = fopen(path, "rb");
	if (fp == NULL) {
		return false;
	}

	bytes_read = fread(buf, 1, buf_size, fp);
	if (ferror(fp) != 0) {
		fclose(fp);
		return false;
	}

	fclose(fp);
	*len = bytes_read;
	return true;
}

bool
unbound_afl_symcc_mutator_server_get_stats(unbound_afl_symcc_mutator_stats_t *out)
{
	bool ok = false;

	if (out == NULL) {
		return false;
	}

	pthread_mutex_lock(&g_server_lock);
	if (g_server != NULL) {
		out->received = g_server->received;
		out->replied = g_server->replied;
		out->parse_errors = g_server->parse_errors;
		ok = true;
	}
	pthread_mutex_unlock(&g_server_lock);
	return ok;
}

static int
load_response_sections(unbound_afl_symcc_mutator_server_t *server,
	uint8_t *sections, size_t sections_max, size_t *sections_len,
	unbound_afl_symcc_dns_header_t *tail_hdr, uint8_t *tail_flags_hi,
	uint8_t *tail_flags_lo)
{
	uint8_t packet[UNBOUND_AFL_SYMCC_MAX_PACKET];
	size_t packet_len = 0;
	size_t question_end = 0;
	size_t safe_end = 0;
	size_t cursor = 0;
	uint16_t i;
	char path[PATH_MAX];

	*sections_len = 0;
	memset(tail_hdr, 0, sizeof(*tail_hdr));
	*tail_flags_hi = 0;
	*tail_flags_lo = 0;

	if (!pick_response_tail_path(server, path, sizeof(path))) {
		return 0;
	}

	if (!load_file_bytes(path, packet, sizeof(packet), &packet_len)) {
		return -1;
	}

	if (parse_dns_header(packet, packet_len, tail_hdr) != 0) {
		return -1;
	}

	if (parse_dns_question_end(packet, packet_len, tail_hdr,
		    &question_end) != 0)
	{
		return -1;
	}

	if (question_end > packet_len || packet_len - question_end > sections_max) {
		return -1;
	}

	/*
	 * 语料可能存在 header 计数与实际内容不一致的情况，这里按计数逐条解析 RR，
	 * 截断到可解析边界并下调计数，避免 Unbound 因尾部脏字节而持续重试。
	 */
	cursor = question_end;
	safe_end = question_end;
	for (i = 0; i < tail_hdr->ancount; i++) {
		size_t rr_end = 0;
		if (parse_dns_rr_end(packet, packet_len, cursor, &rr_end) != 0) {
			tail_hdr->ancount = i;
			tail_hdr->nscount = 0;
			tail_hdr->arcount = 0;
			break;
		}
		cursor = rr_end;
		safe_end = rr_end;
	}
	for (i = 0; i < tail_hdr->nscount; i++) {
		size_t rr_end = 0;
		if (parse_dns_rr_end(packet, packet_len, cursor, &rr_end) != 0) {
			tail_hdr->nscount = i;
			tail_hdr->arcount = 0;
			break;
		}
		cursor = rr_end;
		safe_end = rr_end;
	}
	for (i = 0; i < tail_hdr->arcount; i++) {
		size_t rr_end = 0;
		if (parse_dns_rr_end(packet, packet_len, cursor, &rr_end) != 0) {
			tail_hdr->arcount = i;
			break;
		}
		cursor = rr_end;
		safe_end = rr_end;
	}

	if (safe_end < question_end || safe_end > packet_len) {
		return -1;
	}

	memcpy(sections, packet + question_end, safe_end - question_end);
	*sections_len = safe_end - question_end;
	*tail_flags_hi = packet[2];
	*tail_flags_lo = packet[3];
	return 1;
}

static int
build_dns_response(unbound_afl_symcc_mutator_server_t *server,
	const uint8_t *query, size_t query_len, uint8_t *response,
	size_t response_max)
{
	unbound_afl_symcc_dns_header_t query_hdr;
	unbound_afl_symcc_dns_header_t tail_hdr;
	uint8_t sections[UNBOUND_AFL_SYMCC_MAX_PACKET];
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
	/* QR=1，其它尽量沿用 query，避免不匹配；rcode 先置 0 */
	response[2] = (uint8_t)((query[2] & 0x79) | 0x80);
	/* forwarder 场景下通常会带 RA=1，便于 Unbound 快速收敛 */
	response[3] = 0x80;
	/* 先把 answer/ns/ar 计数清零，后续按 tail 覆盖 */
	response[6] = 0;
	response[7] = 0;
	response[8] = 0;
	response[9] = 0;
	response[10] = 0;
	response[11] = 0;

	tail_status = load_response_sections(server, sections, sizeof(sections),
		&sections_len, &tail_hdr, &tail_flags_hi, &tail_flags_lo);
	if (tail_status < 0) {
		return (int)question_end;
	}

	if (tail_status > 0) {
		if (question_end + sections_len > response_max) {
			return -1;
		}

		memcpy(response + question_end, sections, sections_len);
		response[2] = (uint8_t)((query[2] & 0x79) | 0x80 |
			(tail_flags_hi & 0x04));
		response[3] = (uint8_t)(tail_flags_lo | 0x80);
		response[6] = (uint8_t)((tail_hdr.ancount >> 8) & 0xff);
		response[7] = (uint8_t)(tail_hdr.ancount & 0xff);
		response[8] = (uint8_t)((tail_hdr.nscount >> 8) & 0xff);
		response[9] = (uint8_t)(tail_hdr.nscount & 0xff);
		response[10] = (uint8_t)((tail_hdr.arcount >> 8) & 0xff);
		response[11] = (uint8_t)(tail_hdr.arcount & 0xff);
		if (tail_hdr.ancount == 0 && tail_hdr.nscount == 0 &&
			tail_hdr.arcount == 0 && (response[3] & 0x0f) == 0)
		{
			/* 空 NOERROR 回复容易触发重试，转为 NXDOMAIN */
			response[3] = (uint8_t)((response[3] & 0xf0) | 0x03);
		}
		return (int)(question_end + sections_len);
	}

	return (int)question_end;
}

static void *
mutator_server_thread(void *arg)
{
	unbound_afl_symcc_mutator_server_t *server =
		(unbound_afl_symcc_mutator_server_t *)arg;
	uint8_t query[UNBOUND_AFL_SYMCC_MAX_PACKET];
	uint8_t response[UNBOUND_AFL_SYMCC_MAX_PACKET];

	while (!server->stop_requested) {
		struct sockaddr_storage client;
		socklen_t client_len = (socklen_t)sizeof(client);
		ssize_t n;
		int resp_len;

		n = recvfrom(server->sockfd, query, sizeof(query), 0,
			(struct sockaddr *)&client, &client_len);
		if (n < 0) {
			if (server->stop_requested) {
				break;
			}
			continue;
		}

		server->received++;
		resp_len = build_dns_response(server, query, (size_t)n, response,
			sizeof(response));
		if (resp_len < 0) {
			server->parse_errors++;
			continue;
		}

		if (sendto(server->sockfd, response, (size_t)resp_len, 0,
			(struct sockaddr *)&client, client_len) == resp_len)
		{
			server->replied++;
		}
	}

	return NULL;
}

static bool
bind_udp_loopback(int sockfd, uint16_t requested_port, uint16_t *bound_port)
{
	struct sockaddr_in addr;
	socklen_t addrlen = (socklen_t)sizeof(addr);
	struct timeval tv;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(requested_port);
	if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
		return false;
	}

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		return false;
	}

	if (getsockname(sockfd, (struct sockaddr *)&addr, &addrlen) != 0) {
		return false;
	}

	/* 避免 stop 时 join 卡住：让 recvfrom 周期性超时返回 */
	tv.tv_sec = 0;
	tv.tv_usec = 200000;
	(void)setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	*bound_port = ntohs(addr.sin_port);
	return *bound_port != 0;
}

bool
unbound_afl_symcc_mutator_server_start(uint16_t requested_port,
	uint16_t *bound_port)
{
	unbound_afl_symcc_mutator_server_t *server = NULL;
	int sockfd = -1;
	int reuse = 1;
	uint16_t port = 0;
	bool ok = false;

	if (bound_port == NULL) {
		return false;
	}

	pthread_mutex_lock(&g_server_lock);
	if (g_server != NULL) {
		*bound_port = g_server->bound_port;
		pthread_mutex_unlock(&g_server_lock);
		return true;
	}
	pthread_mutex_unlock(&g_server_lock);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		return false;
	}
	(void)setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	if (!bind_udp_loopback(sockfd, requested_port, &port)) {
		close(sockfd);
		return false;
	}

	server = (unbound_afl_symcc_mutator_server_t *)calloc(1, sizeof(*server));
	if (server == NULL) {
		close(sockfd);
		return false;
	}
	server->sockfd = sockfd;
	server->bound_port = port;

	if (pthread_create(&server->thread_id, NULL, mutator_server_thread,
		    server) != 0)
	{
		close(sockfd);
		free(server);
		return false;
	}
	server->thread_started = true;

	pthread_mutex_lock(&g_server_lock);
	g_server = server;
	ok = true;
	pthread_mutex_unlock(&g_server_lock);

	*bound_port = port;
	return ok;
}

void
unbound_afl_symcc_mutator_server_stop(void)
{
	unbound_afl_symcc_mutator_server_t *server = NULL;

	pthread_mutex_lock(&g_server_lock);
	server = g_server;
	g_server = NULL;
	pthread_mutex_unlock(&g_server_lock);

	if (server == NULL) {
		return;
	}

	server->stop_requested = true;
	if (server->thread_started) {
		pthread_join(server->thread_id, NULL);
		server->thread_started = false;
	}
	if (server->sockfd >= 0) {
		close(server->sockfd);
		server->sockfd = -1;
	}
	free(server);
}
