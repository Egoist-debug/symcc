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

/* 服务端只使用 IPv4 UDP，超过此载荷上限的输入必须拒绝而非截断。 */
#define UNBOUND_AFL_SYMCC_MAX_PACKET 65507

/*
 * 注入原始响应，仅用实时 query 的事务 ID 绑定请求。
 * 不替换 Question 或修复 RR，避免改变压缩指针和无效报文的语义。
 */
typedef struct {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} unbound_afl_symcc_dns_header_t;

#define UNBOUND_AFL_SYMCC_MAX_MEMORY_RESPONSES 16

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
	const uint8_t *memory_responses[UNBOUND_AFL_SYMCC_MAX_MEMORY_RESPONSES];
	size_t memory_response_lens[UNBOUND_AFL_SYMCC_MAX_MEMORY_RESPONSES];
	size_t memory_response_count;
	unbound_afl_symcc_observer_t observer;
	void *observer_arg;
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
	if (fgetc(fp) != EOF || ferror(fp) != 0) {
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
load_response_packet(unbound_afl_symcc_mutator_server_t *server,
	uint8_t *packet, size_t packet_max, size_t *packet_len)
{
	char path[PATH_MAX];

	*packet_len = 0;

	bool has_memory_resp = false;
	const uint8_t *resp_data = NULL;
	size_t resp_len = 0;

	/* dispatch_query 已持有 g_server_lock，覆盖取样、复制及发送的生命周期。 */
	if (server != NULL && server->memory_response_count > 0) {
		uint64_t wanted_index = server->tail_pick_count % server->memory_response_count;
		server->tail_pick_count++;
		resp_len = server->memory_response_lens[wanted_index];
		resp_data = server->memory_responses[wanted_index];
		has_memory_resp = true;
	}
	if (has_memory_resp) {
		if (resp_data == NULL || resp_len > packet_max) {
			return -1;
		}
		memcpy(packet, resp_data, resp_len);
		*packet_len = resp_len;
	} else {
		if (!pick_response_tail_path(server, path, sizeof(path))) {
			return 0;
		}

		if (!load_file_bytes(path, packet, packet_max, packet_len)) {
			return -1;
		}
	}

	return 1;
}

static int
build_dns_response(unbound_afl_symcc_mutator_server_t *server,
	const uint8_t *query, size_t query_len, uint8_t *response,
	size_t response_max)
{
	unbound_afl_symcc_dns_header_t query_hdr;
	size_t question_end = 0;
	size_t response_len = 0;

	if (parse_dns_header(query, query_len, &query_hdr) != 0) {
		return -1;
	}

	if (parse_dns_question_end(query, query_len, &query_hdr, &question_end) !=
		0)
	{
		return -1;
	}

	if (response_max > UNBOUND_AFL_SYMCC_MAX_PACKET) {
		response_max = UNBOUND_AFL_SYMCC_MAX_PACKET;
	}

	/* 缺失、读取失败或不完整的 header 不能变成新造的空回复。 */
	if (load_response_packet(server, response, response_max, &response_len) !=
		    1 || response_len < 12)
	{
		return -1;
	}

	response[0] = query[0];
	response[1] = query[1];
	return (int)response_len;
}

static void
dispatch_query(unbound_afl_symcc_mutator_server_t *server,
	const uint8_t *query, size_t query_len, struct sockaddr *client,
	socklen_t client_len)
{
	uint8_t response[UNBOUND_AFL_SYMCC_MAX_PACKET];
	int resp_len;

	pthread_mutex_lock(&g_server_lock);
	server->received++;
	if (server->observer != NULL) {
		server->observer(query, query_len, false, server->observer_arg);
	}
	resp_len = build_dns_response(server, query, query_len, response,
		sizeof(response));
	if (resp_len < 0) {
		server->parse_errors++;
	} else if (sendto(server->sockfd, response, (size_t)resp_len, 0,
		client, client_len) == resp_len)
	{
		server->replied++;
		if (server->observer != NULL) {
			server->observer(query, query_len, true, server->observer_arg);
		}
	}
	pthread_mutex_unlock(&g_server_lock);
}

void
unbound_afl_symcc_mutator_server_set_observer(unbound_afl_symcc_observer_t observer,
	void *arg)
{
	pthread_mutex_lock(&g_server_lock);
	if (g_server != NULL) {
		g_server->observer = observer;
		g_server->observer_arg = arg;
	}
	pthread_mutex_unlock(&g_server_lock);
}

static void *
mutator_server_thread(void *arg)
{
	unbound_afl_symcc_mutator_server_t *server =
		(unbound_afl_symcc_mutator_server_t *)arg;
	uint8_t query[UNBOUND_AFL_SYMCC_MAX_PACKET];

	while (true) {
		struct sockaddr_storage client;
		socklen_t client_len = (socklen_t)sizeof(client);
		ssize_t n;
		bool stopped;

		pthread_mutex_lock(&g_server_lock);
		stopped = server->stop_requested;
		pthread_mutex_unlock(&g_server_lock);
		if (stopped) {
			break;
		}
		n = recvfrom(server->sockfd, query, sizeof(query), 0,
			(struct sockaddr *)&client, &client_len);
		if (n < 0) {
			continue;
		}
		dispatch_query(server, query, (size_t)n, (struct sockaddr *)&client,
			client_len);
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
	if (server != NULL) {
		server->stop_requested = true;
		server->observer = NULL;
		server->observer_arg = NULL;
	}
	pthread_mutex_unlock(&g_server_lock);

	if (server == NULL) {
		return;
	}

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

void
unbound_afl_symcc_mutator_server_set_responses(
	const uint8_t *const *responses, const size_t *response_lens,
	size_t response_count)
{
	size_t i;

	pthread_mutex_lock(&g_server_lock);
	if (g_server != NULL) {
		if (responses == NULL || response_lens == NULL || response_count == 0) {
			g_server->memory_response_count = 0;
		} else {
			if (response_count > UNBOUND_AFL_SYMCC_MAX_MEMORY_RESPONSES) {
				response_count = UNBOUND_AFL_SYMCC_MAX_MEMORY_RESPONSES;
			}
			for (i = 0; i < response_count; i++) {
				g_server->memory_responses[i] = responses[i];
				g_server->memory_response_lens[i] = response_lens[i];
			}
			g_server->memory_response_count = response_count;
		}
	}
	pthread_mutex_unlock(&g_server_lock);
}

void
unbound_afl_symcc_mutator_server_clear_responses(void)
{
	pthread_mutex_lock(&g_server_lock);
	if (g_server != NULL) {
		g_server->memory_response_count = 0;
	}
	pthread_mutex_unlock(&g_server_lock);
}

void
unbound_afl_symcc_mutator_server_reset_response_sequence(void)
{
	pthread_mutex_lock(&g_server_lock);
	if (g_server != NULL) {
		g_server->tail_pick_count = 0;
	}
	pthread_mutex_unlock(&g_server_lock);
}

