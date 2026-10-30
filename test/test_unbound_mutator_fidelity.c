#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 直接测试生产 builder，避免复制一份响应构造逻辑。 */
#include "patch/cache/unbound/smallapp/unbound_afl_symcc_mutator_server.c"

/* Unbound 的 config.h 会定义 NDEBUG，回归断言必须重新启用。 */
#undef NDEBUG
#include <assert.h>

static const uint8_t query[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x01, 0x00, 0x01
};

static const uint8_t answer[] = {
    0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x01, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
    0x01, 0x02, 0x03, 0x04
};

static unsigned int checks;

static void check_packet(const char *name, const uint8_t *request,
                         size_t request_len, const uint8_t *packet,
                         size_t packet_len, size_t response_max, bool accepted) {
    /* 内存入口与文件 fallback 必须遵循同一份字节合同。 */
    for (int from_file = 0; from_file <= 1; from_file++) {
        unbound_afl_symcc_mutator_server_t server = {0};
        uint8_t response[65536];
        uint8_t original[65536];
        char path[PATH_MAX];
        assert(packet_len <= sizeof(original));
        assert(response_max <= sizeof(response));
        if (packet != NULL) {
            memcpy(original, packet, packet_len);
        }

        if (from_file) {
            if (packet == NULL) {
                continue;
            }
            const char *tmpdir = getenv("TMPDIR");
            int n = snprintf(path, sizeof(path), "%s/unbound-tail.XXXXXX",
                             tmpdir != NULL ? tmpdir : "/tmp");
            assert(n > 0 && (size_t)n < sizeof(path));
            int fd = mkstemp(path);
            assert(fd >= 0);
            FILE *fp = fdopen(fd, "wb");
            assert(fp != NULL);
            assert(fwrite(packet, 1, packet_len, fp) == packet_len);
            assert(fclose(fp) == 0);
            assert(setenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL", path, 1) == 0);
        } else {
            server.memory_response_count = 1;
            server.memory_responses[0] = packet;
            server.memory_response_lens[0] = packet_len;
        }

        memset(response, 0xa5, sizeof(response));
        int len = build_dns_response(&server, request, request_len,
                                     response, response_max);
        if (from_file) {
            assert(unlink(path) == 0);
            assert(unsetenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL") == 0);
        }
        fprintf(stderr, "CHECK: %s (%s)\n", name, from_file ? "file" : "memory");
        if (accepted) {
            if (len != (int)packet_len) {
                fprintf(stderr, "length: expected %zu, got %d\n", packet_len, len);
            }
            assert(len == (int)packet_len);
            assert(response[0] == request[0] && response[1] == request[1]);
            /* 白名单仅含事务 ID；flags、计数、Question 和尾部均逐字节比较。 */
            assert(memcmp(response + 2, original + 2, packet_len - 2) == 0);
        } else {
            assert(len == -1);
        }
        if (packet != NULL) {
            assert(memcmp(packet, original, packet_len) == 0);
        }
        checks++;
    }
}

static void check_fidelity(const char *name, const uint8_t *packet, size_t len) {
    check_packet(name, query, sizeof(query), packet, len, 65536, true);
}

static void test_sections_and_flags(void) {
    uint8_t packet[sizeof(answer) + 2];
    memcpy(packet, answer, sizeof(answer));
    packet[sizeof(answer)] = 0xde;
    packet[sizeof(answer) + 1] = 0xad;
    check_fidelity("trailing garbage", packet, sizeof(packet));
    check_fidelity("positive A", answer, sizeof(answer));

    for (size_t len = sizeof(query); len < sizeof(answer); len++) {
        check_fidelity("truncated answer RR", answer, len);
    }
    for (size_t section = 7; section <= 11; section += 2) {
        memcpy(packet, answer, sizeof(answer));
        packet[7] = 0;
        packet[section] = 2;
        check_fidelity("count exceeds available RRs", packet, sizeof(answer));
        check_fidelity("truncated section RR", packet, sizeof(answer) - 1);
    }
    memcpy(packet, answer, sizeof(answer));
    packet[7] = 0;
    check_fidelity("uncounted RR", packet, sizeof(answer));
    for (size_t i = 4; i < 12; i++) {
        packet[i] = 0xff;
    }
    check_fidelity("all counts inconsistent", packet, sizeof(answer));

    memcpy(packet, query, sizeof(query));
    for (int tc = 0; tc <= 1; tc++) {
        for (int ra = 0; ra <= 1; ra++) {
            packet[2] = (uint8_t)(0x80 | (tc << 1));
            packet[3] = (uint8_t)(ra << 7);
            check_fidelity("empty NOERROR TC/RA", packet, sizeof(query));
        }
    }
    packet[2] = 0x84;
    packet[3] = 0x83;
    check_fidelity("NXDOMAIN", packet, sizeof(query));
    packet[2] = 0x7d;
    packet[3] = 0x70;
    check_fidelity("QR opcode AA RD Z AD CD unchanged", packet, sizeof(query));

    check_fidelity("truncated question", answer, sizeof(query) - 1);
    check_fidelity("header only with nonzero counts", answer, 12);
}

static void test_question_identity(void) {
    /* CNAME 指向原 Question 的 example 后缀；换成长名字后原偏移会失效。 */
    const uint8_t packet[] = {
        0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x01, 'a', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x02,
        0xc0, 0x0e
    };
    uint8_t request[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 'l', 'o', 'n', 'g', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    check_packet("different question length", request, sizeof(request),
                 packet, sizeof(packet), 65536, true);
    memcpy(request + 12, packet + 12, 15);
    request[13] = 'b';
    check_packet("different QNAME", request, 27, packet, sizeof(packet), 65536, true);
    request[13] = 'A';
    check_packet("different QNAME case", request, 27, packet, sizeof(packet), 65536, true);
    request[13] = 'a';
    request[24] = 28;
    check_packet("different QTYPE", request, 27, packet, sizeof(packet), 65536, true);
    request[24] = 1;
    request[26] = 3;
    check_packet("different QCLASS", request, 27, packet, sizeof(packet), 65536, true);
}

static void test_controlled_failures(void) {
    check_packet("insufficient output capacity", query, sizeof(query),
                 answer, sizeof(answer), sizeof(answer) - 1, false);
    check_packet("zero output capacity", query, sizeof(query),
                 answer, sizeof(answer), 0, false);
    check_packet("short query header", query, 11,
                 answer, sizeof(answer), 65536, false);
    for (size_t len = 0; len < 12; len++) {
        check_packet("short response header", query, sizeof(query),
                     answer, len, 65536, false);
    }
    check_packet("null memory response", query, sizeof(query), NULL, 12, 65536, false);

    /* loopback 使用 IPv4 UDP，不能把过大的输入静默读成合法长度的前缀。 */
    uint8_t large[65536] = {0};
    memcpy(large, answer, sizeof(answer));
    check_fidelity("maximum IPv4 UDP payload", large, 65507);
    check_packet("oversized UDP payload", query, sizeof(query),
                 large, 65508, 65536, false);
    check_packet("oversized file and memory input", query, sizeof(query),
                 large, sizeof(large), 65536, false);

    unbound_afl_symcc_mutator_server_t server = {0};
    uint8_t response[512];
    assert(build_dns_response(&server, query, sizeof(query),
                              response, sizeof(response)) == -1);
    assert(setenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL", "/dev/null/missing", 1) == 0);
    assert(build_dns_response(&server, query, sizeof(query),
                              response, sizeof(response)) == -1);
    assert(unsetenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL") == 0);
    checks += 2;
}

int main(void) {
    assert(unsetenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL") == 0);
    assert(unsetenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR") == 0);
    test_sections_and_flags();
    test_question_identity();
    test_controlled_failures();
    printf("PASS: Unbound response fidelity (%u checks)\n", checks);
    return 0;
}
