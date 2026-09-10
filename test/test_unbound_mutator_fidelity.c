#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Direct include to test static helper in translation unit
#include "patch/cache/unbound/smallapp/unbound_afl_symcc_mutator_server.c"

int main() {
    unbound_afl_symcc_mutator_server_t server;
    memset(&server, 0, sizeof(server));

    // A valid DNS query: header (12 bytes) + question for "example.com" A IN
    // ID=0x1234, Flags=0x0100 (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    uint8_t query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };

    // Fake a tail response packet:
    // Empty NOERROR with TC=1 (truncated), RA=0
    // Flags hi: 0x82 (QR=1, TC=1)
    // Flags lo: 0x00 (RCODE=0, RA=0)
    uint8_t tail[] = {
        0x00, 0x00, 0x82, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };

    // Save tail packet to temporary file and set server tail path via env var
    char tail_path[] = "/tmp/unbound_mutator_tail_test_XXXXXX";
    int fd = mkstemp(tail_path);
    assert(fd >= 0);
    ssize_t written = write(fd, tail, sizeof(tail));
    (void)written;
    close(fd);

    setenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL", tail_path, 1);

    uint8_t response[UNBOUND_AFL_SYMCC_MAX_PACKET];
    int resp_len = build_dns_response(&server, query, sizeof(query), response, sizeof(response));

    unlink(tail_path);
    unsetenv("UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL");

    assert(resp_len > 0);
    // Verify Header Flags:
    // response[2] must preserve TC: (tail_flags_hi & 0x06) -> bit 1 (0x02) must be 1!
    uint8_t tc = (response[2] & 0x02) != 0;
    assert(tc == 1);

    // response[3] must preserve RCODE: must be 0 (NOERROR), NOT 3 (NXDOMAIN)!
    uint8_t rcode = response[3] & 0x0F;
    assert(rcode == 0);

    // RA flag: should NOT be forced to 1 if tail was 0
    uint8_t ra = (response[3] & 0x80) != 0;
    assert(ra == 0);

    printf("PASS: Unbound mutator preserves TC=1, RCODE=0 (no forced NXDOMAIN), RA=0\n");
    return 0;
}
