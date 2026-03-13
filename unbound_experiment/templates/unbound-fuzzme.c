/*
 * unbound-fuzzme.c - parse a packet provided on stdin (for fuzzing).
 *
 */
#include "config.h"
#include "util/regional.h"
#include "util/fptr_wlist.h"
#include "sldns/sbuffer.h"

#define SZ 10000

int main() {
	char buffer[SZ];
	size_t n_read = fread(buffer, 1, SZ, stdin);
	if (n_read == SZ) {
		printf("input too big\n");
		return 1;
	}
	sldns_buffer *pkt = sldns_buffer_new(n_read);
	sldns_buffer_init_frm_data(pkt, buffer, n_read);

	struct regional *region = regional_create();

	struct msg_parse* prs;
	struct edns_data edns;
	prs = (struct msg_parse*)malloc(sizeof(struct msg_parse));
	if (!prs) {
		printf("out of memory on incoming message\n");
		return 1;
	}
	memset(prs, 0, sizeof(*prs));
	memset(&edns, 0, sizeof(edns));
	sldns_buffer_set_position(pkt, 0);
	if (parse_packet(pkt, prs, region) != LDNS_RCODE_NOERROR) {
		printf("parse error\n");
		return 1;
	}
}
