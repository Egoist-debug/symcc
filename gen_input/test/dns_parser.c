/*
 * dns_parser.c - Simple DNS packet validator for gen_input testing
 *
 * Reads a DNS packet from stdin and validates its structure.
 * Returns 0 if valid DNS query packet, 1 otherwise.
 *
 * Compile with SymCC: symcc dns_parser.c -o dns_parser_sym
 * Test with gen_input: ./gen_input --format dns -v ./dns_parser_sym
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DNS_HEADER_SIZE 12
#define MAX_PACKET_SIZE 512
#define MAX_LABEL_LEN 63
#define MAX_NAME_LEN 255

struct dns_header {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

static uint16_t read_u16_be(const uint8_t *p) {
  return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static int parse_dns_name(const uint8_t *packet, size_t packet_len,
                          size_t offset, size_t *name_len) {
  size_t pos = offset;
  size_t total_len = 0;
  int label_count = 0;

  while (pos < packet_len) {
    uint8_t len = packet[pos];

    if (len == 0) {
      pos++;
      *name_len = pos - offset;
      return (label_count > 0) ? 0 : -1;
    }

    if ((len & 0xC0) == 0xC0) {
      if (pos + 1 >= packet_len)
        return -1;
      pos += 2;
      *name_len = pos - offset;
      return 0;
    }

    if (len > MAX_LABEL_LEN)
      return -1;
    if (pos + 1 + len > packet_len)
      return -1;

    total_len += len + 1;
    if (total_len > MAX_NAME_LEN)
      return -1;

    pos += 1 + len;
    label_count++;
  }

  return -1;
}

static int validate_dns_query(const uint8_t *packet, size_t len) {
  if (len < DNS_HEADER_SIZE)
    return -1;

  struct dns_header hdr;
  hdr.id = read_u16_be(packet);
  hdr.flags = read_u16_be(packet + 2);
  hdr.qdcount = read_u16_be(packet + 4);
  hdr.ancount = read_u16_be(packet + 6);
  hdr.nscount = read_u16_be(packet + 8);
  hdr.arcount = read_u16_be(packet + 10);

  int qr = (hdr.flags >> 15) & 1;
  if (qr != 0)
    return -1;

  if (hdr.qdcount == 0 || hdr.qdcount > 16)
    return -1;

  size_t offset = DNS_HEADER_SIZE;

  for (uint16_t i = 0; i < hdr.qdcount; i++) {
    size_t name_len;
    if (parse_dns_name(packet, len, offset, &name_len) != 0)
      return -1;
    offset += name_len;

    if (offset + 4 > len)
      return -1;

    uint16_t qtype = read_u16_be(packet + offset);
    uint16_t qclass = read_u16_be(packet + offset + 2);
    offset += 4;

    if (qtype == 0 || qtype > 255)
      return -1;

    if (qclass != 1 && qclass != 3 && qclass != 4 && qclass != 255)
      return -1;
  }

  return 0;
}

int main(void) {
  uint8_t buffer[MAX_PACKET_SIZE];

  ssize_t bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer));
  if (bytes_read <= 0)
    return 1;

  if (validate_dns_query(buffer, (size_t)bytes_read) == 0)
    return 0;

  return 1;
}
