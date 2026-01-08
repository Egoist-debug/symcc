#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DNS_HEADER_SIZE 12
#define MAX_PACKET_SIZE 65535
#define MAX_NAME_LENGTH 255

typedef struct {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} dns_header_t;

static int parse_dns_name(const uint8_t *packet, size_t packet_len,
                          size_t offset, size_t *name_len) {
  size_t pos = offset;
  size_t total_len = 0;
  int pointer_followed = 0;

  while (pos < packet_len) {
    uint8_t label_len = packet[pos];

    if (label_len == 0) {
      if (!pointer_followed) {
        total_len++;
      }
      *name_len = pointer_followed ? total_len : (pos - offset + 1);
      return 0;
    }

    if ((label_len & 0xC0) == 0xC0) {
      if (pos + 1 >= packet_len) {
        return -1;
      }
      uint16_t pointer = ((label_len & 0x3F) << 8) | packet[pos + 1];
      if (pointer >= offset) {
        return -1;
      }
      if (!pointer_followed) {
        total_len = pos - offset + 2;
        pointer_followed = 1;
      }
      pos = pointer;
      continue;
    }

    if (label_len > 63) {
      return -1;
    }

    pos += 1 + label_len;
    if (pos > packet_len) {
      return -1;
    }
  }

  return -1;
}

static int parse_resource_record(const uint8_t *packet, size_t packet_len,
                                 size_t offset, size_t *rr_len) {
  size_t name_len;
  if (parse_dns_name(packet, packet_len, offset, &name_len) != 0) {
    return -1;
  }

  size_t pos = offset + name_len;
  if (pos + 10 > packet_len) {
    return -1;
  }

  uint16_t rdlength = (packet[pos + 8] << 8) | packet[pos + 9];
  pos += 10;

  if (pos + rdlength > packet_len) {
    return -1;
  }

  *rr_len = (pos + rdlength) - offset;
  return 0;
}

int main(void) {
  uint8_t packet[MAX_PACKET_SIZE];
  ssize_t len = read(STDIN_FILENO, packet, sizeof(packet));

  if (len < DNS_HEADER_SIZE) {
    return 1;
  }

  dns_header_t header;
  header.id = (packet[0] << 8) | packet[1];
  header.flags = (packet[2] << 8) | packet[3];
  header.qdcount = (packet[4] << 8) | packet[5];
  header.ancount = (packet[6] << 8) | packet[7];
  header.nscount = (packet[8] << 8) | packet[9];
  header.arcount = (packet[10] << 8) | packet[11];

  uint16_t qr = (header.flags >> 15) & 0x1;
  if (qr != 1) {
    return 1;
  }

  uint16_t rcode = header.flags & 0x0F;
  if (rcode > 5 && rcode != 9 && rcode != 10) {
    return 1;
  }

  size_t offset = DNS_HEADER_SIZE;

  for (uint16_t i = 0; i < header.qdcount; i++) {
    size_t name_len;
    if (parse_dns_name(packet, len, offset, &name_len) != 0) {
      return 1;
    }
    offset += name_len;

    if (offset + 4 > (size_t)len) {
      return 1;
    }

    uint16_t qtype = (packet[offset] << 8) | packet[offset + 1];
    uint16_t qclass = (packet[offset + 2] << 8) | packet[offset + 3];

    if (qtype == 0 || qtype > 65535) {
      return 1;
    }
    if ((qclass & 0x7FFF) == 0) {
      return 1;
    }

    offset += 4;
  }

  for (uint16_t i = 0; i < header.ancount; i++) {
    size_t rr_len;
    if (parse_resource_record(packet, len, offset, &rr_len) != 0) {
      return 1;
    }
    offset += rr_len;
  }

  for (uint16_t i = 0; i < header.nscount; i++) {
    size_t rr_len;
    if (parse_resource_record(packet, len, offset, &rr_len) != 0) {
      return 1;
    }
    offset += rr_len;
  }

  for (uint16_t i = 0; i < header.arcount; i++) {
    size_t rr_len;
    if (parse_resource_record(packet, len, offset, &rr_len) != 0) {
      return 1;
    }
    offset += rr_len;
  }

  return 0;
}
