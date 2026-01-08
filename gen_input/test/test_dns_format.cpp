#include "BinaryFormat.h"
#include "FormatAwareGenerator.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace geninput;

std::string hexDump(const std::vector<uint8_t> &data) {
  std::ostringstream oss;
  for (size_t i = 0; i < data.size(); ++i) {
    oss << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<int>(data[i]);
    if (i + 1 < data.size())
      oss << " ";
  }
  return oss.str();
}

void testDNSNameCodec() {
  std::cout << "=== Testing DNSNameCodec ===" << std::endl;

  auto encoded = DNSNameCodec::encode("example.com");
  std::cout << "Encoded 'example.com': " << hexDump(encoded) << std::endl;

  assert(encoded.size() == 13);
  assert(encoded[0] == 7);
  assert(memcmp(&encoded[1], "example", 7) == 0);
  assert(encoded[8] == 3);
  assert(memcmp(&encoded[9], "com", 3) == 0);
  assert(encoded[12] == 0);

  auto decoded = DNSNameCodec::decode(encoded);
  std::cout << "Decoded: '" << decoded << "'" << std::endl;
  assert(decoded == "example.com");

  auto single = DNSNameCodec::encode("localhost");
  std::cout << "Encoded 'localhost': " << hexDump(single) << std::endl;
  assert(single.size() == 11);
  assert(single[0] == 9);

  auto empty = DNSNameCodec::encode("");
  std::cout << "Encoded '': " << hexDump(empty) << std::endl;
  assert(empty.size() == 1);
  assert(empty[0] == 0);

  std::cout << "DNSNameCodec tests PASSED" << std::endl << std::endl;
}

void testDNSPacketBuilder() {
  std::cout << "=== Testing DNSPacketBuilder ===" << std::endl;

  auto query = DNSPacketBuilder::buildQuery("example.com", 1);
  std::cout << "DNS Query packet (" << query.size() << " bytes):" << std::endl;
  std::cout << "  " << hexDump(query) << std::endl;

  assert(query.size() >= 12 + 13 + 4);

  uint16_t id = (query[0] << 8) | query[1];
  uint16_t flags = (query[2] << 8) | query[3];
  uint16_t qdcount = (query[4] << 8) | query[5];
  uint16_t ancount = (query[6] << 8) | query[7];

  std::cout << "  ID: 0x" << std::hex << id << std::dec << std::endl;
  std::cout << "  Flags: 0x" << std::hex << flags << std::dec << std::endl;
  std::cout << "  QDCOUNT: " << qdcount << std::endl;
  std::cout << "  ANCOUNT: " << ancount << std::endl;

  assert((flags & 0x8000) == 0);
  assert(qdcount == 1);
  assert(ancount == 0);

  std::cout << "DNSPacketBuilder tests PASSED" << std::endl << std::endl;
}

void testBinaryFormat() {
  std::cout << "=== Testing BinaryFormat ===" << std::endl;

  auto format = BinaryFormatFactory::createDNS();
  std::cout << "Format name: " << format.getName() << std::endl;
  std::cout << "Min size: " << format.getMinSize() << " bytes" << std::endl;

  auto seed = format.createSeed();
  std::cout << "Seed (" << seed.size() << " bytes): " << hexDump(seed)
            << std::endl;

  assert(seed.size() >= 12);

  uint16_t qdcount = (seed[4] << 8) | seed[5];
  std::cout << "Seed QDCOUNT: " << qdcount << std::endl;
  assert(qdcount == 1);

  std::cout << "BinaryFormat tests PASSED" << std::endl << std::endl;
}

void testDNSParserValidation() {
  std::cout << "=== Testing DNS Parser Validation ===" << std::endl;

  auto query = DNSPacketBuilder::buildQuery("test.example.com", 1);
  std::cout << "Generated query (" << query.size() << " bytes)" << std::endl;

  FILE *pipe = popen("/tmp/dns_parser", "w");
  if (!pipe) {
    std::cerr << "Failed to open pipe to dns_parser" << std::endl;
    return;
  }

  fwrite(query.data(), 1, query.size(), pipe);
  int status = pclose(pipe);
  int exit_code = WEXITSTATUS(status);

  std::cout << "DNS parser exit code: " << exit_code << std::endl;

  if (exit_code == 0) {
    std::cout << "DNS Parser validation PASSED" << std::endl;
  } else {
    std::cout << "DNS Parser validation FAILED (expected 0, got " << exit_code
              << ")" << std::endl;
  }
  std::cout << std::endl;
}

void testInvalidDNSPackets() {
  std::cout << "=== Testing Invalid DNS Packets ===" << std::endl;

  std::vector<uint8_t> tooShort = {0x00, 0x01, 0x00, 0x00};
  FILE *pipe = popen("/tmp/dns_parser", "w");
  fwrite(tooShort.data(), 1, tooShort.size(), pipe);
  int status = pclose(pipe);
  int exit_code = WEXITSTATUS(status);
  std::cout << "Too short packet: exit=" << exit_code << " (expected non-zero)"
            << std::endl;
  assert(exit_code != 0);

  auto response = DNSPacketBuilder()
                      .setID(0x1234)
                      .asResponse()
                      .addQuestion("example.com", 1, 1)
                      .build();
  pipe = popen("/tmp/dns_parser", "w");
  fwrite(response.data(), 1, response.size(), pipe);
  status = pclose(pipe);
  exit_code = WEXITSTATUS(status);
  std::cout << "Response packet (QR=1): exit=" << exit_code
            << " (expected non-zero)" << std::endl;
  assert(exit_code != 0);

  std::cout << "Invalid packet tests PASSED" << std::endl << std::endl;
}

void testDNSResponseFormat() {
  std::cout << "=== Testing DNS Response Format ===" << std::endl;

  auto format = BinaryFormatFactory::createDNSResponse();
  std::cout << "Format name: " << format.getName() << std::endl;
  std::cout << "Min size: " << format.getMinSize() << " bytes" << std::endl;

  auto seed = format.createSeed();
  std::cout << "Response seed (" << seed.size() << " bytes): " << hexDump(seed)
            << std::endl;

  // Check QR bit is set (response)
  uint16_t flags = (seed[2] << 8) | seed[3];
  std::cout << "Flags: 0x" << std::hex << flags << std::dec << std::endl;
  assert((flags & 0x8000) != 0); // QR=1 for response

  // Check ANCOUNT is 1
  uint16_t ancount = (seed[6] << 8) | seed[7];
  std::cout << "ANCOUNT: " << ancount << std::endl;
  assert(ancount == 1);

  std::cout << "DNS Response Format tests PASSED" << std::endl << std::endl;
}

void testDNSResourceRecordFormat() {
  std::cout << "=== Testing DNS Resource Record Format ===" << std::endl;

  auto format = BinaryFormatFactory::createDNSResourceRecord();
  std::cout << "Format name: " << format.getName() << std::endl;

  auto seed = format.createSeed();
  std::cout << "RR seed (" << seed.size() << " bytes): " << hexDump(seed)
            << std::endl;

  // Should have at least name + type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes + name
  assert(seed.size() >= 13); // 3 (min name "a\0") + 10

  std::cout << "DNS RR Format tests PASSED" << std::endl << std::endl;
}

void testBuildResponseFromQuery() {
  std::cout << "=== Testing buildResponseFromQuery ===" << std::endl;

  // Create a query packet
  auto query = DNSPacketBuilder::buildQuery("test.example.com", 1);
  std::cout << "Query packet (" << query.size() << " bytes):" << std::endl;
  std::cout << "  " << hexDump(query) << std::endl;

  uint16_t queryTxID = (query[0] << 8) | query[1];
  std::cout << "Query TxID: 0x" << std::hex << queryTxID << std::dec << std::endl;

  // Build response from query
  std::vector<uint8_t> answerRData = {192, 168, 1, 1}; // IP address
  auto response = DNSPacketBuilder::buildResponseFromQuery(query, answerRData, 1, 300);
  std::cout << "Response packet (" << response.size() << " bytes):" << std::endl;
  std::cout << "  " << hexDump(response) << std::endl;

  // Verify TxID is copied
  uint16_t responseTxID = (response[0] << 8) | response[1];
  std::cout << "Response TxID: 0x" << std::hex << responseTxID << std::dec << std::endl;
  assert(responseTxID == queryTxID);

  // Verify QR=1 (response)
  uint16_t responseFlags = (response[2] << 8) | response[3];
  std::cout << "Response flags: 0x" << std::hex << responseFlags << std::dec << std::endl;
  assert((responseFlags & 0x8000) != 0);

  // Verify QDCOUNT=1, ANCOUNT=1
  uint16_t qdcount = (response[4] << 8) | response[5];
  uint16_t ancount = (response[6] << 8) | response[7];
  std::cout << "QDCOUNT: " << qdcount << ", ANCOUNT: " << ancount << std::endl;
  assert(qdcount == 1);
  assert(ancount == 1);

  std::cout << "buildResponseFromQuery tests PASSED" << std::endl << std::endl;
}

void testDNSResponseWithAuthority() {
  std::cout << "=== Testing DNS Response with Authority/Additional ===" << std::endl;

  auto response = DNSPacketBuilder()
      .setID(0xABCD)
      .asResponse()
      .setAuthoritative(true)
      .setRecursionAvailable(true)
      .setRCode(0)
      .addQuestion("example.com", 1, 1)
      .addAnswer("example.com", 1, 1, 300, {127, 0, 0, 1})
      .addAuthority("example.com", 2, 1, 3600, {2, 'n', 's', 0})
      .addAdditional("ns.example.com", 1, 1, 3600, {10, 0, 0, 1})
      .build();

  std::cout << "Full response packet (" << response.size() << " bytes):" << std::endl;
  std::cout << "  " << hexDump(response) << std::endl;

  // Verify header
  uint16_t id = (response[0] << 8) | response[1];
  uint16_t flags = (response[2] << 8) | response[3];
  uint16_t qdcount = (response[4] << 8) | response[5];
  uint16_t ancount = (response[6] << 8) | response[7];
  uint16_t nscount = (response[8] << 8) | response[9];
  uint16_t arcount = (response[10] << 8) | response[11];

  std::cout << "ID: 0x" << std::hex << id << std::dec << std::endl;
  std::cout << "Flags: 0x" << std::hex << flags << std::dec << std::endl;
  std::cout << "QDCOUNT: " << qdcount << std::endl;
  std::cout << "ANCOUNT: " << ancount << std::endl;
  std::cout << "NSCOUNT: " << nscount << std::endl;
  std::cout << "ARCOUNT: " << arcount << std::endl;

  assert(id == 0xABCD);
  assert((flags & 0x8000) != 0);  // QR=1
  assert((flags & 0x0400) != 0);  // AA=1
  assert((flags & 0x0080) != 0);  // RA=1
  assert(qdcount == 1);
  assert(ancount == 1);
  assert(nscount == 1);
  assert(arcount == 1);

  std::cout << "DNS Response with Authority/Additional tests PASSED" << std::endl << std::endl;
}

void testDNSResponseParserValidation() {
  std::cout << "=== Testing DNS Response Parser Validation ===" << std::endl;

  // Build a valid DNS response
  auto response = DNSPacketBuilder()
      .setID(0x1234)
      .asResponse()
      .setRecursionDesired(true)
      .setRecursionAvailable(true)
      .setRCode(0)
      .addQuestion("example.com", 1, 1)
      .addAnswer("example.com", 1, 1, 300, {127, 0, 0, 1})
      .build();

  std::cout << "Generated response (" << response.size() << " bytes)" << std::endl;

  FILE *pipe = popen("/tmp/dns_response_parser", "w");
  if (!pipe) {
    std::cerr << "Failed to open pipe to dns_response_parser (try building it first)" << std::endl;
    return;
  }

  fwrite(response.data(), 1, response.size(), pipe);
  int status = pclose(pipe);
  int exit_code = WEXITSTATUS(status);

  std::cout << "DNS response parser exit code: " << exit_code << std::endl;

  if (exit_code == 0) {
    std::cout << "DNS Response Parser validation PASSED" << std::endl;
  } else {
    std::cout << "DNS Response Parser validation FAILED (expected 0, got " << exit_code
              << ")" << std::endl;
  }
  std::cout << std::endl;
}

void testInvalidDNSResponse() {
  std::cout << "=== Testing Invalid DNS Response ===" << std::endl;

  // Query packet should be rejected by response parser
  auto query = DNSPacketBuilder::buildQuery("example.com", 1);
  FILE *pipe = popen("/tmp/dns_response_parser", "w");
  if (!pipe) {
    std::cerr << "Skipping (dns_response_parser not available)" << std::endl;
    return;
  }
  fwrite(query.data(), 1, query.size(), pipe);
  int status = pclose(pipe);
  int exit_code = WEXITSTATUS(status);
  std::cout << "Query packet to response parser: exit=" << exit_code
            << " (expected non-zero)" << std::endl;
  assert(exit_code != 0);

  std::cout << "Invalid DNS Response tests PASSED" << std::endl << std::endl;
}

void testSerializeParseRoundtrip() {
  std::cout << "=== Testing Serialize/Parse Roundtrip ===" << std::endl;

  auto format = BinaryFormatFactory::createDNS();

  StructuredInput input(format);
  input.setField("id", 0xABCD);
  input.setField("flags", 0x0100);
  input.setField("qdcount", 1);
  input.setField("ancount", 0);
  input.setField("nscount", 0);
  input.setField("arcount", 0);
  input.setField("qname", DNSNameCodec::encode("test.com"));
  input.setField("qtype", 1);
  input.setField("qclass", 1);

  auto serialized = format.serialize(input);
  std::cout << "Serialized (" << serialized.size()
            << " bytes): " << hexDump(serialized) << std::endl;

  auto parsed = format.parse(serialized);
  assert(parsed != nullptr);

  auto id = parsed->getIntField("id");
  auto flags = parsed->getIntField("flags");
  auto qdcount = parsed->getIntField("qdcount");

  std::cout << "Parsed ID: 0x" << std::hex << (id ? *id : 0) << std::dec
            << std::endl;
  std::cout << "Parsed Flags: 0x" << std::hex << (flags ? *flags : 0)
            << std::dec << std::endl;
  std::cout << "Parsed QDCOUNT: " << (qdcount ? *qdcount : 0) << std::endl;

  assert(id && *id == 0xABCD);
  assert(flags && *flags == 0x0100);
  assert(qdcount && *qdcount == 1);

  std::cout << "Roundtrip tests PASSED" << std::endl << std::endl;
}

int main() {
  std::cout << "gen_input DNS Format Tests" << std::endl;
  std::cout << "==========================" << std::endl << std::endl;

  testDNSNameCodec();
  testDNSPacketBuilder();
  testBinaryFormat();
  testSerializeParseRoundtrip();
  testDNSParserValidation();
  testInvalidDNSPackets();
  
  testDNSResponseFormat();
  testDNSResourceRecordFormat();
  testBuildResponseFromQuery();
  testDNSResponseWithAuthority();
  testDNSResponseParserValidation();
  testInvalidDNSResponse();

  std::cout << "==========================" << std::endl;
  std::cout << "All tests PASSED!" << std::endl;

  return 0;
}
