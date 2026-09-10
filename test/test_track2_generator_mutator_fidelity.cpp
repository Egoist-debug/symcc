#include "DST1Mutator.h"
#include "DST1Transcript.h"
#include "FormatAwareGenerator.h"

#include <arpa/nameser.h>
#include <resolv.h>

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using namespace geninput;

namespace {

[[noreturn]] void fail(const std::string &msg) {
  std::cerr << "[track2-test] FAIL: " << msg << std::endl;
  std::exit(1);
}

void require(bool condition, const std::string &msg) {
  if (!condition) {
    fail(msg);
  }
}

// Helper to build a DNS packet with manual CNAME compression pointer
std::vector<uint8_t> buildCnameResponseWithPointer(const std::string &qname,
                                                   uint16_t targetOffset) {
  // Header: ID=0x1234, Flags=0x8180 (Response, RD, RA), QD=1, AN=1, NS=0, AR=0
  std::vector<uint8_t> pkt = {
      0x12, 0x34, // ID
      0x81, 0x80, // Flags
      0x00, 0x01, // QDCOUNT = 1
      0x00, 0x01, // ANCOUNT = 1
      0x00, 0x00, // NSCOUNT = 0
      0x00, 0x00  // ARCOUNT = 0
  };

  // Question section starting at offset 12
  auto encName = DNSNameCodec::encode(qname);
  pkt.insert(pkt.end(), encName.begin(), encName.end());
  pkt.push_back(0x00);
  pkt.push_back(0x05); // QTYPE = CNAME
  pkt.push_back(0x00);
  pkt.push_back(0x01); // QCLASS = IN

  // Answer RR: CNAME pointing to offset 12 for owner, targetOffset in RDATA
  pkt.push_back(0xC0);
  pkt.push_back(0x0C); // Owner -> offset 12 (qname)
  pkt.push_back(0x00);
  pkt.push_back(0x05); // TYPE = CNAME
  pkt.push_back(0x00);
  pkt.push_back(0x01); // CLASS = IN
  pkt.push_back(0x00);
  pkt.push_back(0x00);
  pkt.push_back(0x01);
  pkt.push_back(0x2C); // TTL = 300
  pkt.push_back(0x00);
  pkt.push_back(0x02); // RDLENGTH = 2
  pkt.push_back(static_cast<uint8_t>(0xC0 | ((targetOffset >> 8) & 0x3F)));
  pkt.push_back(static_cast<uint8_t>(targetOffset & 0xFF));

  return pkt;
}

void testF5QnameRelocation() {
  std::cout << "[track2-test] Running F5 QNAME compression relocation test..."
            << std::endl;

  // Question: a.example (offset 12).
  // "a" is length 1 (bytes: 0x01, 'a'), so "example" begins at offset 14 (0x0E).
  const std::string oldQname = "a.example";
  const uint16_t oldTargetOffset = 14; // points to "example"
  const auto oldResp = buildCnameResponseWithPointer(oldQname, oldTargetOffset);

  // Verify old response parses with ns_initparse and uncompresses to "example"
  ns_msg handle;
  require(ns_initparse(oldResp.data(), oldResp.size(), &handle) == 0,
          "old response ns_initparse failed");
  require(ns_msg_count(handle, ns_s_an) == 1, "old response ANCOUNT != 1");
  ns_rr rr;
  require(ns_parserr(&handle, ns_s_an, 0, &rr) == 0, "old response parserr failed");
  char uncompressed[MAXDNAME];
  int decLen = ns_name_uncompress(oldResp.data(), oldResp.data() + oldResp.size(),
                                  ns_rr_rdata(rr), uncompressed, sizeof(uncompressed));
  require(decLen > 0, "old response CNAME uncompress failed");
  require(std::string(uncompressed) == "example",
          "old response uncompressed target != example");

  // New query: long.example (offset 12).
  // "long" has length 4 (bytes: 0x04, 'l', 'o', 'n', 'g'), so "example" begins at offset 17 (0x11).
  const auto newQuery = DNSPacketBuilder::buildQuery("long.example", 5);
  auto normalized = DST1Mutator::normalizeResponseForQuery(oldResp, newQuery);
  require(normalized.has_value(), "DST1Mutator::normalizeResponseForQuery returned nullopt");

  // Verify normalized response parses with ns_initparse
  require(ns_initparse(normalized->data(), normalized->size(), &handle) == 0,
          "normalized response ns_initparse failed");
  require(ns_msg_count(handle, ns_s_an) == 1, "normalized response ANCOUNT != 1");
  require(ns_parserr(&handle, ns_s_an, 0, &rr) == 0, "normalized parserr failed");

  // Verify that CNAME RDATA in normalized packet correctly uncompresses to "example"
  decLen = ns_name_uncompress(normalized->data(),
                              normalized->data() + normalized->size(),
                              ns_rr_rdata(rr), uncompressed, sizeof(uncompressed));
  require(decLen > 0, "normalized CNAME uncompress failed (F5 defect!)");
  require(std::string(uncompressed) == "example",
          "normalized CNAME uncompressed target != example");

  // Verify DST1Mutator validation
  DST1Mutator::Transcript t;
  t.ClientQuery = newQuery;
  t.Responses = {*normalized};
  t.PostCheckQuery = newQuery;
  require(DST1Mutator::validatePoisonEligible(t).ok(),
          "normalized transcript not poison eligible");

  // Negative control: create packet with invalid compression pointer in CNAME RDATA
  auto corruptResp = *normalized;
  corruptResp[corruptResp.size() - 1] = 0xFE; // Point to invalid location
  t.Responses = {corruptResp};
  auto valResult = DST1Mutator::validatePoisonEligible(t);
  require(valResult.Error == DST1Mutator::ValidationError::InvalidCompressionPointer,
          "corrupted compression pointer was not caught by validatePoisonEligible");

  std::cout << "[track2-test] PASS F5 QNAME compression relocation" << std::endl;
}

void testF7DonorTransplant() {
  std::cout << "[track2-test] Running F7 Donor RR transplant fidelity test..."
            << std::endl;

  // Build donor packet with compressed Authority RR (owner is 0xC0 0x0C pointing to Question)
  std::vector<uint8_t> donorResp = {
      0x12, 0x34, 0x81, 0x80,
      0x00, 0x01, // QD = 1
      0x00, 0x01, // AN = 1
      0x00, 0x01, // NS = 1
      0x00, 0x00  // AR = 0
  };
  // Question: cache.example.test A IN
  auto qNameEnc = DNSNameCodec::encode("cache.example.test");
  donorResp.insert(donorResp.end(), qNameEnc.begin(), qNameEnc.end());
  donorResp.push_back(0x00);
  donorResp.push_back(0x01);
  donorResp.push_back(0x00);
  donorResp.push_back(0x01);

  // Answer: cache.example.test A 300 127.0.0.1 (owner: 0xC0 0x0C)
  donorResp.push_back(0xC0);
  donorResp.push_back(0x0C);
  donorResp.push_back(0x00);
  donorResp.push_back(0x01); // A
  donorResp.push_back(0x00);
  donorResp.push_back(0x01); // IN
  donorResp.push_back(0x00);
  donorResp.push_back(0x00);
  donorResp.push_back(0x01);
  donorResp.push_back(0x2C); // TTL=300
  donorResp.push_back(0x00);
  donorResp.push_back(0x04); // RdLen=4
  donorResp.push_back(127);
  donorResp.push_back(0);
  donorResp.push_back(0);
  donorResp.push_back(1);

  // Authority: NS record with owner 0xC0 0x0C (compressed!)
  donorResp.push_back(0xC0);
  donorResp.push_back(0x0C);
  donorResp.push_back(0x00);
  donorResp.push_back(0x02); // NS
  donorResp.push_back(0x00);
  donorResp.push_back(0x01); // IN
  donorResp.push_back(0x00);
  donorResp.push_back(0x00);
  donorResp.push_back(0x02);
  donorResp.push_back(0x58); // TTL=600
  auto nsTarget = DNSNameCodec::encode("ns1.example.test");
  donorResp.push_back(static_cast<uint8_t>((nsTarget.size() >> 8) & 0xFF));
  donorResp.push_back(static_cast<uint8_t>(nsTarget.size() & 0xFF));
  donorResp.insert(donorResp.end(), nsTarget.begin(), nsTarget.end());

  const auto donorQuery = DNSPacketBuilder::buildQuery("cache.example.test", 1);
  auto donorTranscript = dst1::buildTranscript(donorQuery, {donorResp}, donorQuery);
  require(!donorTranscript.empty(), "donor transcript build failed");
  require(DST1Mutator::validatePoisonEligible(donorTranscript).ok(),
          "donor transcript validation failed");

  // Target: query cache.example.test, response without authority
  auto targetResp = DNSPacketBuilder()
                        .setID(0x5678)
                        .asResponse()
                        .setRecursionDesired(true)
                        .setRecursionAvailable(true)
                        .addQuestion("cache.example.test", 1, 1)
                        .addAnswer("cache.example.test", 1, 1, 300, {10, 0, 0, 1})
                        .build();
  auto targetTranscript = dst1::buildTranscript(donorQuery, {targetResp}, donorQuery);
  require(!targetTranscript.empty(), "target transcript build failed");

  // Transplant authority from donor
  DST1Mutator::MutationRequest request;
  request.DonorFamily = DST1Mutator::DonorMutationFamily::AuthorityTransplant;
  request.ResponseIndex = 0;

  auto mutated = DST1Mutator::mutate(targetTranscript, request, donorTranscript);
  require(mutated.has_value(), "AuthorityTransplant mutate returned nullopt");
  require(*mutated != targetTranscript,
          "AuthorityTransplant returned unchanged target (F7 silent fallback!)");

  auto parsed = DST1Mutator::parse(*mutated);
  require(parsed.has_value(), "mutated transcript parse failed");
  require(DST1Mutator::validatePoisonEligible(*parsed).ok(),
          "mutated transcript not poison eligible");

  // Verify that authority RR is present and parseable
  ns_msg handle;
  require(ns_initparse(parsed->Responses[0].data(), parsed->Responses[0].size(),
                       &handle) == 0,
          "mutated response ns_initparse failed");
  require(ns_msg_count(handle, ns_s_ns) == 1,
          "mutated response NS count != 1");

  std::cout << "[track2-test] PASS F7 Donor RR transplant fidelity" << std::endl;
}

void testF8HybridGenerator() {
  std::cout << "[track2-test] Running F8 HybridDNSGenerator wire fidelity test..."
            << std::endl;

  // Seed: valid response for cache.example.test
  auto seed = DNSPacketBuilder()
                  .setID(0x1234)
                  .asResponse()
                  .setRecursionDesired(true)
                  .setRecursionAvailable(true)
                  .addQuestion("cache.example.test", 1, 1)
                  .addAnswer("cache.example.test", 1, 1, 300, {127, 0, 0, 1})
                  .build();

  HybridDNSGenerator::Config cfg;
  cfg.PreserveHeaderBytes = 20; // Previous magic number that caused label chopping
  cfg.MaxIterations = 0;        // Isolate initial seed generation
  cfg.IsResponse = true;

  HybridDNSGenerator gen(cfg);
  gen.addSeed(seed);

  auto generated = gen.generate();
  require(!generated.empty(), "HybridDNSGenerator generated 0 packets");

  size_t invalidCount = 0;
  for (size_t i = 0; i < generated.size(); ++i) {
    const auto &pkt = generated[i];
    ns_msg handle;
    if (ns_initparse(pkt.data(), pkt.size(), &handle) != 0) {
      invalidCount++;
      continue;
    }
    if (ns_msg_count(handle, ns_s_qd) != 1) {
      invalidCount++;
      continue;
    }
    if (ns_msg_count(handle, ns_s_an) < 1) {
      invalidCount++;
      continue;
    }
    ns_rr rr;
    if (ns_parserr(&handle, ns_s_qd, 0, &rr) != 0) {
      invalidCount++;
      continue;
    }
    if (std::string(ns_rr_name(rr)) != "cache.example.test") {
      invalidCount++;
      continue;
    }
  }

  std::cout << "[track2-test] generated_packets=" << generated.size()
            << " invalid_dns_packets=" << invalidCount << std::endl;
  require(invalidCount == 0,
          "HybridDNSGenerator produced invalid DNS packets (F8 defect!)");

  std::cout << "[track2-test] PASS F8 HybridDNSGenerator wire fidelity"
            << std::endl;
}

} // namespace

int main() {
  testF5QnameRelocation();
  testF7DonorTransplant();
  testF8HybridGenerator();
  std::cout << "[track2-test] ALL TRACK 2 TESTS PASSED!" << std::endl;
  return 0;
}
