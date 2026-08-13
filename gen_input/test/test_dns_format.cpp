#include "BinaryFormat.h"
#include "DST1Mutator.h"
#include "DST1Transcript.h"
#include "FormatAwareGenerator.h"

#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <spawn.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef DNS_PARSER_PATH
#error DNS_PARSER_PATH must be provided by the build system
#endif

#ifndef DNS_RESPONSE_PARSER_PATH
#error DNS_RESPONSE_PARSER_PATH must be provided by the build system
#endif

using namespace geninput;

#include "../src/DST1Mutator.cpp"

extern char **environ;

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

std::string createTempExecutableScript(unsigned SleepSec) {
  char pathTemplate[] = "/tmp/gen_input_timeout_runnerXXXXXX";
  int fd = mkstemp(pathTemplate);
  assert(fd >= 0);
  close(fd);

  std::ofstream script(pathTemplate);
  assert(script.is_open());
  script << "#!/bin/sh\n";
  script << "sleep " << SleepSec << "\n";
  script << "exit 1\n";
  script.close();

  if (chmod(pathTemplate, 0755) != 0) {
    assert(false);
  }
  return pathTemplate;
}

std::string createTempDirectory() {
  char pathTemplate[] = "/tmp/gen_input_timeout_outputXXXXXX";
  char *dirPath = mkdtemp(pathTemplate);
  assert(dirPath != nullptr);
  return dirPath;
}

int runParser(const char *parserPath, const std::vector<uint8_t> &input) {
  if (access(parserPath, X_OK) != 0) {
    std::cerr << "Parser is not executable: " << parserPath << std::endl;
    std::abort();
  }

  int inputPipe[2];
  if (pipe(inputPipe) != 0) {
    std::cerr << "Failed to create parser input pipe: " << std::strerror(errno)
              << std::endl;
    std::abort();
  }

  posix_spawn_file_actions_t actions;
  if (posix_spawn_file_actions_init(&actions) != 0 ||
      posix_spawn_file_actions_adddup2(&actions, inputPipe[0], STDIN_FILENO) !=
          0 ||
      posix_spawn_file_actions_addclose(&actions, inputPipe[0]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, inputPipe[1]) != 0) {
    close(inputPipe[0]);
    close(inputPipe[1]);
    std::cerr << "Failed to prepare parser process: " << parserPath << std::endl;
    std::abort();
  }

  pid_t pid = -1;
  char *const argv[] = {const_cast<char *>(parserPath), nullptr};
  const int spawnError =
      posix_spawn(&pid, parserPath, &actions, nullptr, argv, environ);
  posix_spawn_file_actions_destroy(&actions);
  close(inputPipe[0]);
  if (spawnError != 0) {
    close(inputPipe[1]);
    std::cerr << "Failed to execute parser: " << parserPath << ": "
              << std::strerror(spawnError) << std::endl;
    std::abort();
  }

  size_t written = 0;
  while (written < input.size()) {
    const ssize_t result =
        write(inputPipe[1], input.data() + written, input.size() - written);
    if (result > 0) {
      written += static_cast<size_t>(result);
    } else if (result < 0 && errno == EINTR) {
      continue;
    } else {
      close(inputPipe[1]);
      std::cerr << "Failed to write parser input: " << parserPath << std::endl;
      std::abort();
    }
  }
  if (close(inputPipe[1]) != 0) {
    std::cerr << "Failed to close parser input: " << parserPath << std::endl;
    std::abort();
  }

  int status = 0;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno == EINTR) {
      continue;
    }
    std::cerr << "Failed to wait for parser: " << parserPath << std::endl;
    std::abort();
  }
  if (!WIFEXITED(status)) {
    std::cerr << "Parser did not exit normally: " << parserPath << std::endl;
    std::abort();
  }
  return WEXITSTATUS(status);
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

  const int exit_code = runParser(DNS_PARSER_PATH, query);

  std::cout << "DNS parser exit code: " << exit_code << std::endl;

  assert(exit_code == 0);
  std::cout << "DNS Parser validation PASSED" << std::endl;
  std::cout << std::endl;
}

void testInvalidDNSPackets() {
  std::cout << "=== Testing Invalid DNS Packets ===" << std::endl;

  std::vector<uint8_t> tooShort = {0x00, 0x01, 0x00, 0x00};
  int exit_code = runParser(DNS_PARSER_PATH, tooShort);
  std::cout << "Too short packet: exit=" << exit_code << " (expected non-zero)"
            << std::endl;
  assert(exit_code != 0);

  auto response = DNSPacketBuilder()
                      .setID(0x1234)
                      .asResponse()
                      .addQuestion("example.com", 1, 1)
                      .build();
  exit_code = runParser(DNS_PARSER_PATH, response);
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

  assert(format.validate(seed));
  auto parsed = format.parse(seed);
  assert(parsed != nullptr);

  auto answer_rrs = parsed->getBytesField("answer_rrs");
  assert(answer_rrs.has_value());
  assert(answer_rrs->size() >= 14);

  const uint16_t rdlength =
      (static_cast<uint16_t>((*answer_rrs)[answer_rrs->size() - 6]) << 8) |
      static_cast<uint16_t>((*answer_rrs)[answer_rrs->size() - 5]);
  if (rdlength != 4 ||
      answer_rrs->size() < static_cast<std::size_t>(10 + rdlength)) {
    std::abort();
  }

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

  auto format = BinaryFormatFactory::createDNSResponse();
  assert(format.validate(response));
  auto parsed = format.parse(response);
  assert(parsed != nullptr);

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

  auto format = BinaryFormatFactory::createDNSResponse();
  assert(format.validate(response));
  auto parsed = format.parse(response);
  assert(parsed != nullptr);

  auto answer_rrs = parsed->getBytesField("answer_rrs");
  auto authority_rrs = parsed->getBytesField("authority_rrs");
  auto additional_rrs = parsed->getBytesField("additional_rrs");
  assert(answer_rrs.has_value() && !answer_rrs->empty());
  assert(authority_rrs.has_value() && !authority_rrs->empty());
  assert(additional_rrs.has_value() && !additional_rrs->empty());

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

  const int exit_code = runParser(DNS_RESPONSE_PARSER_PATH, response);

  std::cout << "DNS response parser exit code: " << exit_code << std::endl;

  assert(exit_code == 0);
  std::cout << "DNS Response Parser validation PASSED" << std::endl;
  std::cout << std::endl;
}

void testInvalidDNSResponse() {
  std::cout << "=== Testing Invalid DNS Response ===" << std::endl;

  // Query packet should be rejected by response parser
  auto query = DNSPacketBuilder::buildQuery("example.com", 1);
  const int exit_code = runParser(DNS_RESPONSE_PARSER_PATH, query);
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

void testFormatAwareGeneratorTimeoutStop() {
  std::cout << "=== Testing FormatAwareGenerator Timeout Stop ===" << std::endl;

  auto format = BinaryFormatFactory::createDNS();
  FormatGeneratorConfig config;
  config.MaxIterations = 10;
  config.TimeoutSec = 1;
  config.MaxRecursionDepth = 0;
  config.EnableFieldMutation = false;

  const std::string programPath = createTempExecutableScript(2);
  const std::string outputDir = createTempDirectory();

  RunConfig runConfig;
  runConfig.ProgramPath = programPath;
  runConfig.OutputDir = outputDir;
  runConfig.TimeoutSec = 1;
  runConfig.UseStdin = true;

  auto runner = std::make_shared<SymCCRunner>(runConfig);
  FormatAwareGenerator generator(format, config);
  generator.setRunner(runner);
  generator.addSeed(DNSPacketBuilder::buildQuery("a.example.com", 1));
  generator.addSeed(DNSPacketBuilder::buildQuery("b.example.com", 1));
  generator.addSeed(DNSPacketBuilder::buildQuery("c.example.com", 1));

  const auto start = std::chrono::steady_clock::now();
  auto result = generator.run();
  const auto elapsedMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - start)
          .count();
  const auto &stats = generator.getStats();

  std::cout << "Elapsed: " << elapsedMs << " ms" << std::endl;
  std::cout << "Iterations: " << stats.TotalIterations << std::endl;
  std::cout << "SymCC runs: " << stats.TotalSymCCRuns << std::endl;
  std::cout << "Valid inputs: " << result.ValidInputs.size() << std::endl;

  assert(stats.TotalIterations == 1);
  assert(stats.TotalSymCCRuns == 1);
  assert(stats.TotalTimeMs >= 1000.0);
  assert(elapsedMs < 2500);

  std::filesystem::remove(programPath);
  std::filesystem::remove_all(outputDir);

  std::cout << "FormatAwareGenerator timeout stop tests PASSED" << std::endl
            << std::endl;
}

void testDST1TranscriptProtocol() {
  std::cout << "=== Testing DST1 Transcript Protocol ===" << std::endl;

  const std::vector<uint8_t> query = {0x11, 0x22, 0x33};
  const std::vector<std::vector<uint8_t>> responses = {{0xAA, 0xBB}, {0xCC}};
  const std::vector<uint8_t> postCheck = {0x44, 0x55};

  auto transcript = dst1::buildTranscript(query, responses, postCheck);
  assert(!transcript.empty());

  assert(transcript.size() == dst1::computePrefixSize(responses.size()) +
                                 query.size() + postCheck.size() +
                                 responses[0].size() + responses[1].size());
  assert(transcript[0] == dst1::MAGIC[0]);
  assert(transcript[1] == dst1::MAGIC[1]);
  assert(transcript[2] == dst1::MAGIC[2]);
  assert(transcript[3] == dst1::MAGIC[3]);
  assert(transcript[dst1::RESPONSE_COUNT_OFFSET] == responses.size());
  assert(transcript[dst1::RESERVED_OFFSET] == dst1::RESERVED_VALUE);

  auto queryLen = dst1::readU16Le(transcript, dst1::QUERY_LENGTH_OFFSET);
  auto postLen = dst1::readU16Le(transcript, dst1::POST_CHECK_LENGTH_OFFSET);
  auto firstResponseLen = dst1::readU16Le(transcript, dst1::RESPONSE_LENGTHS_OFFSET);
  auto secondResponseLen =
      dst1::readU16Le(transcript, dst1::RESPONSE_LENGTHS_OFFSET + dst1::LENGTH_FIELD_SIZE);
  if (!queryLen || *queryLen != query.size() || !postLen ||
      *postLen != postCheck.size() || !firstResponseLen ||
      *firstResponseLen != responses[0].size() || !secondResponseLen ||
      *secondResponseLen != responses[1].size()) {
    std::abort();
  }

  const size_t payloadOffset = dst1::computePrefixSize(responses.size());
  assert(std::equal(query.begin(), query.end(), transcript.begin() + payloadOffset));

  const size_t firstResponseOffset = payloadOffset + query.size();
  assert(std::equal(responses[0].begin(), responses[0].end(),
                    transcript.begin() + firstResponseOffset));

  const size_t secondResponseOffset = firstResponseOffset + responses[0].size();
  assert(std::equal(responses[1].begin(), responses[1].end(),
                    transcript.begin() + secondResponseOffset));

  if (!std::equal(postCheck.begin(), postCheck.end(),
                  transcript.begin() + secondResponseOffset +
                      responses[1].size())) {
    std::abort();
  }

  std::vector<std::vector<uint8_t>> tooManyResponses(dst1::MAX_RESPONSES + 1,
                                                     std::vector<uint8_t>{0x01});
  assert(dst1::buildTranscript(query, tooManyResponses, postCheck).empty());

  std::vector<std::vector<uint8_t>> oversizedResponses(
      dst1::MAX_RESPONSES, std::vector<uint8_t>(1024, 0x7F));
  assert(dst1::buildTranscript(query, oversizedResponses, postCheck).empty());

  std::cout << "DST1 Transcript protocol tests PASSED" << std::endl << std::endl;
}

std::vector<uint8_t> buildDnsRR(const std::string &name, uint16_t type,
                                uint16_t dnsClass, uint32_t ttl,
                                const std::vector<uint8_t> &rdata) {
  auto owner = DNSNameCodec::encode(name);
  std::vector<uint8_t> rr;
  rr.reserve(owner.size() + 10 + rdata.size());
  rr.insert(rr.end(), owner.begin(), owner.end());
  rr.push_back(static_cast<uint8_t>((type >> 8) & 0xFF));
  rr.push_back(static_cast<uint8_t>(type & 0xFF));
  rr.push_back(static_cast<uint8_t>((dnsClass >> 8) & 0xFF));
  rr.push_back(static_cast<uint8_t>(dnsClass & 0xFF));
  rr.push_back(static_cast<uint8_t>((ttl >> 24) & 0xFF));
  rr.push_back(static_cast<uint8_t>((ttl >> 16) & 0xFF));
  rr.push_back(static_cast<uint8_t>((ttl >> 8) & 0xFF));
  rr.push_back(static_cast<uint8_t>(ttl & 0xFF));
  const uint16_t rdlength = static_cast<uint16_t>(rdata.size());
  rr.push_back(static_cast<uint8_t>((rdlength >> 8) & 0xFF));
  rr.push_back(static_cast<uint8_t>(rdlength & 0xFF));
  rr.insert(rr.end(), rdata.begin(), rdata.end());
  return rr;
}

std::vector<uint8_t> buildSampleDst1Transcript() {
  auto query = DNSPacketBuilder::buildQuery("www.example.com", 1);

  auto responseA = DNSPacketBuilder()
                       .setID(0x1234)
                       .asResponse()
                       .setRecursionDesired(true)
                       .setRecursionAvailable(true)
                       .addQuestion("www.example.com", 1, 1)
                       .addAnswer("www.example.com", 1, 1, 300, {1, 2, 3, 4})
                       .build();

  auto responseB = DNSPacketBuilder()
                       .setID(0x1234)
                       .asResponse()
                       .setRecursionDesired(true)
                       .setRecursionAvailable(true)
                       .addQuestion("www.example.com", 1, 1)
                       .addAnswer("www.example.com", 1, 1, 300, {5, 6, 7, 8})
                       .build();

  auto postCheck = DNSPacketBuilder::buildQuery("www.example.com", 1);
  auto transcript =
      dst1::buildTranscript(query, {responseA, responseB}, postCheck);
  assert(!transcript.empty());
  return transcript;
}

void testDST1MutatorRoundtrip() {
  std::cout << "=== Testing DST1Mutator Roundtrip ===" << std::endl;

  auto transcript = buildSampleDst1Transcript();
  auto parsed = DST1Mutator::parse(transcript);
  assert(parsed.has_value());

  auto serialized = DST1Mutator::serialize(*parsed);
  assert(serialized.has_value());

  auto reparsed = DST1Mutator::parse(*serialized);
  assert(reparsed.has_value());

  const uint8_t originalResponseCount = transcript[dst1::RESPONSE_COUNT_OFFSET];
  const uint8_t roundtripResponseCount =
      (*serialized)[dst1::RESPONSE_COUNT_OFFSET];
  if (originalResponseCount != roundtripResponseCount) {
    std::abort();
  }

  auto originalQueryLen = dst1::readU16Le(transcript, dst1::QUERY_LENGTH_OFFSET);
  auto roundtripQueryLen =
      dst1::readU16Le(*serialized, dst1::QUERY_LENGTH_OFFSET);
  auto originalPostLen =
      dst1::readU16Le(transcript, dst1::POST_CHECK_LENGTH_OFFSET);
  auto roundtripPostLen =
      dst1::readU16Le(*serialized, dst1::POST_CHECK_LENGTH_OFFSET);
  if (!originalQueryLen.has_value() || !roundtripQueryLen.has_value() ||
      !originalPostLen.has_value() || !roundtripPostLen.has_value() ||
      *originalQueryLen != *roundtripQueryLen ||
      *originalPostLen != *roundtripPostLen) {
    std::abort();
  }

  for (size_t i = 0; i < originalResponseCount; ++i) {
    const size_t off = dst1::RESPONSE_LENGTHS_OFFSET +
                       i * dst1::LENGTH_FIELD_SIZE;
    auto lhs = dst1::readU16Le(transcript, off);
    auto rhs = dst1::readU16Le(*serialized, off);
    if (!lhs.has_value() || !rhs.has_value() || *lhs != *rhs) {
      std::abort();
    }
  }

  std::cout << "DST1Mutator roundtrip tests PASSED" << std::endl << std::endl;
}

void testDST1MutatorMutationSafety() {
  std::cout << "=== Testing DST1Mutator Mutation Safety ===" << std::endl;

  auto transcript = buildSampleDst1Transcript();

  DST1Mutator::MutationRequest validRequest;
  DST1Mutator::QueryMutation validQueryMutation;
  validQueryMutation.QNAME = std::string("www.target.test");
  validQueryMutation.QTYPE = static_cast<uint16_t>(28);
  validQueryMutation.RD = false;
  validQueryMutation.TC = true;
  validQueryMutation.CD = true;
  validRequest.Query = validQueryMutation;

  auto nsRData = DNSNameCodec::encode("ns1.target.test");
  auto glueA = std::vector<uint8_t>{10, 10, 10, 10};
  auto glueAAAA =
      std::vector<uint8_t>{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42};

  DST1Mutator::ResponseMutation responseMutation;
  responseMutation.AA = true;
  responseMutation.RA = true;
  responseMutation.RCODE = 3;
  responseMutation.ANCOUNT = 1;
  responseMutation.NSCOUNT = 1;
  responseMutation.ARCOUNT = 2;
  responseMutation.AuthorityRRs = std::vector<std::vector<uint8_t>>{
      buildDnsRR("target.test", 2, 1, 600, nsRData)};
  responseMutation.AdditionalRRs = std::vector<std::vector<uint8_t>>{
      buildDnsRR("ns1.target.test", 1, 1, 600, glueA)};
  responseMutation.GlueRRs = std::vector<std::vector<uint8_t>>{
      buildDnsRR("ns1.target.test", 28, 1, 600, glueAAAA)};

  validRequest.Response = responseMutation;
  validRequest.ResponseIndex = 0;

  DST1Mutator::TranscriptMutation transcriptMutation;
  transcriptMutation.ResponseCount = 1;
  transcriptMutation.PostCheckName = std::string("www.target.test");
  transcriptMutation.PostCheckType = static_cast<uint16_t>(28);
  validRequest.Transcript = transcriptMutation;

  auto mutated = DST1Mutator::mutate(transcript, validRequest);
  assert(mutated.has_value());

  auto parsedMutated = DST1Mutator::parse(*mutated);
  assert(parsedMutated.has_value());
  assert(parsedMutated->Responses.size() == 1);

  DST1Mutator::MutationRequest invalidRRRequest;
  DST1Mutator::ResponseMutation invalidResponseMutation;
  invalidResponseMutation.AuthorityRRs =
      std::vector<std::vector<uint8_t>>{{0xC0}};
  invalidRRRequest.Response = invalidResponseMutation;
  invalidRRRequest.ResponseIndex = 0;

  auto rejectedByRR = DST1Mutator::mutate(transcript, invalidRRRequest);
  assert(!rejectedByRR.has_value());

  DST1Mutator::MutationRequest invalidCountRequest;
  DST1Mutator::TranscriptMutation invalidTranscriptMutation;
  invalidTranscriptMutation.ResponseCount = 3;
  invalidCountRequest.Transcript = invalidTranscriptMutation;

  auto rejectedByCount = DST1Mutator::mutate(transcript, invalidCountRequest);
  assert(!rejectedByCount.has_value());

  std::cout << "DST1Mutator mutation safety tests PASSED" << std::endl
            << std::endl;
}

void testDST1CoupledQuestionMutations() {
  std::cout << "=== Testing DST1 Coupled Question Mutations ===" << std::endl;

  const auto transcript = buildSampleDst1Transcript();

  DST1Mutator::MutationRequest nameRequest;
  DST1Mutator::QueryMutation nameMutation;
  nameMutation.QNAME = std::string("edge.target.test");
  nameRequest.Query = nameMutation;

  const auto nameMutated = DST1Mutator::mutate(transcript, nameRequest);
  assert(nameMutated.has_value());
  assert(DST1Mutator::validatePoisonEligible(*nameMutated).ok());

  DST1Mutator::MutationRequest typeRequest;
  DST1Mutator::QueryMutation typeMutation;
  typeMutation.QTYPE = static_cast<uint16_t>(28);
  typeRequest.Query = typeMutation;

  const auto typeMutated = DST1Mutator::mutate(transcript, typeRequest);
  assert(typeMutated.has_value());
  assert(DST1Mutator::validatePoisonEligible(*typeMutated).ok());

  DST1Mutator::MutationRequest classRequest;
  DST1Mutator::QueryMutation classMutation;
  classMutation.QCLASS = static_cast<uint16_t>(3);
  classRequest.Query = classMutation;

  const auto classMutated = DST1Mutator::mutate(transcript, classRequest);
  assert(classMutated.has_value());
  assert(DST1Mutator::validatePoisonEligible(*classMutated).ok());

  std::cout << "DST1 coupled question mutation tests PASSED" << std::endl
            << std::endl;
}

void testStatefulGeneratorFairBudget() {
  std::cout << "=== Testing Stateful Generator Fair Budget ===" << std::endl;

  StatefulDNSGenerator::Config config;
  config.MaxTranscripts = 2;
  config.MaxResponsesPerTranscript = 1;
  config.GenerateResponseRaces = false;

  StatefulDNSGenerator generator(config);
  generator.addQuerySeed(DNSPacketBuilder::buildQuery("first.example.test", 1));
  generator.addQuerySeed(DNSPacketBuilder::buildQuery("second.example.test", 1));

  const auto transcripts = generator.generateStatefulTranscripts();
  assert(transcripts.size() == 2);

  std::set<std::string> queryNames;
  for (const auto &transcript : transcripts) {
    const auto parsed = DST1Mutator::parse(transcript);
    assert(parsed.has_value());
    assert(DST1Mutator::validatePoisonEligible(*parsed).ok());
    queryNames.insert(DNSNameCodec::decode(parsed->ClientQuery, 12));
  }

  assert(queryNames.count("first.example.test") == 1);
  assert(queryNames.count("second.example.test") == 1);

  std::cout << "Stateful generator fair budget tests PASSED" << std::endl
            << std::endl;
}

void testDST1ValidationContract() {
  std::cout << "=== Testing DST1 Validation Contract ===" << std::endl;
  using Error = DST1Mutator::ValidationError;

  const auto valid = buildSampleDst1Transcript();
  assert(DST1Mutator::validateWire(valid).ok());
  assert(DST1Mutator::validatePoisonEligible(valid).ok());

  std::vector<uint8_t> shortHeader = {'D', 'S', 'T', '1'};
  assert(DST1Mutator::validateWire(shortHeader).Error == Error::InputTooShort);

  std::vector<uint8_t> truncatedTable = {
      'D', 'S', 'T', '1', 1, 0, 1, 0, 0, 0};
  assert(DST1Mutator::validateWire(truncatedTable).Error ==
         Error::TruncatedLengthTable);

  auto lengthMismatch = valid;
  lengthMismatch.pop_back();
  assert(DST1Mutator::validateWire(lengthMismatch).Error ==
         Error::LengthMismatch);

  const auto query = DNSPacketBuilder::buildQuery("www.example.com", 1);
  const auto postCheck = DNSPacketBuilder::buildQuery("www.example.com", 1);
  const auto response = DNSPacketBuilder()
                            .setID(0x1234)
                            .asResponse()
                            .addQuestion("www.example.com", 1, 1)
                            .build();

  const auto zeroResponse = dst1::buildTranscript(query, {}, postCheck);
  assert(DST1Mutator::validateWire(zeroResponse).ok());
  assert(DST1Mutator::validatePoisonEligible(zeroResponse).Error ==
         Error::MissingResponse);

  const auto emptyPost = dst1::buildTranscript(query, {response}, {});
  assert(DST1Mutator::validateWire(emptyPost).ok());
  assert(DST1Mutator::validatePoisonEligible(emptyPost).Error ==
         Error::EmptyPostCheck);

  const auto otherPost = DNSPacketBuilder::buildQuery("other.example.com", 1);
  const auto mismatchedPost =
      dst1::buildTranscript(query, {response}, otherPost);
  assert(DST1Mutator::validatePoisonEligible(mismatchedPost).Error ==
         Error::QueryPostCheckMismatch);

  const auto otherResponse = DNSPacketBuilder()
                                 .setID(0x1234)
                                 .asResponse()
                                 .addQuestion("other.example.com", 1, 1)
                                 .build();
  const auto mismatchedResponse =
      dst1::buildTranscript(query, {otherResponse}, postCheck);
  assert(DST1Mutator::validatePoisonEligible(mismatchedResponse).Error ==
         Error::ResponseQuestionMismatch);

  std::vector<uint8_t> pointerQuery = {
      0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0xC0, 0xFF, 0x00, 0x01, 0x00, 0x01};
  const auto invalidPointer =
      dst1::buildTranscript(pointerQuery, {response}, postCheck);
  assert(DST1Mutator::validateWire(invalidPointer).ok());
  assert(DST1Mutator::validatePoisonEligible(invalidPointer).Error ==
         Error::InvalidCompressionPointer);

  std::vector<uint8_t> oversized(dst1::MAX_TRANSCRIPT_INPUT + 1, 0);
  assert(DST1Mutator::validateWire(oversized).Error == Error::InputTooLarge);

  assert(std::string(DST1Mutator::validationErrorName(
             Error::ResponseQuestionMismatch)) ==
         "response_question_mismatch");

  std::cout << "DST1 validation contract tests PASSED" << std::endl
            << std::endl;
}

int main() {
  std::cout << "gen_input DNS Format Tests" << std::endl;
  std::cout << "==========================" << std::endl << std::endl;

  testDNSNameCodec();
  testDNSPacketBuilder();
  testBinaryFormat();
  testSerializeParseRoundtrip();
  testDST1TranscriptProtocol();
  testDST1MutatorRoundtrip();
  testDST1MutatorMutationSafety();
  testDST1CoupledQuestionMutations();
  testStatefulGeneratorFairBudget();
  testDST1ValidationContract();
  testFormatAwareGeneratorTimeoutStop();
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
