#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
HELPER_CPP="$TMP_DIR/dst1_structured_splice_helper.cpp"
HELPER_BIN="$TMP_DIR/dst1_structured_splice_helper"
LOG_FILE="$TMP_DIR/dst1_structured_splice.log"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

assert_file_contains() {
  local path="$1"
  local needle="$2"
  if ! grep -Fq "$needle" "$path"; then
    printf 'ASSERT FAIL: %s 未包含 %s\n' "$path" "$needle" >&2
    return 1
  fi
}

python3 - "$HELPER_CPP" <<'PY'
from pathlib import Path
import sys

code = r'''#include "DST1Mutator.h"
#include "DST1Transcript.h"
#include "FormatAwareGenerator.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using namespace geninput;

namespace {

[[noreturn]] void fail(const std::string &message) {
  std::cerr << "[dst1-structured-splice] FAIL: " << message << std::endl;
  std::exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition) {
    fail(message);
  }
}

uint16_t readBe16(const std::vector<uint8_t> &input, size_t offset) {
  return (static_cast<uint16_t>(input[offset]) << 8) |
         static_cast<uint16_t>(input[offset + 1]);
}

std::optional<size_t> consumeDnsName(const std::vector<uint8_t> &packet,
                                     size_t offset) {
  size_t position = offset;
  size_t guard = packet.size();

  while (position < packet.size() && guard > 0) {
    const uint8_t length = packet[position];
    if ((length & 0xC0) == 0xC0) {
      if (position + 1 >= packet.size()) {
        return std::nullopt;
      }
      return position + 2;
    }

    if (length == 0) {
      return position + 1;
    }

    if (length > 63 || position + 1 + length > packet.size()) {
      return std::nullopt;
    }

    position += 1 + length;
    --guard;
  }

  return std::nullopt;
}

struct ParsedQuestionInfo {
  size_t endOffset = 0;
  std::string name;
  uint16_t type = 0;
  uint16_t dnsClass = 0;
};

std::optional<ParsedQuestionInfo>
parseSingleQuestion(const std::vector<uint8_t> &packet) {
  if (packet.size() < 12 || readBe16(packet, 4) != 1) {
    return std::nullopt;
  }

  auto nameEnd = consumeDnsName(packet, 12);
  if (!nameEnd || *nameEnd + 4 > packet.size()) {
    return std::nullopt;
  }

  ParsedQuestionInfo info;
  info.endOffset = *nameEnd + 4;
  info.name = DNSNameCodec::decode(packet, 12);
  info.type = readBe16(packet, *nameEnd);
  info.dnsClass = readBe16(packet, *nameEnd + 2);
  if (info.name.empty()) {
    return std::nullopt;
  }
  return info;
}

struct RRInfo {
  size_t startOffset = 0;
  size_t endOffset = 0;
};

std::optional<RRInfo> parseRRAt(const std::vector<uint8_t> &packet,
                                size_t offset) {
  RRInfo info;
  info.startOffset = offset;
  auto nameEnd = consumeDnsName(packet, offset);
  if (!nameEnd || *nameEnd + 10 > packet.size()) {
    return std::nullopt;
  }

  const uint16_t rdLength = readBe16(packet, *nameEnd + 8);
  const size_t rdataOffset = *nameEnd + 10;
  if (rdataOffset + rdLength > packet.size()) {
    return std::nullopt;
  }

  info.endOffset = rdataOffset + rdLength;
  return info;
}

struct ParsedResponseLayout {
  std::vector<std::vector<uint8_t>> answerRRs;
  std::vector<std::vector<uint8_t>> authorityRRs;
  std::vector<std::vector<uint8_t>> additionalRRs;
};

std::optional<ParsedResponseLayout>
parseResponseLayout(const std::vector<uint8_t> &packet) {
  if (packet.size() < 12 || (packet[2] & 0x80) == 0) {
    return std::nullopt;
  }

  auto question = parseSingleQuestion(packet);
  if (!question) {
    return std::nullopt;
  }

  ParsedResponseLayout layout;
  size_t cursor = question->endOffset;
  const uint16_t ancount = readBe16(packet, 6);
  const uint16_t nscount = readBe16(packet, 8);
  const uint16_t arcount = readBe16(packet, 10);

  auto parseSection = [&](uint16_t count,
                          std::vector<std::vector<uint8_t>> &output) -> bool {
    for (uint16_t i = 0; i < count; ++i) {
      auto rr = parseRRAt(packet, cursor);
      if (!rr) {
        return false;
      }
      output.emplace_back(packet.begin() + rr->startOffset,
                          packet.begin() + rr->endOffset);
      cursor = rr->endOffset;
    }
    return true;
  };

  if (!parseSection(ancount, layout.answerRRs) ||
      !parseSection(nscount, layout.authorityRRs) ||
      !parseSection(arcount, layout.additionalRRs) || cursor != packet.size()) {
    return std::nullopt;
  }

  return layout;
}

DST1Mutator::Transcript requireParsedTranscript(const std::vector<uint8_t> &bytes,
                                                const std::string &label) {
  auto parsed = DST1Mutator::parse(bytes);
  require(parsed.has_value(), label + " 无法被 DST1Mutator::parse 解析");
  return *parsed;
}

void requirePostCheckCoupling(const DST1Mutator::Transcript &transcript,
                              const std::string &label) {
  auto query = parseSingleQuestion(transcript.ClientQuery);
  auto post = parseSingleQuestion(transcript.PostCheckQuery);
  require(query.has_value() && post.has_value(),
          label + " 的 query/post-check 解析失败");
  require(query->name == post->name && query->type == post->type,
          label + " 的 post-check coupling 被破坏");
}

void requireRoundTrip(const std::vector<uint8_t> &bytes, const std::string &label) {
  auto parsed = requireParsedTranscript(bytes, label);
  requirePostCheckCoupling(parsed, label);
  auto serialized = DST1Mutator::serialize(parsed);
  require(serialized.has_value(), label + " serialize 失败");
  auto reparsed = DST1Mutator::parse(*serialized);
  require(reparsed.has_value(), label + " parse->serialize->parse 失败");
  requirePostCheckCoupling(*reparsed, label + " roundtrip");
}

std::vector<uint8_t> buildBaseTranscript() {
  auto query = DNSPacketBuilder::buildQuery("cache.example.test", 1);
  auto response = DNSPacketBuilder()
                      .setID(0x1234)
                      .asResponse()
                      .setRecursionDesired(true)
                      .setRecursionAvailable(true)
                      .addQuestion("cache.example.test", 1, 1)
                      .addAnswer("cache.example.test", 1, 1, 300, {1, 2, 3, 4})
                      .build();
  auto postCheck = DNSPacketBuilder::buildQuery("cache.example.test", 1);
  auto transcript = dst1::buildTranscript(query, {response}, postCheck);
  require(!transcript.empty(), "基础 transcript 构造失败");
  return transcript;
}

std::vector<uint8_t> buildCompatibleDonorTranscript() {
  auto query = DNSPacketBuilder::buildQuery("cache.example.test", 1);
  auto response0 = DNSPacketBuilder()
                       .setID(0x1234)
                       .asResponse()
                       .setRecursionDesired(true)
                       .setRecursionAvailable(true)
                       .addQuestion("cache.example.test", 1, 1)
                       .addAnswer("cache.example.test", 1, 1, 600, {9, 9, 9, 9})
                       .addAuthority("example.test", 2, 1, 600,
                                     DNSNameCodec::encode("ns1.example.test"))
                       .addAdditional("ns1.example.test", 1, 1, 600,
                                      {10, 20, 30, 40})
                       .build();
  auto response1 = DNSPacketBuilder()
                       .setID(0x1234)
                       .asResponse()
                       .setRecursionDesired(true)
                       .setRecursionAvailable(true)
                       .addQuestion("cache.example.test", 1, 1)
                       .addAnswer("cache.example.test", 1, 1, 600, {8, 8, 4, 4})
                       .build();
  auto postCheck = DNSPacketBuilder::buildQuery("cache.example.test", 1);
  auto transcript = dst1::buildTranscript(query, {response0, response1}, postCheck);
  require(!transcript.empty(), "兼容 donor transcript 构造失败");
  return transcript;
}

std::vector<uint8_t> buildShiftDonorTranscript() {
  auto query = DNSPacketBuilder::buildQuery("shift.example.test", 28);
  auto response = DNSPacketBuilder()
                      .setID(0x4321)
                      .asResponse()
                      .setRecursionDesired(true)
                      .setRecursionAvailable(true)
                      .addQuestion("shift.example.test", 28, 1)
                      .addAnswer("shift.example.test", 28, 1, 300,
                                 {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A})
                      .build();
  auto postCheck = DNSPacketBuilder::buildQuery("shift.example.test", 28);
  auto transcript = dst1::buildTranscript(query, {response}, postCheck);
  require(!transcript.empty(), "post-check donor transcript 构造失败");
  return transcript;
}

std::vector<uint8_t> buildZeroResponseDonorTranscript() {
  auto query = DNSPacketBuilder::buildQuery("cache.example.test", 1);
  auto postCheck = DNSPacketBuilder::buildQuery("cache.example.test", 1);
  auto transcript = dst1::buildTranscript(query, {}, postCheck);
  require(!transcript.empty(), "零响应 donor transcript 构造失败");
  return transcript;
}

void testResponseSpliceSameIndex(const std::vector<uint8_t> &base,
                                 const std::vector<uint8_t> &donor) {
  DST1Mutator::MutationRequest request;
  request.DonorFamily = DST1Mutator::DonorMutationFamily::ResponseSpliceSameIndex;
  request.ResponseIndex = 0;

  auto mutated = DST1Mutator::mutate(base, request, donor);
  require(mutated.has_value(), "response_splice_same_index 未生成结果");
  auto parsed = requireParsedTranscript(*mutated, "response_splice_same_index");
  auto donorParsed = requireParsedTranscript(donor, "response_splice_same_index donor");
  require(parsed.Responses.size() == 1,
          "response_splice_same_index 不应改变 response 数量");
  require(parsed.Responses[0] == donorParsed.Responses[0],
          "response_splice_same_index 未使用 donor 同索引 response");
  requireRoundTrip(*mutated, "response_splice_same_index");
  std::cout << "PASS response_splice_same_index" << std::endl;
}

void testAuthorityTransplant(const std::vector<uint8_t> &base,
                             const std::vector<uint8_t> &donor) {
  DST1Mutator::MutationRequest request;
  request.DonorFamily = DST1Mutator::DonorMutationFamily::AuthorityTransplant;
  request.ResponseIndex = 0;

  auto mutated = DST1Mutator::mutate(base, request, donor);
  require(mutated.has_value(), "authority_transplant 未生成结果");
  auto parsed = requireParsedTranscript(*mutated, "authority_transplant");
  auto donorParsed = requireParsedTranscript(donor, "authority donor");
  auto layout = parseResponseLayout(parsed.Responses[0]);
  auto donorLayout = parseResponseLayout(donorParsed.Responses[0]);
  require(layout.has_value() && donorLayout.has_value(),
          "authority_transplant 响应布局解析失败");
  require(layout->authorityRRs == donorLayout->authorityRRs,
          "authority_transplant 未移植 donor authority RRs");
  requireRoundTrip(*mutated, "authority_transplant");
  std::cout << "PASS authority_transplant" << std::endl;
}

void testAdditionalOrGlueTransplant(const std::vector<uint8_t> &base,
                                    const std::vector<uint8_t> &donor) {
  DST1Mutator::MutationRequest request;
  request.DonorFamily =
      DST1Mutator::DonorMutationFamily::AdditionalOrGlueTransplant;
  request.ResponseIndex = 0;

  auto mutated = DST1Mutator::mutate(base, request, donor);
  require(mutated.has_value(), "additional_or_glue_transplant 未生成结果");
  auto parsed = requireParsedTranscript(*mutated, "additional_or_glue_transplant");
  auto donorParsed = requireParsedTranscript(donor, "additional donor");
  auto layout = parseResponseLayout(parsed.Responses[0]);
  auto donorLayout = parseResponseLayout(donorParsed.Responses[0]);
  require(layout.has_value() && donorLayout.has_value(),
          "additional_or_glue_transplant 响应布局解析失败");
  require(layout->additionalRRs == donorLayout->additionalRRs,
          "additional_or_glue_transplant 未移植 donor additional/glue RRs");
  requireRoundTrip(*mutated, "additional_or_glue_transplant");
  std::cout << "PASS additional_or_glue_transplant" << std::endl;
}

void testResponseCountExpandAndShrink(const std::vector<uint8_t> &base,
                                      const std::vector<uint8_t> &donor,
                                      const std::vector<uint8_t> &zeroDonor) {
  DST1Mutator::MutationRequest request;
  request.DonorFamily =
      DST1Mutator::DonorMutationFamily::ResponseCountExpandOrShrinkFromDonor;

  auto expanded = DST1Mutator::mutate(base, request, donor);
  require(expanded.has_value(), "response_count_expand 未生成结果");
  auto expandedParsed = requireParsedTranscript(*expanded, "response_count_expand");
  auto donorParsed = requireParsedTranscript(donor, "response_count_expand donor");
  require(expandedParsed.Responses.size() == donorParsed.Responses.size(),
          "response_count_expand 未采用 donor response 数量");
  require(expandedParsed.Responses.back() == donorParsed.Responses.back(),
          "response_count_expand 未追加 donor response 块");
  requireRoundTrip(*expanded, "response_count_expand");
  std::cout << "PASS response_count_expand_from_donor" << std::endl;

  auto shrunk = DST1Mutator::mutate(base, request, zeroDonor);
  require(shrunk.has_value(), "response_count_shrink 未生成结果");
  auto shrunkParsed = requireParsedTranscript(*shrunk, "response_count_shrink");
  require(shrunkParsed.Responses.empty(),
          "response_count_shrink 未按照 donor 缩减为 0 个 response");
  requireRoundTrip(*shrunk, "response_count_shrink");
  std::cout << "PASS response_count_shrink_from_donor" << std::endl;
}

void testPostCheckCoupledShift(const std::vector<uint8_t> &base,
                               const std::vector<uint8_t> &donor) {
  DST1Mutator::MutationRequest request;
  request.DonorFamily =
      DST1Mutator::DonorMutationFamily::PostCheckCoupledNameOrTypeShift;

  auto mutated = DST1Mutator::mutate(base, request, donor);
  require(mutated.has_value(), "post_check_coupled_name_or_type_shift 未生成结果");
  auto parsed = requireParsedTranscript(*mutated,
                                        "post_check_coupled_name_or_type_shift");
  auto query = parseSingleQuestion(parsed.ClientQuery);
  auto post = parseSingleQuestion(parsed.PostCheckQuery);
  require(query.has_value() && post.has_value(),
          "post_check_coupled_name_or_type_shift 的 query/post-check 解析失败");
  require(query->name == "shift.example.test" && query->type == 28,
          "post_check_coupled_name_or_type_shift 未应用 donor query name/type");
  require(post->name == "shift.example.test" && post->type == 28,
          "post_check_coupled_name_or_type_shift 未保持 post-check coupling");
  requireRoundTrip(*mutated, "post_check_coupled_name_or_type_shift");
  std::cout << "PASS post_check_coupled_name_or_type_shift" << std::endl;
}

void testMalformedDonorFallback(const std::vector<uint8_t> &base,
                                 const std::vector<uint8_t> &malformedDonor) {
  DST1Mutator::MutationRequest request;
  request.DonorFamily = DST1Mutator::DonorMutationFamily::AuthorityTransplant;
  request.ResponseIndex = 0;

  DST1Mutator::ResponseMutation fallback;
  fallback.AA = true;
  fallback.RCODE = 2;
  request.Response = fallback;

  auto fallbackOnly = DST1Mutator::mutate(base, request);
  require(fallbackOnly.has_value(), "malformed donor fallback 的基线变异失败");
  require(*fallbackOnly != base, "malformed donor fallback 的基线变异未生效");

  auto withMalformedDonor = DST1Mutator::mutate(base, request, malformedDonor);
  require(withMalformedDonor.has_value(),
          "malformed donor fallback 未返回自包含回退结果");
  require(*withMalformedDonor == *fallbackOnly,
          "malformed donor fallback 未回退到既有自包含行为");
  requireRoundTrip(*withMalformedDonor, "malformed donor fallback");
  std::cout << "PASS malformed_donor_fallback" << std::endl;
}

void testParseableButIncompatibleDonorFallback(const std::vector<uint8_t> &base,
                                               const std::vector<uint8_t> &donor) {
  DST1Mutator::MutationRequest request;
  request.DonorFamily = DST1Mutator::DonorMutationFamily::ResponseSpliceSameIndex;
  request.ResponseIndex = 0;

  DST1Mutator::QueryMutation query;
  query.QNAME = std::string("shifted.local.example.test");
  request.Query = query;

  DST1Mutator::TranscriptMutation transcript;
  transcript.PostCheckName = std::string("shifted.local.example.test");
  request.Transcript = transcript;

  auto fallbackOnly = DST1Mutator::mutate(base, request);
  require(fallbackOnly.has_value(),
          "parseable-but-incompatible donor fallback 的基线变异失败");

  auto withDonor = DST1Mutator::mutate(base, request, donor);
  require(withDonor.has_value(),
          "parseable-but-incompatible donor fallback 未返回回退结果");
  require(*withDonor == *fallbackOnly,
          "parseable-but-incompatible donor fallback 未退回原始自包含请求");
  requireRoundTrip(*withDonor, "parseable-but-incompatible donor fallback");
  std::cout << "PASS parseable_but_incompatible_donor_fallback" << std::endl;
}

} // namespace

int main() {
  const auto base = buildBaseTranscript();
  const auto compatibleDonor = buildCompatibleDonorTranscript();
  const auto shiftDonor = buildShiftDonorTranscript();
  const auto zeroDonor = buildZeroResponseDonorTranscript();
  const std::vector<uint8_t> malformedDonor = {0x00, 0x01, 0x02, 0x03};

  testResponseSpliceSameIndex(base, compatibleDonor);
  testAuthorityTransplant(base, compatibleDonor);
  testAdditionalOrGlueTransplant(base, compatibleDonor);
  testResponseCountExpandAndShrink(base, compatibleDonor, zeroDonor);
  testPostCheckCoupledShift(base, shiftDonor);
  testMalformedDonorFallback(base, malformedDonor);
  testParseableButIncompatibleDonorFallback(base, compatibleDonor);

  std::cout << "PASS all_structured_splice_checks" << std::endl;
  return 0;
}
'''

Path(sys.argv[1]).write_text(code, encoding='utf-8')
PY

"${CXX:-c++}" -std=c++17 -Wall -Wextra -Wpedantic -pthread \
  -I"$ROOT_DIR/gen_input/include" \
  -I"$ROOT_DIR/runtime/include" \
  "$HELPER_CPP" \
  "$ROOT_DIR/gen_input/src/DST1Mutator.cpp" \
  "$ROOT_DIR/gen_input/src/FormatAwareGenerator.cpp" \
  "$ROOT_DIR/gen_input/src/BinaryFormat.cpp" \
  "$ROOT_DIR/gen_input/src/SymCCRunner.cpp" \
  -o "$HELPER_BIN"

"$HELPER_BIN" | tee "$LOG_FILE"

assert_file_contains "$LOG_FILE" 'PASS response_splice_same_index'
assert_file_contains "$LOG_FILE" 'PASS authority_transplant'
assert_file_contains "$LOG_FILE" 'PASS additional_or_glue_transplant'
assert_file_contains "$LOG_FILE" 'PASS response_count_expand_from_donor'
assert_file_contains "$LOG_FILE" 'PASS response_count_shrink_from_donor'
assert_file_contains "$LOG_FILE" 'PASS post_check_coupled_name_or_type_shift'
assert_file_contains "$LOG_FILE" 'PASS malformed_donor_fallback'
assert_file_contains "$LOG_FILE" 'PASS parseable_but_incompatible_donor_fallback'
assert_file_contains "$LOG_FILE" 'PASS all_structured_splice_checks'

printf '[dst1-structured-splice] PASS\n'
