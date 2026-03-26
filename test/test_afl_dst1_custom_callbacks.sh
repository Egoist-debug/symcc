#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
HELPER_CPP="$TMP_DIR/afl_dst1_custom_callbacks_helper.cpp"
HELPER_BIN="$TMP_DIR/afl_dst1_custom_callbacks_helper"
LOG_FILE="$TMP_DIR/afl_dst1_custom_callbacks.log"
LIB_PATH="$ROOT_DIR/build/linux/x86_64/release/libafl_dst1_mutator.so"

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

xmake f -P gen_input -m release
xmake b -P gen_input afl_dst1_mutator

if [ ! -f "$LIB_PATH" ]; then
  printf 'ASSERT FAIL: 缺少 mutator 动态库 %s\n' "$LIB_PATH" >&2
  exit 1
fi

python3 - "$HELPER_CPP" <<'PY'
from pathlib import Path
import sys

code = r'''#include "DST1Mutator.h"
#include "DST1Transcript.h"
#include "FormatAwareGenerator.h"

#include <dlfcn.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using namespace geninput;

namespace {

[[noreturn]] void fail(const std::string &message) {
  std::cerr << "[afl-dst1-custom-callbacks] FAIL: " << message << std::endl;
  std::exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition) {
    fail(message);
  }
}

template <typename T>
T loadSymbol(void *handle, const char *name) {
  dlerror();
  void *symbol = dlsym(handle, name);
  const char *error = dlerror();
  require(error == nullptr && symbol != nullptr,
          std::string("缺少符号 ") + name);
  return reinterpret_cast<T>(symbol);
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

  auto skipSection = [&](uint16_t count) -> bool {
    for (uint16_t i = 0; i < count; ++i) {
      auto rr = parseRRAt(packet, cursor);
      if (!rr) {
        return false;
      }
      cursor = rr->endOffset;
    }
    return true;
  };

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

  if (!skipSection(ancount) || !parseSection(nscount, layout.authorityRRs) ||
      !parseSection(arcount, layout.additionalRRs) || cursor != packet.size()) {
    return std::nullopt;
  }

  return layout;
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

bool showsDonorUsage(const std::vector<uint8_t> &candidate,
                    const std::vector<uint8_t> &donor) {
  auto parsed = DST1Mutator::parse(candidate);
  auto donorParsed = DST1Mutator::parse(donor);
  if (!parsed || !donorParsed) {
    return false;
  }

  if (parsed->Responses.size() > 1 &&
      parsed->Responses.size() == donorParsed->Responses.size() &&
      parsed->Responses.back() == donorParsed->Responses.back()) {
    return true;
  }

  if (!parsed->Responses.empty() && !donorParsed->Responses.empty()) {
    if (parsed->Responses[0] == donorParsed->Responses[0]) {
      return true;
    }

    auto layout = parseResponseLayout(parsed->Responses[0]);
    auto donorLayout = parseResponseLayout(donorParsed->Responses[0]);
    if (layout && donorLayout) {
      if (!donorLayout->authorityRRs.empty() &&
          layout->authorityRRs == donorLayout->authorityRRs) {
        return true;
      }
      if (!donorLayout->additionalRRs.empty() &&
          layout->additionalRRs == donorLayout->additionalRRs) {
        return true;
      }
    }
  }

  return false;
}

void writeFile(const std::string &path, const std::vector<uint8_t> &bytes) {
  std::ofstream file(path, std::ios::binary);
  require(static_cast<bool>(file), "无法写入文件 " + path);
  file.write(reinterpret_cast<const char *>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
  require(static_cast<bool>(file), "写入文件失败 " + path);
}

struct MutatorApi {
  using InitFn = void *(*)(void *, unsigned int);
  using FuzzCountFn = unsigned int (*)(void *, const unsigned char *, size_t);
  using FuzzFn = size_t (*)(void *, unsigned char *, size_t, unsigned char **,
                            unsigned char *, size_t, size_t);
  using QueueGetFn = unsigned char (*)(void *, const unsigned char *);
  using PostProcessFn = size_t (*)(void *, unsigned char *, size_t,
                                   unsigned char **);
  using InitTrimFn = int (*)(void *, unsigned char *, size_t);
  using TrimFn = size_t (*)(void *, unsigned char **);
  using PostTrimFn = int (*)(void *, unsigned char);
  using DeinitFn = void (*)(void *);

  void *handle = nullptr;
  InitFn init = nullptr;
  FuzzCountFn fuzzCount = nullptr;
  FuzzFn fuzz = nullptr;
  QueueGetFn queueGet = nullptr;
  PostProcessFn postProcess = nullptr;
  InitTrimFn initTrim = nullptr;
  TrimFn trim = nullptr;
  PostTrimFn postTrim = nullptr;
  DeinitFn deinit = nullptr;
};

struct MutatorSession {
  const MutatorApi &api;
  void *state = nullptr;

  explicit MutatorSession(const MutatorApi &api, unsigned int seed) : api(api) {
    state = api.init(nullptr, seed);
    require(state != nullptr, "afl_custom_init 返回空状态");
  }

  ~MutatorSession() {
    if (state != nullptr) {
      api.deinit(state);
    }
  }
};

std::vector<uint8_t> callFuzz(const MutatorApi &api,
                              void *state,
                              const std::vector<uint8_t> &input,
                              const std::vector<uint8_t> *donor,
                              size_t maxSize) {
  std::vector<uint8_t> inputCopy = input;
  std::vector<uint8_t> donorCopy = donor ? *donor : std::vector<uint8_t>{};
  unsigned char *outBuf = nullptr;
  size_t outLen = api.fuzz(state, inputCopy.data(), inputCopy.size(), &outBuf,
                           donor ? donorCopy.data() : nullptr, donorCopy.size(),
                           maxSize);
  require(outLen > 0, "afl_custom_fuzz 返回空结果");
  require(outBuf != nullptr, "afl_custom_fuzz 未设置 OutBuf");
  return std::vector<uint8_t>(outBuf, outBuf + outLen);
}

std::vector<uint8_t> callPostProcess(const MutatorApi &api,
                                     void *state,
                                     const std::vector<uint8_t> &input) {
  std::vector<uint8_t> inputCopy = input;
  unsigned char *outBuf = nullptr;
  size_t outLen = api.postProcess(state,
                                  inputCopy.empty() ? nullptr : inputCopy.data(),
                                  inputCopy.size(), &outBuf);
  require(outLen > 0, "afl_custom_post_process 返回空结果");
  require(outBuf != nullptr, "afl_custom_post_process 未设置 OutBuf");
  return std::vector<uint8_t>(outBuf, outBuf + outLen);
}

void testFuzzAndCount(const MutatorApi &api) {
  const auto base = buildBaseTranscript();
  const auto donor = buildCompatibleDonorTranscript();
  const std::vector<uint8_t> malformed = {0x13, 0x37, 0x42};
  MutatorSession session(api, 0xC0FFEEU);

  const unsigned int freshSessionCount =
      api.fuzzCount(session.state, base.data(), base.size());
  require(freshSessionCount == 8,
          "fresh session 首次 parseable fuzz_count 必须为 8");

  {
    MutatorSession countThenFuzzSession(api, 0x111111U);
    require(api.fuzzCount(countThenFuzzSession.state, base.data(), base.size()) == 8,
            "先 count 后 fuzz 路径的首次 fuzz_count 必须为 8");
    auto countThenFuzz =
        callFuzz(api, countThenFuzzSession.state, base, nullptr, 4096);
    require(DST1Mutator::parse(countThenFuzz).has_value(),
            "先 count 后 fuzz 路径的结果必须保持 transcript 可解析");
    require(api.fuzzCount(countThenFuzzSession.state, base.data(), base.size()) ==
                8,
            "先 count 后 fuzz 路径在 fuzz 之后 fuzz_count 仍必须为 8");
  }

  {
    MutatorSession fuzzThenCountSession(api, 0x222222U);
    auto fuzzThenCount = callFuzz(api, fuzzThenCountSession.state, base, nullptr,
                                  4096);
    require(DST1Mutator::parse(fuzzThenCount).has_value(),
            "先 fuzz 后 count 路径的结果必须保持 transcript 可解析");
    require(api.fuzzCount(fuzzThenCountSession.state, base.data(), base.size()) ==
                8,
            "先 fuzz 后 count 路径的 fuzz_count 必须为 8");
  }

  bool donorUsed = false;
  for (size_t attempt = 0; attempt < 128; ++attempt) {
    auto mutated = callFuzz(api, session.state, base, &donor, 4096);
    require(DST1Mutator::parse(mutated).has_value(),
            "带 donor 的 fuzz 结果必须保持 transcript 可解析");
    if (showsDonorUsage(mutated, donor)) {
      donorUsed = true;
      break;
    }
  }
  require(donorUsed, "带 donor 的 afl_custom_fuzz 未实际消费 donor 输入");
  require(api.fuzzCount(session.state, base.data(), base.size()) == 8,
          "带 donor 路径之后 parseable fuzz_count 仍必须为 8");

  auto withoutDonor = callFuzz(api, session.state, base, nullptr, 4096);
  require(DST1Mutator::parse(withoutDonor).has_value(),
          "无 donor 的 fuzz 结果必须保持 transcript 可解析");
  const unsigned int postFuzzCount =
      api.fuzzCount(session.state, base.data(), base.size());
  require(postFuzzCount == 8,
          "无 donor 路径之后 parseable fuzz_count 仍必须为 8");

  auto malformedFallback = callFuzz(api, session.state, base, &malformed, 4096);
  require(!malformedFallback.empty(), "malformed donor fallback 结果不能为空");
  require(DST1Mutator::parse(malformedFallback).has_value(),
          "malformed donor fallback 必须保持 transcript 可解析");
  const unsigned int malformedCount =
      api.fuzzCount(session.state, malformed.data(), malformed.size());
  require(malformedCount == 1, "non-parseable fuzz_count 必须为 1");

  std::cout << "INFO fresh_session_count=" << freshSessionCount << std::endl;
  std::cout << "INFO post_fuzz_count=" << postFuzzCount << std::endl;
  std::cout << "INFO malformed_count=" << malformedCount << std::endl;

  std::cout << "PASS fuzz_count_rules" << std::endl;
  std::cout << "PASS fuzz_count_order_regression" << std::endl;
  std::cout << "PASS donor_consumed" << std::endl;
  std::cout << "PASS malformed_donor_fallback" << std::endl;
}

void testQueueGet(const MutatorApi &api, const std::string &tmpDir) {
  const auto base = buildBaseTranscript();
  const std::vector<uint8_t> invalid = {0x99, 0x88, 0x77, 0x66};
  const std::string validPath = tmpDir + "/queue_valid.dst1";
  const std::string invalidPath = tmpDir + "/queue_invalid.bin";
  writeFile(validPath, base);
  writeFile(invalidPath, invalid);

  require(setenv("DST1_MUTATOR_ONLY", "1", 1) == 0,
          "无法设置 DST1_MUTATOR_ONLY=1");
  require(api.queueGet(nullptr,
                       reinterpret_cast<const unsigned char *>(validPath.c_str())) == 1,
          "DST1_MUTATOR_ONLY=1 时应接受 parseable transcript");
  require(api.queueGet(nullptr,
                       reinterpret_cast<const unsigned char *>(invalidPath.c_str())) == 0,
          "DST1_MUTATOR_ONLY=1 时必须拒绝 non-parseable transcript");

  require(setenv("DST1_MUTATOR_ONLY", "0", 1) == 0,
          "无法设置 DST1_MUTATOR_ONLY=0");
  require(api.queueGet(nullptr,
                       reinterpret_cast<const unsigned char *>(invalidPath.c_str())) == 1,
          "非 mutator-only 模式不应过度过滤 queue entry");
  require(unsetenv("DST1_MUTATOR_ONLY") == 0,
          "无法清理 DST1_MUTATOR_ONLY");

  std::cout << "PASS queue_get_mutator_only_filter" << std::endl;
}

void testPostProcess(const MutatorApi &api) {
  MutatorSession session(api, 0x515151U);
  const auto base = buildBaseTranscript();
  const std::vector<uint8_t> invalid = {0x13, 0x37, 0x00};

  auto parsed = DST1Mutator::parse(base);
  require(parsed.has_value(), "base transcript 解析失败");
  auto canonical = DST1Mutator::serialize(*parsed);
  require(canonical.has_value() && !canonical->empty(),
          "base transcript canonicalize 失败");

  auto canonicalized = callPostProcess(api, session.state, base);
  require(canonicalized == *canonical,
          "post_process 必须执行 parse/serialize 规范化");

  auto fallback = callPostProcess(api, session.state, invalid);
  require(!fallback.empty(), "post_process fallback 不得输出空结果");
  require(fallback == invalid,
          "post_process 解析失败时必须安全回退到原始非空输入");

  std::cout << "PASS post_process_canonicalization" << std::endl;
  std::cout << "PASS post_process_nonempty_fallback" << std::endl;
}

void testTrim(const MutatorApi &api) {
  MutatorSession session(api, 0xABCD12U);
  const auto rich = buildCompatibleDonorTranscript();

  const int initSteps = api.initTrim(session.state,
                                     const_cast<unsigned char *>(rich.data()),
                                     rich.size());
  require(initSteps > 0, "afl_custom_init_trim 必须为富 transcript 提供裁剪步骤");

  size_t currentSize = rich.size();
  size_t successfulTrims = 0;

  while (true) {
    unsigned char *outBuf = nullptr;
    size_t outLen = api.trim(session.state, &outBuf);
    require(outLen > 0, "afl_custom_trim 不得输出空结果");
    require(outBuf != nullptr, "afl_custom_trim 未设置 OutBuf");
    require(outLen < currentSize,
            "afl_custom_trim 必须生成比当前输入更小的候选");

    std::vector<uint8_t> candidate(outBuf, outBuf + outLen);
    require(DST1Mutator::parse(candidate).has_value(),
            "afl_custom_trim 结果必须保持 transcript 可解析");

    currentSize = candidate.size();
    ++successfulTrims;
    const int next = api.postTrim(session.state, 1);
    if (next != 0) {
      break;
    }
  }

  require(successfulTrims > 0, "trim 必须产生至少一次有效裁剪");
  std::cout << "PASS trim_preserves_parseability" << std::endl;
  std::cout << "PASS trim_makes_forward_progress" << std::endl;
}

} // namespace

int main(int argc, char **argv) {
  require(argc == 3, "USAGE: helper <mutator-so> <tmp-dir>");

  void *handle = dlopen(argv[1], RTLD_NOW);
  const char *dlopenError = dlerror();
  require(handle != nullptr,
          std::string("dlopen 失败: ") +
              (dlopenError != nullptr ? dlopenError : "unknown"));

  MutatorApi api;
  api.handle = handle;
  api.init = loadSymbol<MutatorApi::InitFn>(handle, "afl_custom_init");
  api.fuzzCount =
      loadSymbol<MutatorApi::FuzzCountFn>(handle, "afl_custom_fuzz_count");
  api.fuzz = loadSymbol<MutatorApi::FuzzFn>(handle, "afl_custom_fuzz");
  api.queueGet =
      loadSymbol<MutatorApi::QueueGetFn>(handle, "afl_custom_queue_get");
  api.postProcess = loadSymbol<MutatorApi::PostProcessFn>(
      handle, "afl_custom_post_process");
  api.initTrim =
      loadSymbol<MutatorApi::InitTrimFn>(handle, "afl_custom_init_trim");
  api.trim = loadSymbol<MutatorApi::TrimFn>(handle, "afl_custom_trim");
  api.postTrim =
      loadSymbol<MutatorApi::PostTrimFn>(handle, "afl_custom_post_trim");
  api.deinit = loadSymbol<MutatorApi::DeinitFn>(handle, "afl_custom_deinit");

  testFuzzAndCount(api);
  testQueueGet(api, argv[2]);
  testPostProcess(api);
  testTrim(api);

  dlclose(handle);
  std::cout << "PASS all_custom_callback_checks" << std::endl;
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
  -ldl \
  -o "$HELPER_BIN"

"$HELPER_BIN" "$LIB_PATH" "$TMP_DIR" | tee "$LOG_FILE"

assert_file_contains "$LOG_FILE" 'PASS fuzz_count_rules'
assert_file_contains "$LOG_FILE" 'PASS fuzz_count_order_regression'
assert_file_contains "$LOG_FILE" 'PASS donor_consumed'
assert_file_contains "$LOG_FILE" 'PASS malformed_donor_fallback'
assert_file_contains "$LOG_FILE" 'PASS queue_get_mutator_only_filter'
assert_file_contains "$LOG_FILE" 'PASS post_process_canonicalization'
assert_file_contains "$LOG_FILE" 'PASS post_process_nonempty_fallback'
assert_file_contains "$LOG_FILE" 'PASS trim_preserves_parseability'
assert_file_contains "$LOG_FILE" 'PASS trim_makes_forward_progress'
assert_file_contains "$LOG_FILE" 'PASS all_custom_callback_checks'

printf '[afl-dst1-custom-callbacks] PASS\n'
