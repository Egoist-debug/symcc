#include "DST1Mutator.h"
#include "DST1Transcript.h"
#include "FormatAwareGenerator.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using namespace geninput;

namespace {

enum class RunMode {
  Mutator,
  Baseline,
};

struct SampleSet {
  std::string SourceTag;
  std::vector<std::vector<uint8_t>> Samples;
};

struct Metrics {
  size_t Total = 0;
  size_t HeaderPass = 0;
  size_t ParsePass = 0;
  size_t MutationApplied = 0;
};

uint16_t readBe16(const std::vector<uint8_t> &Bytes, size_t Offset) {
  return (static_cast<uint16_t>(Bytes[Offset]) << 8) |
         static_cast<uint16_t>(Bytes[Offset + 1]);
}

std::optional<std::vector<uint8_t>> readFileBytes(const std::filesystem::path &Path) {
  std::ifstream Input(Path, std::ios::binary);
  if (!Input) {
    return std::nullopt;
  }
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(Input),
                              std::istreambuf_iterator<char>());
}

std::vector<std::filesystem::path> collectFilesSorted(const std::filesystem::path &Dir) {
  std::vector<std::filesystem::path> Files;
  if (!std::filesystem::exists(Dir) || !std::filesystem::is_directory(Dir)) {
    return Files;
  }

  for (const auto &Entry : std::filesystem::directory_iterator(Dir)) {
    if (Entry.is_regular_file()) {
      Files.push_back(Entry.path());
    }
  }

  std::sort(Files.begin(), Files.end());
  return Files;
}

std::vector<std::vector<uint8_t>> buildBuiltinFixedCorpus() {
  std::vector<std::vector<uint8_t>> Corpus;

  struct SeedSpec {
    std::string Domain;
    uint16_t Type;
    std::vector<std::vector<uint8_t>> AnswerIPs;
  };

  const std::vector<SeedSpec> Specs = {
      {"www.example.com", 1, {{1, 2, 3, 4}, {9, 8, 7, 6}}},
      {"ns1.example.net", 1, {{10, 20, 30, 40}}},
      {"edge.demo.org", 1, {{127, 0, 0, 1}, {192, 168, 10, 11}, {8, 8, 4, 4}}},
      {"mail.target.test", 28, {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 1}}},
  };

  for (const auto &Spec : Specs) {
    const auto Query = DNSPacketBuilder::buildQuery(Spec.Domain, Spec.Type);
    std::vector<std::vector<uint8_t>> Responses;
    for (const auto &RData : Spec.AnswerIPs) {
      Responses.push_back(DNSPacketBuilder()
                              .setID(0x1234)
                              .asResponse()
                              .setRecursionDesired(true)
                              .setRecursionAvailable(true)
                              .addQuestion(Spec.Domain, Spec.Type, 1)
                              .addAnswer(Spec.Domain, Spec.Type, 1, 300, RData)
                              .build());
    }

    const auto PostCheck = DNSPacketBuilder::buildQuery(Spec.Domain, Spec.Type);
    auto Transcript = dst1::buildTranscript(Query, Responses, PostCheck);
    if (!Transcript.empty()) {
      Corpus.push_back(std::move(Transcript));
    }
  }

  return Corpus;
}

SampleSet loadAutomaticCorpus() {
  std::vector<std::filesystem::path> CandidateDirs;

  if (const char *EnvPath = std::getenv("DST1_CORPUS_DIR"); EnvPath != nullptr &&
                                                           *EnvPath != '\0') {
    CandidateDirs.emplace_back(EnvPath);
  }

  const std::filesystem::path Cwd = std::filesystem::current_path();
  const std::filesystem::path Parent = Cwd.parent_path();
  CandidateDirs.push_back(Cwd / "named_experiment/work/stable_transcript_corpus");
  CandidateDirs.push_back(Cwd / "unbound_experiment/work/stable_transcript_corpus");
  CandidateDirs.push_back(Parent / "named_experiment/work/stable_transcript_corpus");
  CandidateDirs.push_back(Parent / "unbound_experiment/work/stable_transcript_corpus");

  for (const auto &Dir : CandidateDirs) {
    auto Files = collectFilesSorted(Dir);
    if (Files.empty()) {
      continue;
    }

    SampleSet Result;
    Result.SourceTag = Dir.string();
    for (const auto &Path : Files) {
      auto Bytes = readFileBytes(Path);
      if (!Bytes || Bytes->empty()) {
        continue;
      }
      Result.Samples.push_back(std::move(*Bytes));
    }

    if (!Result.Samples.empty()) {
      return Result;
    }
  }

  SampleSet Fallback;
  Fallback.SourceTag = "builtin-fixed-corpus";
  Fallback.Samples = buildBuiltinFixedCorpus();
  return Fallback;
}

bool checkHeaderAndLengthConsistency(const std::vector<uint8_t> &Input) {
  if (Input.size() < dst1::computePrefixSize(0)) {
    return false;
  }

  if (!std::equal(dst1::MAGIC.begin(), dst1::MAGIC.end(), Input.begin())) {
    return false;
  }

  if (Input[dst1::RESERVED_OFFSET] != dst1::RESERVED_VALUE) {
    return false;
  }

  const uint8_t ResponseCount = Input[dst1::RESPONSE_COUNT_OFFSET];
  if (ResponseCount > dst1::MAX_RESPONSES) {
    return false;
  }

  const size_t PrefixSize = dst1::computePrefixSize(ResponseCount);
  if (PrefixSize > Input.size()) {
    return false;
  }

  auto QueryLength = dst1::readU16Le(Input, dst1::QUERY_LENGTH_OFFSET);
  auto PostLength = dst1::readU16Le(Input, dst1::POST_CHECK_LENGTH_OFFSET);
  if (!QueryLength || !PostLength || *QueryLength == 0) {
    return false;
  }

  size_t TotalFromHeader = PrefixSize + *QueryLength + *PostLength;
  for (uint8_t I = 0; I < ResponseCount; ++I) {
    const size_t Offset =
        dst1::RESPONSE_LENGTHS_OFFSET + (static_cast<size_t>(I) * dst1::LENGTH_FIELD_SIZE);
    auto SegmentLen = dst1::readU16Le(Input, Offset);
    if (!SegmentLen || *SegmentLen == 0) {
      return false;
    }
    TotalFromHeader += *SegmentLen;
  }

  if (TotalFromHeader != Input.size() || TotalFromHeader > dst1::MAX_TRANSCRIPT_INPUT) {
    return false;
  }

  return true;
}

std::optional<std::vector<uint8_t>> mutateTranscriptDeterministically(
    const std::vector<uint8_t> &Input) {
  auto Parsed = DST1Mutator::parse(Input);
  if (!Parsed) {
    return std::nullopt;
  }

  if (Parsed->ClientQuery.size() < 4) {
    return std::nullopt;
  }

  DST1Mutator::MutationRequest Request;
  DST1Mutator::QueryMutation Mutation;

  const uint16_t QueryFlags = readBe16(Parsed->ClientQuery, 2);
  Mutation.RD = (QueryFlags & 0x0100U) == 0;
  Request.Query = Mutation;

  auto Mutated = DST1Mutator::mutate(Input, Request);
  if (Mutated && *Mutated != Input) {
    return Mutated;
  }

  Mutation.RD.reset();
  Mutation.TC = (QueryFlags & 0x0200U) == 0;
  Request.Query = Mutation;
  Mutated = DST1Mutator::mutate(Input, Request);
  if (Mutated && *Mutated != Input) {
    return Mutated;
  }

  Mutation.TC.reset();
  Mutation.CD = (QueryFlags & 0x0010U) == 0;
  Request.Query = Mutation;
  Mutated = DST1Mutator::mutate(Input, Request);
  if (Mutated && *Mutated != Input) {
    return Mutated;
  }

  return std::nullopt;
}

Metrics runEvaluation(const SampleSet &Corpus, RunMode Mode) {
  Metrics Result;
  Result.Total = Corpus.Samples.size();

  for (const auto &Sample : Corpus.Samples) {
    std::vector<uint8_t> Candidate = Sample;
    if (Mode == RunMode::Mutator) {
      auto Mutated = mutateTranscriptDeterministically(Sample);
      if (Mutated) {
        Candidate = std::move(*Mutated);
        Result.MutationApplied += 1;
      }
    }

    if (checkHeaderAndLengthConsistency(Candidate)) {
      Result.HeaderPass += 1;
    }

    if (DST1Mutator::parse(Candidate).has_value()) {
      Result.ParsePass += 1;
    }
  }

  return Result;
}

double toRate(size_t Passed, size_t Total) {
  if (Total == 0) {
    return 0.0;
  }
  return (static_cast<double>(Passed) * 100.0) / static_cast<double>(Total);
}

std::optional<RunMode> parseModeFromArgs(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    const std::string Arg = argv[i];
    if (Arg == "--mode" && i + 1 < argc) {
      const std::string Mode = argv[++i];
      if (Mode == "baseline") {
        return RunMode::Baseline;
      }
      if (Mode == "mutator") {
        return RunMode::Mutator;
      }
      return std::nullopt;
    }
  }
  return RunMode::Mutator;
}

}

int main(int argc, char **argv) {
  auto ModeOpt = parseModeFromArgs(argc, argv);
  if (!ModeOpt) {
    std::cerr << "USAGE: test_dst1_mutator [--mode baseline|mutator]" << std::endl;
    return 2;
  }

  const RunMode Mode = *ModeOpt;
  const SampleSet Corpus = loadAutomaticCorpus();
  if (Corpus.Samples.empty()) {
    std::cerr << "[dst1-mutator-test] ERROR: 自动样本集为空" << std::endl;
    return 1;
  }

  const Metrics Stats = runEvaluation(Corpus, Mode);
  const double HeaderPassRate = toRate(Stats.HeaderPass, Stats.Total);
  const double ParsePassRate = toRate(Stats.ParsePass, Stats.Total);
  const double MutationAppliedRate = toRate(Stats.MutationApplied, Stats.Total);

  std::cout << "[dst1-mutator-test] mode="
            << (Mode == RunMode::Mutator ? "mutator" : "baseline") << std::endl;
  std::cout << "[dst1-mutator-test] corpus-source=" << Corpus.SourceTag << std::endl;
  std::cout << "[dst1-mutator-test] total-samples=" << Stats.Total << std::endl;
  std::cout << std::fixed << std::setprecision(2);
  std::cout << "[dst1-mutator-test] header-pass-rate=" << HeaderPassRate << "%"
            << " (" << Stats.HeaderPass << "/" << Stats.Total << ")" << std::endl;
  std::cout << "[dst1-mutator-test] parse-pass-rate=" << ParsePassRate << "%"
            << " (" << Stats.ParsePass << "/" << Stats.Total << ")" << std::endl;
  std::cout << "[dst1-mutator-test] mutation-applied-rate=" << MutationAppliedRate << "%"
            << " (" << Stats.MutationApplied << "/" << Stats.Total << ")" << std::endl;

  if (Stats.HeaderPass != Stats.Total) {
    std::cerr << "[dst1-mutator-test] ASSERT FAIL: header-pass-rate 必须为 100%" << std::endl;
    return 1;
  }

  if (ParsePassRate < 80.0) {
    std::cerr << "[dst1-mutator-test] ASSERT FAIL: parse-pass-rate 必须 >= 80%" << std::endl;
    return 1;
  }

  std::cout << "[dst1-mutator-test] ASSERT PASS: header-pass-rate == 100%" << std::endl;
  std::cout << "[dst1-mutator-test] ASSERT PASS: parse-pass-rate >= 80%" << std::endl;
  return 0;
}
