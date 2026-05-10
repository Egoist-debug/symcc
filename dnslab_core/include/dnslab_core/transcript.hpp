#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dnslab {

struct TranscriptView {
  std::vector<uint8_t> ClientQuery;
  std::vector<std::vector<uint8_t>> ForgedResponses;
  std::vector<uint8_t> PostCheckQuery;
};

struct TranscriptSummary {
  size_t ResponseCount = 0;
  size_t ClientQuerySize = 0;
  size_t PostCheckQuerySize = 0;
  size_t TotalResponseBytes = 0;
  size_t TotalTranscriptBytes = 0;
};

struct SampleIdentity {
  std::string QueueEventId;
  std::string SampleSha1;
  std::string SampleId;
  size_t SampleSize = 0;
};

std::optional<TranscriptView> parseTranscript(const std::vector<uint8_t> &Input);
std::vector<uint8_t> serializeTranscript(const TranscriptView &Input);
TranscriptSummary summarizeTranscript(const TranscriptView &Input);

std::string sha1Hex(const std::vector<uint8_t> &Input);
SampleIdentity buildSampleIdentity(const std::string &QueueEventId,
                                   const std::vector<uint8_t> &SampleBytes);

} // namespace dnslab
