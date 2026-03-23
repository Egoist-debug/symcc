// DST1Transcript.h - Shared DST1 transcript specification
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GENINPUT_DST1TRANSCRIPT_H
#define GENINPUT_DST1TRANSCRIPT_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace geninput {
namespace dst1 {

inline constexpr std::array<uint8_t, 4> MAGIC = {'D', 'S', 'T', '1'};
inline constexpr uint8_t RESERVED_VALUE = 0;

inline constexpr size_t RESPONSE_COUNT_OFFSET = 4;
inline constexpr size_t RESERVED_OFFSET = 5;
inline constexpr size_t QUERY_LENGTH_OFFSET = 6;
inline constexpr size_t POST_CHECK_LENGTH_OFFSET = 8;
inline constexpr size_t RESPONSE_LENGTHS_OFFSET = 10;

inline constexpr size_t LENGTH_FIELD_SIZE = 2;
inline constexpr size_t MAX_RESPONSES = 16;
inline constexpr size_t MAX_TRANSCRIPT_INPUT = 16384;
inline constexpr size_t MAX_SEGMENT_LENGTH = 0xFFFF;

inline bool isLengthEncodable(size_t Length) {
  return Length <= MAX_SEGMENT_LENGTH;
}

inline size_t computePrefixSize(size_t ResponseCount) {
  return RESPONSE_LENGTHS_OFFSET + (ResponseCount * LENGTH_FIELD_SIZE);
}

inline bool validateSegments(const std::vector<uint8_t> &ClientQuery,
                             const std::vector<std::vector<uint8_t>> &Responses,
                             const std::vector<uint8_t> &PostCheckQuery) {
  if (ClientQuery.empty() || Responses.size() > MAX_RESPONSES ||
      !isLengthEncodable(ClientQuery.size()) ||
      !isLengthEncodable(PostCheckQuery.size())) {
    return false;
  }

  size_t TotalLength = computePrefixSize(Responses.size()) + ClientQuery.size() +
                       PostCheckQuery.size();

  for (const auto &Response : Responses) {
    if (Response.empty() || !isLengthEncodable(Response.size())) {
      return false;
    }
    TotalLength += Response.size();
  }

  return TotalLength <= MAX_TRANSCRIPT_INPUT;
}

inline void appendU16Le(std::vector<uint8_t> &Output, size_t Value) {
  Output.push_back(static_cast<uint8_t>(Value & 0xFF));
  Output.push_back(static_cast<uint8_t>((Value >> 8) & 0xFF));
}

inline std::optional<uint16_t> readU16Le(const std::vector<uint8_t> &Input,
                                         size_t Offset) {
  if (Offset + 1 >= Input.size()) {
    return std::nullopt;
  }

  return static_cast<uint16_t>(Input[Offset]) |
         (static_cast<uint16_t>(Input[Offset + 1]) << 8);
}

inline std::vector<uint8_t>
buildTranscript(const std::vector<uint8_t> &ClientQuery,
                const std::vector<std::vector<uint8_t>> &Responses,
                const std::vector<uint8_t> &PostCheckQuery) {
  if (!validateSegments(ClientQuery, Responses, PostCheckQuery)) {
    return {};
  }

  std::vector<uint8_t> Output;
  Output.reserve(computePrefixSize(Responses.size()) + ClientQuery.size() +
                 PostCheckQuery.size());

  Output.insert(Output.end(), MAGIC.begin(), MAGIC.end());
  Output.push_back(static_cast<uint8_t>(Responses.size()));
  Output.push_back(RESERVED_VALUE);
  appendU16Le(Output, ClientQuery.size());
  appendU16Le(Output, PostCheckQuery.size());
  for (const auto &Response : Responses) {
    appendU16Le(Output, Response.size());
  }

  Output.insert(Output.end(), ClientQuery.begin(), ClientQuery.end());
  for (const auto &Response : Responses) {
    Output.insert(Output.end(), Response.begin(), Response.end());
  }
  Output.insert(Output.end(), PostCheckQuery.begin(), PostCheckQuery.end());
  return Output;
}

} // namespace dst1
} // namespace geninput

#endif // GENINPUT_DST1TRANSCRIPT_H
