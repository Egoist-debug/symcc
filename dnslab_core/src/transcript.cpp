#include "dnslab_core/transcript.hpp"

#include "DST1Mutator.h"

#include <array>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <vector>

namespace dnslab {

namespace {

inline uint32_t leftRotate(uint32_t Value, int Shift) {
  return (Value << Shift) | (Value >> (32 - Shift));
}

std::array<uint32_t, 5> computeSha1Words(const std::vector<uint8_t> &Input) {
  std::vector<uint8_t> Buffer(Input.begin(), Input.end());
  const uint64_t BitLength = static_cast<uint64_t>(Buffer.size()) * 8U;
  Buffer.push_back(0x80);
  while ((Buffer.size() % 64U) != 56U) {
    Buffer.push_back(0x00);
  }
  for (int Index = 7; Index >= 0; --Index) {
    Buffer.push_back(static_cast<uint8_t>((BitLength >> (Index * 8)) & 0xffU));
  }

  uint32_t H0 = 0x67452301U;
  uint32_t H1 = 0xEFCDAB89U;
  uint32_t H2 = 0x98BADCFEU;
  uint32_t H3 = 0x10325476U;
  uint32_t H4 = 0xC3D2E1F0U;

  for (size_t Offset = 0; Offset < Buffer.size(); Offset += 64U) {
    uint32_t Words[80] = {0};
    for (size_t Index = 0; Index < 16U; ++Index) {
      const size_t Base = Offset + (Index * 4U);
      Words[Index] = (static_cast<uint32_t>(Buffer[Base]) << 24) |
                     (static_cast<uint32_t>(Buffer[Base + 1]) << 16) |
                     (static_cast<uint32_t>(Buffer[Base + 2]) << 8) |
                     static_cast<uint32_t>(Buffer[Base + 3]);
    }
    for (size_t Index = 16; Index < 80U; ++Index) {
      Words[Index] = leftRotate(Words[Index - 3] ^ Words[Index - 8] ^
                                    Words[Index - 14] ^ Words[Index - 16],
                                1);
    }

    uint32_t A = H0;
    uint32_t B = H1;
    uint32_t C = H2;
    uint32_t D = H3;
    uint32_t E = H4;

    for (size_t Index = 0; Index < 80U; ++Index) {
      uint32_t F = 0;
      uint32_t K = 0;
      if (Index < 20U) {
        F = (B & C) | ((~B) & D);
        K = 0x5A827999U;
      } else if (Index < 40U) {
        F = B ^ C ^ D;
        K = 0x6ED9EBA1U;
      } else if (Index < 60U) {
        F = (B & C) | (B & D) | (C & D);
        K = 0x8F1BBCDCU;
      } else {
        F = B ^ C ^ D;
        K = 0xCA62C1D6U;
      }

      const uint32_t Temp =
          leftRotate(A, 5) + F + E + K + Words[Index];
      E = D;
      D = C;
      C = leftRotate(B, 30);
      B = A;
      A = Temp;
    }

    H0 += A;
    H1 += B;
    H2 += C;
    H3 += D;
    H4 += E;
  }

  return {H0, H1, H2, H3, H4};
}

} // namespace

std::optional<TranscriptView> parseTranscript(const std::vector<uint8_t> &Input) {
  const auto Parsed = geninput::DST1Mutator::parse(Input);
  if (!Parsed.has_value()) {
    return std::nullopt;
  }

  TranscriptView Output;
  Output.ClientQuery = Parsed->ClientQuery;
  Output.ForgedResponses = Parsed->Responses;
  Output.PostCheckQuery = Parsed->PostCheckQuery;
  return Output;
}

std::vector<uint8_t> serializeTranscript(const TranscriptView &Input) {
  geninput::DST1Mutator::Transcript Native;
  Native.ClientQuery = Input.ClientQuery;
  Native.Responses = Input.ForgedResponses;
  Native.PostCheckQuery = Input.PostCheckQuery;

  const auto Serialized = geninput::DST1Mutator::serialize(Native);
  if (!Serialized.has_value()) {
    return {};
  }
  return *Serialized;
}

TranscriptSummary summarizeTranscript(const TranscriptView &Input) {
  TranscriptSummary Output;
  Output.ResponseCount = Input.ForgedResponses.size();
  Output.ClientQuerySize = Input.ClientQuery.size();
  Output.PostCheckQuerySize = Input.PostCheckQuery.size();
  for (const auto &Response : Input.ForgedResponses) {
    Output.TotalResponseBytes += Response.size();
  }
  Output.TotalTranscriptBytes = Output.ClientQuerySize + Output.PostCheckQuerySize +
                                Output.TotalResponseBytes;
  return Output;
}

std::string sha1Hex(const std::vector<uint8_t> &Input) {
  const auto Words = computeSha1Words(Input);
  std::ostringstream Stream;
  Stream << std::hex << std::setfill('0');
  for (const uint32_t Word : Words) {
    Stream << std::setw(8) << Word;
  }
  return Stream.str();
}

SampleIdentity buildSampleIdentity(const std::string &QueueEventId,
                                   const std::vector<uint8_t> &SampleBytes) {
  SampleIdentity Output;
  Output.QueueEventId = QueueEventId;
  Output.SampleSha1 = sha1Hex(SampleBytes);
  Output.SampleSize = SampleBytes.size();
  Output.SampleId =
      QueueEventId + "__" + Output.SampleSha1.substr(0, 8);
  return Output;
}

} // namespace dnslab
