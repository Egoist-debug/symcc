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

inline uint32_t rightRotate(uint32_t Value, int Shift) {
  return (Value >> Shift) | (Value << (32 - Shift));
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

std::array<uint32_t, 8> computeSha256Words(const std::vector<uint8_t> &Input) {
  static constexpr std::array<uint32_t, 64> K = {
      0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
      0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
      0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
      0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
      0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
      0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
      0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
      0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
      0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
      0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
      0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
      0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
      0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
      0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
      0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
      0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

  std::vector<uint8_t> Buffer(Input.begin(), Input.end());
  const uint64_t BitLength = static_cast<uint64_t>(Buffer.size()) * 8U;
  Buffer.push_back(0x80U);
  while ((Buffer.size() % 64U) != 56U) {
    Buffer.push_back(0x00U);
  }
  for (int Index = 7; Index >= 0; --Index) {
    Buffer.push_back(static_cast<uint8_t>((BitLength >> (Index * 8)) & 0xffU));
  }

  std::array<uint32_t, 8> H = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U,
                               0xa54ff53aU, 0x510e527fU, 0x9b05688cU,
                               0x1f83d9abU, 0x5be0cd19U};
  for (size_t Offset = 0; Offset < Buffer.size(); Offset += 64U) {
    std::array<uint32_t, 64> Words = {};
    for (size_t Index = 0; Index < 16U; ++Index) {
      const size_t Base = Offset + (Index * 4U);
      Words[Index] = (static_cast<uint32_t>(Buffer[Base]) << 24U) |
                     (static_cast<uint32_t>(Buffer[Base + 1]) << 16U) |
                     (static_cast<uint32_t>(Buffer[Base + 2]) << 8U) |
                     static_cast<uint32_t>(Buffer[Base + 3]);
    }
    for (size_t Index = 16; Index < 64U; ++Index) {
      const uint32_t S0 = rightRotate(Words[Index - 15], 7) ^
                          rightRotate(Words[Index - 15], 18) ^
                          (Words[Index - 15] >> 3U);
      const uint32_t S1 = rightRotate(Words[Index - 2], 17) ^
                          rightRotate(Words[Index - 2], 19) ^
                          (Words[Index - 2] >> 10U);
      Words[Index] = Words[Index - 16] + S0 + Words[Index - 7] + S1;
    }

    uint32_t A = H[0];
    uint32_t B = H[1];
    uint32_t C = H[2];
    uint32_t D = H[3];
    uint32_t E = H[4];
    uint32_t F = H[5];
    uint32_t G = H[6];
    uint32_t T = H[7];
    for (size_t Index = 0; Index < 64U; ++Index) {
      const uint32_t S1 = rightRotate(E, 6) ^ rightRotate(E, 11) ^
                          rightRotate(E, 25);
      const uint32_t Choice = (E & F) ^ ((~E) & G);
      const uint32_t Temp1 = T + S1 + Choice + K[Index] + Words[Index];
      const uint32_t S0 = rightRotate(A, 2) ^ rightRotate(A, 13) ^
                          rightRotate(A, 22);
      const uint32_t Majority = (A & B) ^ (A & C) ^ (B & C);
      const uint32_t Temp2 = S0 + Majority;
      T = G;
      G = F;
      F = E;
      E = D + Temp1;
      D = C;
      C = B;
      B = A;
      A = Temp1 + Temp2;
    }

    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
    H[4] += E;
    H[5] += F;
    H[6] += G;
    H[7] += T;
  }
  return H;
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

std::string sha256Hex(const std::vector<uint8_t> &Input) {
  const auto Words = computeSha256Words(Input);
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
