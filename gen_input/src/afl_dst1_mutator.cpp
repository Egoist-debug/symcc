// SPDX-License-Identifier: GPL-3.0-or-later

#include "../include/FormatAwareGenerator.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace geninput {

std::vector<uint8_t> DNSNameCodec::encode(const std::string &Name) {
  std::vector<uint8_t> Result;

  if (Name.empty()) {
    Result.push_back(0);
    return Result;
  }

  std::istringstream Stream(Name);
  std::string Label;
  while (std::getline(Stream, Label, '.')) {
    if (Label.empty()) {
      continue;
    }

    if (Label.size() > 63) {
      Label = Label.substr(0, 63);
    }

    Result.push_back(static_cast<uint8_t>(Label.size()));
    Result.insert(Result.end(), Label.begin(), Label.end());
  }

  Result.push_back(0);
  return Result;
}

std::string DNSNameCodec::decode(const std::vector<uint8_t> &Data, size_t Offset) {
  std::string Result;
  size_t Position = Offset;

  while (Position < Data.size()) {
    const uint8_t Length = Data[Position++];
    if (Length == 0) {
      break;
    }

    if ((Length & 0xC0) == 0xC0) {
      if (Position >= Data.size()) {
        break;
      }

      const size_t Pointer = ((Length & 0x3F) << 8) | Data[Position];
      if (Pointer >= Offset) {
        break;
      }

      if (!Result.empty()) {
        Result += ".";
      }
      Result += decode(Data, Pointer);
      break;
    }

    if (Position + Length > Data.size()) {
      break;
    }

    if (!Result.empty()) {
      Result += ".";
    }
    Result += std::string(Data.begin() + Position,
                          Data.begin() + Position + Length);
    Position += Length;
  }

  return Result;
}

bool DNSNameCodec::hasCompression(const std::vector<uint8_t> &Data,
                                  size_t Offset) {
  size_t Position = Offset;
  while (Position < Data.size()) {
    const uint8_t Length = Data[Position];
    if (Length == 0) {
      return false;
    }
    if ((Length & 0xC0) == 0xC0) {
      return true;
    }
    Position += 1 + Length;
  }

  return false;
}

size_t DNSNameCodec::getEncodedLength(const std::vector<uint8_t> &Data,
                                      size_t Offset) {
  size_t Position = Offset;
  while (Position < Data.size()) {
    const uint8_t Length = Data[Position++];
    if (Length == 0) {
      break;
    }
    if ((Length & 0xC0) == 0xC0) {
      ++Position;
      break;
    }
    Position += Length;
  }

  return Position - Offset;
}

}

#include "DST1Mutator.cpp"

namespace geninput {
namespace {

struct AFLDST1MutatorState {
  std::mt19937 Rng;
  std::vector<unsigned char> Output;

  explicit AFLDST1MutatorState(unsigned int Seed) : Rng(Seed) {}
};

constexpr std::array<uint16_t, 9> QUERY_TYPE_CHOICES = {
    1, 2, 5, 6, 12, 15, 16, 28, 33,
};

constexpr std::array<const char *, 6> QNAME_LABEL_CHOICES = {
    "www", "ns1", "edge", "cache", "alt", "mail",
};

std::vector<std::string> splitLabels(const std::string &Name) {
  std::vector<std::string> Labels;
  std::istringstream Stream(Name);
  std::string Label;

  while (std::getline(Stream, Label, '.')) {
    if (!Label.empty()) {
      Labels.push_back(Label);
    }
  }

  return Labels;
}

std::string joinLabels(const std::vector<std::string> &Labels) {
  std::string Result;
  for (size_t Index = 0; Index < Labels.size(); ++Index) {
    if (Index != 0) {
      Result += ".";
    }
    Result += Labels[Index];
  }
  return Result;
}

std::string buildQnameVariant(const std::string &CurrentName, std::mt19937 &Rng) {
  std::vector<std::string> Labels = splitLabels(CurrentName);
  if (Labels.empty()) {
    return "alt.test";
  }

  std::uniform_int_distribution<size_t> OffsetDist(0,
                                                   QNAME_LABEL_CHOICES.size() - 1);
  const size_t Start = OffsetDist(Rng);
  for (size_t Step = 0; Step < QNAME_LABEL_CHOICES.size(); ++Step) {
    const std::string Candidate =
        QNAME_LABEL_CHOICES[(Start + Step) % QNAME_LABEL_CHOICES.size()];
    if (Candidate != Labels.front()) {
      Labels.front() = Candidate;
      return joinLabels(Labels);
    }
  }

  Labels.front() = Labels.front().size() < 63 ? Labels.front() + "-x" : "alt";
  return joinLabels(Labels);
}

uint16_t pickDifferentQueryType(uint16_t CurrentType, std::mt19937 &Rng) {
  std::uniform_int_distribution<size_t> Dist(0, QUERY_TYPE_CHOICES.size() - 1);
  for (size_t Attempt = 0; Attempt < QUERY_TYPE_CHOICES.size(); ++Attempt) {
    const uint16_t Candidate = QUERY_TYPE_CHOICES[Dist(Rng)];
    if (Candidate != CurrentType) {
      return Candidate;
    }
  }

  return CurrentType == 1 ? 28 : 1;
}

uint8_t pickDifferentRcode(uint8_t CurrentRcode, std::mt19937 &Rng) {
  std::uniform_int_distribution<int> Dist(0, 15);
  for (size_t Attempt = 0; Attempt < 16; ++Attempt) {
    const uint8_t Candidate = static_cast<uint8_t>(Dist(Rng));
    if (Candidate != CurrentRcode) {
      return Candidate;
    }
  }

  return static_cast<uint8_t>((CurrentRcode + 1) & 0x0F);
}

size_t storeOutput(AFLDST1MutatorState &State,
                   const std::vector<uint8_t> &Bytes,
                   size_t MaxSize,
                   unsigned char **OutBuf) {
  if (OutBuf == nullptr || MaxSize == 0) {
    return 0;
  }

  const size_t OutputSize = std::min(Bytes.size(), MaxSize);
  State.Output.assign(Bytes.begin(), Bytes.begin() + OutputSize);
  *OutBuf = State.Output.empty() ? nullptr : State.Output.data();
  return State.Output.size();
}

std::optional<DST1Mutator::MutationRequest>
buildMutationRequest(const DST1Mutator::Transcript &Transcript, std::mt19937 &Rng) {
  auto Question = parseSingleQuestion(Transcript.ClientQuery);
  if (!Question) {
    return std::nullopt;
  }

  std::uniform_int_distribution<int> OperationDist(0, 4);
  DST1Mutator::MutationRequest Request;

  switch (OperationDist(Rng)) {
  case 0: {
    DST1Mutator::QueryMutation Mutation;
    const uint16_t Flags = readBe16(Transcript.ClientQuery, 2);
    std::uniform_int_distribution<int> FlagDist(0, 2);

    switch (FlagDist(Rng)) {
    case 0:
      Mutation.RD = (Flags & DNS_FLAG_RD) == 0;
      break;
    case 1:
      Mutation.TC = (Flags & DNS_FLAG_TC) == 0;
      break;
    default:
      Mutation.CD = (Flags & DNS_FLAG_CD) == 0;
      break;
    }

    Request.Query = Mutation;
    return Request;
  }
  case 1: {
    const uint16_t NewType = pickDifferentQueryType(Question->Type, Rng);
    DST1Mutator::QueryMutation QueryMutation;
    DST1Mutator::TranscriptMutation TranscriptMutation;

    QueryMutation.QTYPE = NewType;
    TranscriptMutation.PostCheckType = NewType;
    Request.Query = QueryMutation;
    Request.Transcript = TranscriptMutation;
    return Request;
  }
  case 2: {
    const std::string NewName = buildQnameVariant(Question->Name, Rng);
    DST1Mutator::QueryMutation QueryMutation;
    DST1Mutator::TranscriptMutation TranscriptMutation;

    QueryMutation.QNAME = NewName;
    TranscriptMutation.PostCheckName = NewName;
    Request.Query = QueryMutation;
    Request.Transcript = TranscriptMutation;
    return Request;
  }
  case 3: {
    if (Transcript.Responses.empty()) {
      return std::nullopt;
    }

    std::uniform_int_distribution<size_t> ResponseDist(
        0, Transcript.Responses.size() - 1);
    Request.ResponseIndex = ResponseDist(Rng);

    auto Layout = parseResponseLayout(Transcript.Responses[Request.ResponseIndex]);
    if (!Layout) {
      return std::nullopt;
    }

    DST1Mutator::ResponseMutation Mutation;
    const uint16_t Flags = readBe16(Layout->Header, 2);
    std::uniform_int_distribution<int> ResponseOpDist(0, 4);

    switch (ResponseOpDist(Rng)) {
    case 0:
      Mutation.AA = (Flags & DNS_FLAG_AA) == 0;
      break;
    case 1:
      Mutation.RA = (Flags & DNS_FLAG_RA) == 0;
      break;
    case 2:
      Mutation.RCODE = pickDifferentRcode(static_cast<uint8_t>(Flags & 0x0F), Rng);
      break;
    case 3: {
      if (Layout->AnswerRRs.empty()) {
        return std::nullopt;
      }
      std::uniform_int_distribution<size_t> CountDist(0,
                                                      Layout->AnswerRRs.size() - 1);
      Mutation.ANCOUNT = static_cast<uint16_t>(CountDist(Rng));
      break;
    }
    default: {
      const bool HasAuthority = !Layout->AuthorityRRs.empty();
      const bool HasAdditional = !Layout->AdditionalRRs.empty();
      if (!HasAuthority && !HasAdditional) {
        return std::nullopt;
      }

      if (HasAuthority && !HasAdditional) {
        std::uniform_int_distribution<size_t> CountDist(
            0, Layout->AuthorityRRs.size() - 1);
        Mutation.NSCOUNT = static_cast<uint16_t>(CountDist(Rng));
      } else if (!HasAuthority && HasAdditional) {
        std::uniform_int_distribution<size_t> CountDist(
            0, Layout->AdditionalRRs.size() - 1);
        Mutation.ARCOUNT = static_cast<uint16_t>(CountDist(Rng));
      } else {
        std::uniform_int_distribution<int> SectionDist(0, 1);
        if (SectionDist(Rng) == 0) {
          std::uniform_int_distribution<size_t> CountDist(
              0, Layout->AuthorityRRs.size() - 1);
          Mutation.NSCOUNT = static_cast<uint16_t>(CountDist(Rng));
        } else {
          std::uniform_int_distribution<size_t> CountDist(
              0, Layout->AdditionalRRs.size() - 1);
          Mutation.ARCOUNT = static_cast<uint16_t>(CountDist(Rng));
        }
      }
      break;
    }
    }

    Request.Response = Mutation;
    return Request;
  }
  default: {
    if (Transcript.Responses.empty()) {
      return std::nullopt;
    }

    DST1Mutator::TranscriptMutation Mutation;
    std::uniform_int_distribution<size_t> CountDist(0,
                                                    Transcript.Responses.size() - 1);
    Mutation.ResponseCount = static_cast<uint8_t>(CountDist(Rng));
    Request.Transcript = Mutation;
    return Request;
  }
  }
}

std::optional<std::vector<uint8_t>> mutateTranscript(const std::vector<uint8_t> &Input,
                                                     size_t MaxSize,
                                                     std::mt19937 &Rng) {
  auto Transcript = DST1Mutator::parse(Input);
  if (!Transcript) {
    return std::nullopt;
  }

  for (size_t Attempt = 0; Attempt < 16; ++Attempt) {
    auto Request = buildMutationRequest(*Transcript, Rng);
    if (!Request) {
      continue;
    }

    auto Mutated = DST1Mutator::mutate(Input, *Request);
    if (!Mutated || Mutated->empty() || Mutated->size() > MaxSize ||
        *Mutated == Input) {
      continue;
    }

    return Mutated;
  }

  return std::nullopt;
}

}
}

extern "C" __attribute__((visibility("default"))) void *
afl_custom_init(void *AflState, unsigned int Seed) {
  (void)AflState;
  return new geninput::AFLDST1MutatorState(Seed);
}

extern "C" __attribute__((visibility("default"))) size_t afl_custom_fuzz(
    void *Data,
    unsigned char *Buf,
    size_t BufSize,
    unsigned char **OutBuf,
    unsigned char *AddBuf,
    size_t AddBufSize,
    size_t MaxSize) {
  (void)AddBuf;
  (void)AddBufSize;

  auto *State = static_cast<geninput::AFLDST1MutatorState *>(Data);
  if (State == nullptr || Buf == nullptr || BufSize == 0) {
    return 0;
  }

  std::vector<uint8_t> Input(Buf, Buf + BufSize);
  auto Mutated = geninput::mutateTranscript(Input, MaxSize, State->Rng);
  if (Mutated) {
    return geninput::storeOutput(*State, *Mutated, MaxSize, OutBuf);
  }

  return geninput::storeOutput(*State, Input, MaxSize, OutBuf);
}

extern "C" __attribute__((visibility("default"))) void afl_custom_deinit(
    void *Data) {
  delete static_cast<geninput::AFLDST1MutatorState *>(Data);
}
