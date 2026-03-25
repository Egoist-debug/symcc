#include "../include/DST1Mutator.h"
#include "../include/DST1Transcript.h"
#include "../include/FormatAwareGenerator.h"

#include <algorithm>

namespace geninput {

namespace {

constexpr uint16_t DNS_FLAG_AA = 0x0400;
constexpr uint16_t DNS_FLAG_TC = 0x0200;
constexpr uint16_t DNS_FLAG_RD = 0x0100;
constexpr uint16_t DNS_FLAG_RA = 0x0080;
constexpr uint16_t DNS_FLAG_CD = 0x0010;

uint16_t readBe16(const std::vector<uint8_t> &Input, size_t Offset) {
  return (static_cast<uint16_t>(Input[Offset]) << 8) |
         static_cast<uint16_t>(Input[Offset + 1]);
}

uint32_t readBe32(const std::vector<uint8_t> &Input, size_t Offset) {
  return (static_cast<uint32_t>(Input[Offset]) << 24) |
         (static_cast<uint32_t>(Input[Offset + 1]) << 16) |
         (static_cast<uint32_t>(Input[Offset + 2]) << 8) |
         static_cast<uint32_t>(Input[Offset + 3]);
}

void writeBe16(std::vector<uint8_t> &Input, size_t Offset, uint16_t Value) {
  Input[Offset] = static_cast<uint8_t>((Value >> 8) & 0xFF);
  Input[Offset + 1] = static_cast<uint8_t>(Value & 0xFF);
}

std::optional<size_t> consumeDnsName(const std::vector<uint8_t> &Packet,
                                     size_t Offset) {
  size_t Position = Offset;
  size_t Guard = Packet.size();

  while (Position < Packet.size() && Guard > 0) {
    const uint8_t Len = Packet[Position];
    if ((Len & 0xC0) == 0xC0) {
      if (Position + 1 >= Packet.size()) {
        return std::nullopt;
      }
      return Position + 2;
    }

    if (Len == 0) {
      return Position + 1;
    }

    if (Len > 63 || Position + 1 + Len > Packet.size()) {
      return std::nullopt;
    }

    Position += 1 + Len;
    --Guard;
  }

  return std::nullopt;
}

struct ParsedQuestionInfo {
  size_t NameStart = 0;
  size_t NameEnd = 0;
  size_t TypeOffset = 0;
  size_t ClassOffset = 0;
  size_t EndOffset = 0;
  std::string Name;
  uint16_t Type = 0;
  uint16_t DnsClass = 0;
};

std::optional<ParsedQuestionInfo>
parseSingleQuestion(const std::vector<uint8_t> &Packet) {
  if (Packet.size() < 12 || readBe16(Packet, 4) != 1) {
    return std::nullopt;
  }

  ParsedQuestionInfo Info;
  Info.NameStart = 12;
  auto NameEnd = consumeDnsName(Packet, Info.NameStart);
  if (!NameEnd || *NameEnd + 4 > Packet.size()) {
    return std::nullopt;
  }

  Info.NameEnd = *NameEnd;
  Info.TypeOffset = *NameEnd;
  Info.ClassOffset = *NameEnd + 2;
  Info.EndOffset = *NameEnd + 4;
  Info.Name = DNSNameCodec::decode(Packet, Info.NameStart);
  Info.Type = readBe16(Packet, Info.TypeOffset);
  Info.DnsClass = readBe16(Packet, Info.ClassOffset);

  if (Info.Name.empty()) {
    return std::nullopt;
  }

  return Info;
}

struct RRInfo {
  size_t StartOffset = 0;
  size_t EndOffset = 0;
  uint16_t Type = 0;
  uint16_t DnsClass = 0;
  uint32_t TTL = 0;
};

std::optional<RRInfo> parseRRAt(const std::vector<uint8_t> &Packet,
                                size_t Offset) {
  RRInfo Info;
  Info.StartOffset = Offset;
  auto NameEnd = consumeDnsName(Packet, Offset);
  if (!NameEnd || *NameEnd + 10 > Packet.size()) {
    return std::nullopt;
  }

  Info.Type = readBe16(Packet, *NameEnd);
  Info.DnsClass = readBe16(Packet, *NameEnd + 2);
  Info.TTL = readBe32(Packet, *NameEnd + 4);
  const uint16_t RdLength = readBe16(Packet, *NameEnd + 8);
  const size_t RDataOffset = *NameEnd + 10;
  if (RDataOffset + RdLength > Packet.size()) {
    return std::nullopt;
  }

  Info.EndOffset = RDataOffset + RdLength;
  return Info;
}

bool isRRBlobWellFormed(const std::vector<uint8_t> &RRBlob) {
  auto Parsed = parseRRAt(RRBlob, 0);
  return Parsed.has_value() && Parsed->EndOffset == RRBlob.size();
}

bool haveMatchingQuestionIdentity(const ParsedQuestionInfo &Left,
                                  const ParsedQuestionInfo &Right) {
  return Left.Name == Right.Name && Left.Type == Right.Type &&
         Left.DnsClass == Right.DnsClass;
}

bool packetsHaveMatchingQuestionIdentity(const std::vector<uint8_t> &Left,
                                         const std::vector<uint8_t> &Right) {
  auto LeftQuestion = parseSingleQuestion(Left);
  auto RightQuestion = parseSingleQuestion(Right);
  return LeftQuestion.has_value() && RightQuestion.has_value() &&
         haveMatchingQuestionIdentity(*LeftQuestion, *RightQuestion);
}

struct ParsedResponseLayout {
  std::vector<uint8_t> Header;
  std::vector<uint8_t> QuestionBytes;
  std::vector<std::vector<uint8_t>> AnswerRRs;
  std::vector<std::vector<uint8_t>> AuthorityRRs;
  std::vector<std::vector<uint8_t>> AdditionalRRs;
};

std::optional<ParsedResponseLayout>
parseResponseLayout(const std::vector<uint8_t> &Packet) {
  if (Packet.size() < 12 || (Packet[2] & 0x80) == 0) {
    return std::nullopt;
  }

  const uint16_t QdCount = readBe16(Packet, 4);
  if (QdCount != 1) {
    return std::nullopt;
  }

  auto Question = parseSingleQuestion(Packet);
  if (!Question) {
    return std::nullopt;
  }

  ParsedResponseLayout Layout;
  Layout.Header.assign(Packet.begin(), Packet.begin() + 12);
  Layout.QuestionBytes.assign(Packet.begin() + 12, Packet.begin() + Question->EndOffset);

  size_t Cursor = Question->EndOffset;
  const uint16_t AnCount = readBe16(Packet, 6);
  const uint16_t NsCount = readBe16(Packet, 8);
  const uint16_t ArCount = readBe16(Packet, 10);

  auto parseSection = [&](uint16_t Count,
                          std::vector<std::vector<uint8_t>> &Output) -> bool {
    for (uint16_t I = 0; I < Count; ++I) {
      auto RR = parseRRAt(Packet, Cursor);
      if (!RR) {
        return false;
      }
      Output.emplace_back(Packet.begin() + RR->StartOffset,
                          Packet.begin() + RR->EndOffset);
      Cursor = RR->EndOffset;
    }
    return true;
  };

  if (!parseSection(AnCount, Layout.AnswerRRs) ||
      !parseSection(NsCount, Layout.AuthorityRRs) ||
      !parseSection(ArCount, Layout.AdditionalRRs) || Cursor != Packet.size()) {
    return std::nullopt;
  }

  return Layout;
}

bool responsePacketMatchesQuery(const std::vector<uint8_t> &Response,
                                const std::vector<uint8_t> &Query) {
  return parseResponseLayout(Response).has_value() &&
         packetsHaveMatchingQuestionIdentity(Response, Query);
}

bool responseSetMatchesQuery(const std::vector<std::vector<uint8_t>> &Responses,
                             const std::vector<uint8_t> &Query) {
  return std::all_of(Responses.begin(), Responses.end(),
                     [&](const auto &Response) {
                       return responsePacketMatchesQuery(Response, Query);
                     });
}

DST1Mutator::QueryMutation &
ensureQueryMutation(DST1Mutator::MutationRequest &Request) {
  if (!Request.Query.has_value()) {
    Request.Query.emplace();
  }
  return *Request.Query;
}

DST1Mutator::ResponseMutation &
ensureResponseMutation(DST1Mutator::MutationRequest &Request) {
  if (!Request.Response.has_value()) {
    Request.Response.emplace();
  }
  return *Request.Response;
}

DST1Mutator::TranscriptMutation &
ensureTranscriptMutation(DST1Mutator::MutationRequest &Request) {
  if (!Request.Transcript.has_value()) {
    Request.Transcript.emplace();
  }
  return *Request.Transcript;
}

bool applyDonorMutationFamily(const DST1Mutator::Transcript &Target,
                              const DST1Mutator::Transcript &Donor,
                              DST1Mutator::MutationRequest &Request) {
  if (!Request.DonorFamily.has_value()) {
    return false;
  }

  switch (*Request.DonorFamily) {
  case DST1Mutator::DonorMutationFamily::ResponseSpliceSameIndex: {
    if (Request.ResponseIndex >= Target.Responses.size() ||
        Request.ResponseIndex >= Donor.Responses.size()) {
      return false;
    }

    const auto &Candidate = Donor.Responses[Request.ResponseIndex];
    if (!responsePacketMatchesQuery(Candidate, Target.ClientQuery)) {
      return false;
    }

    ensureResponseMutation(Request).Packet = Candidate;
    return true;
  }

  case DST1Mutator::DonorMutationFamily::AuthorityTransplant: {
    if (Request.ResponseIndex >= Target.Responses.size() ||
        Request.ResponseIndex >= Donor.Responses.size()) {
      return false;
    }

    const auto &Candidate = Donor.Responses[Request.ResponseIndex];
    auto Layout = parseResponseLayout(Candidate);
    if (!Layout || !responsePacketMatchesQuery(Candidate, Target.ClientQuery)) {
      return false;
    }

    auto &Mutation = ensureResponseMutation(Request);
    Mutation.AuthorityRRs = Layout->AuthorityRRs;
    Mutation.NSCOUNT = static_cast<uint16_t>(Layout->AuthorityRRs.size());
    return true;
  }

  case DST1Mutator::DonorMutationFamily::AdditionalOrGlueTransplant: {
    if (Request.ResponseIndex >= Target.Responses.size() ||
        Request.ResponseIndex >= Donor.Responses.size()) {
      return false;
    }

    const auto &Candidate = Donor.Responses[Request.ResponseIndex];
    auto Layout = parseResponseLayout(Candidate);
    if (!Layout || !responsePacketMatchesQuery(Candidate, Target.ClientQuery)) {
      return false;
    }

    auto &Mutation = ensureResponseMutation(Request);
    Mutation.AdditionalRRs = Layout->AdditionalRRs;
    Mutation.GlueRRs.reset();
    Mutation.ARCOUNT = static_cast<uint16_t>(Layout->AdditionalRRs.size());
    return true;
  }

  case DST1Mutator::DonorMutationFamily::ResponseCountExpandOrShrinkFromDonor: {
    std::vector<std::vector<uint8_t>> Replacement = Target.Responses;
    const size_t DonorCount = Donor.Responses.size();

    if (DonorCount < Replacement.size()) {
      Replacement.resize(DonorCount);
    } else if (DonorCount > Replacement.size()) {
      std::vector<std::vector<uint8_t>> Appended(
          Donor.Responses.begin() + Replacement.size(), Donor.Responses.end());
      if (!responseSetMatchesQuery(Appended, Target.ClientQuery)) {
        return false;
      }
      Replacement.insert(Replacement.end(), Appended.begin(), Appended.end());
    }

    auto &Mutation = ensureTranscriptMutation(Request);
    Mutation.Responses = std::move(Replacement);
    Mutation.ResponseCount = static_cast<uint8_t>(DonorCount);
    return true;
  }

  case DST1Mutator::DonorMutationFamily::PostCheckCoupledNameOrTypeShift: {
    auto DonorQuery = parseSingleQuestion(Donor.ClientQuery);
    if (!DonorQuery ||
        !packetsHaveMatchingQuestionIdentity(Donor.ClientQuery,
                                             Donor.PostCheckQuery)) {
      return false;
    }

    auto &Query = ensureQueryMutation(Request);
    Query.QNAME = DonorQuery->Name;
    Query.QTYPE = DonorQuery->Type;

    auto &Transcript = ensureTranscriptMutation(Request);
    Transcript.PostCheckName = DonorQuery->Name;
    Transcript.PostCheckType = DonorQuery->Type;
    return true;
  }
  }

  return false;
}

std::optional<std::vector<uint8_t>>
buildResponsePacket(const ParsedResponseLayout &Layout) {
  if (Layout.Header.size() != 12 || Layout.QuestionBytes.empty()) {
    return std::nullopt;
  }

  std::vector<uint8_t> Packet;
  Packet.reserve(Layout.Header.size() + Layout.QuestionBytes.size());
  Packet.insert(Packet.end(), Layout.Header.begin(), Layout.Header.end());

  writeBe16(Packet, 4, 1);
  writeBe16(Packet, 6, static_cast<uint16_t>(Layout.AnswerRRs.size()));
  writeBe16(Packet, 8, static_cast<uint16_t>(Layout.AuthorityRRs.size()));
  writeBe16(Packet, 10, static_cast<uint16_t>(Layout.AdditionalRRs.size()));

  Packet.insert(Packet.end(), Layout.QuestionBytes.begin(), Layout.QuestionBytes.end());

  for (const auto &RR : Layout.AnswerRRs) {
    Packet.insert(Packet.end(), RR.begin(), RR.end());
  }
  for (const auto &RR : Layout.AuthorityRRs) {
    Packet.insert(Packet.end(), RR.begin(), RR.end());
  }
  for (const auto &RR : Layout.AdditionalRRs) {
    Packet.insert(Packet.end(), RR.begin(), RR.end());
  }

  return Packet;
}

std::optional<std::vector<uint8_t>>
applyQuestionMutation(const std::vector<uint8_t> &Packet,
                      const DST1Mutator::QueryMutation &Mutation) {
  auto Question = parseSingleQuestion(Packet);
  if (!Question) {
    return std::nullopt;
  }

  std::vector<uint8_t> Updated = Packet;

  if (Mutation.RD || Mutation.TC || Mutation.CD) {
    uint16_t Flags = readBe16(Updated, 2);
    if (Mutation.RD.has_value()) {
      Flags = Mutation.RD.value() ? static_cast<uint16_t>(Flags | DNS_FLAG_RD)
                                  : static_cast<uint16_t>(Flags & ~DNS_FLAG_RD);
    }
    if (Mutation.TC.has_value()) {
      Flags = Mutation.TC.value() ? static_cast<uint16_t>(Flags | DNS_FLAG_TC)
                                  : static_cast<uint16_t>(Flags & ~DNS_FLAG_TC);
    }
    if (Mutation.CD.has_value()) {
      Flags = Mutation.CD.value() ? static_cast<uint16_t>(Flags | DNS_FLAG_CD)
                                  : static_cast<uint16_t>(Flags & ~DNS_FLAG_CD);
    }
    writeBe16(Updated, 2, Flags);
  }

  if (Mutation.QTYPE.has_value()) {
    writeBe16(Updated, Question->TypeOffset, Mutation.QTYPE.value());
  }

  if (Mutation.QNAME.has_value()) {
    std::vector<uint8_t> NewQName = DNSNameCodec::encode(Mutation.QNAME.value());
    if (NewQName.empty()) {
      return std::nullopt;
    }

    std::vector<uint8_t> Rebuilt;
    Rebuilt.reserve(Updated.size() + NewQName.size());
    Rebuilt.insert(Rebuilt.end(), Updated.begin(), Updated.begin() + Question->NameStart);
    Rebuilt.insert(Rebuilt.end(), NewQName.begin(), NewQName.end());
    Rebuilt.insert(Rebuilt.end(), Updated.begin() + Question->NameEnd, Updated.end());
    Updated = std::move(Rebuilt);
  }

  auto Reparsed = parseSingleQuestion(Updated);
  if (!Reparsed) {
    return std::nullopt;
  }

  return Updated;
}

std::optional<std::vector<uint8_t>>
applyResponseMutation(const std::vector<uint8_t> &Packet,
                      const DST1Mutator::ResponseMutation &Mutation) {
  auto Layout = Mutation.Packet.has_value()
                    ? parseResponseLayout(Mutation.Packet.value())
                    : parseResponseLayout(Packet);
  if (!Layout) {
    return std::nullopt;
  }

  uint16_t Flags = readBe16(Layout->Header, 2);
  if (Mutation.AA.has_value()) {
    Flags = Mutation.AA.value() ? static_cast<uint16_t>(Flags | DNS_FLAG_AA)
                                : static_cast<uint16_t>(Flags & ~DNS_FLAG_AA);
  }
  if (Mutation.RA.has_value()) {
    Flags = Mutation.RA.value() ? static_cast<uint16_t>(Flags | DNS_FLAG_RA)
                                : static_cast<uint16_t>(Flags & ~DNS_FLAG_RA);
  }
  if (Mutation.RCODE.has_value()) {
    Flags = static_cast<uint16_t>((Flags & 0xFFF0) | (Mutation.RCODE.value() & 0x0F));
  }
  writeBe16(Layout->Header, 2, Flags);

  if (Mutation.AuthorityRRs.has_value()) {
    for (const auto &RR : Mutation.AuthorityRRs.value()) {
      if (!isRRBlobWellFormed(RR)) {
        return std::nullopt;
      }
    }
    Layout->AuthorityRRs = Mutation.AuthorityRRs.value();
  }

  if (Mutation.AdditionalRRs.has_value() || Mutation.GlueRRs.has_value()) {
    std::vector<std::vector<uint8_t>> Combined;
    if (Mutation.AdditionalRRs.has_value()) {
      for (const auto &RR : Mutation.AdditionalRRs.value()) {
        if (!isRRBlobWellFormed(RR)) {
          return std::nullopt;
        }
        Combined.push_back(RR);
      }
    }
    if (Mutation.GlueRRs.has_value()) {
      for (const auto &RR : Mutation.GlueRRs.value()) {
        if (!isRRBlobWellFormed(RR)) {
          return std::nullopt;
        }
        Combined.push_back(RR);
      }
    }
    Layout->AdditionalRRs = std::move(Combined);
  }

  auto trimOrReject = [](std::vector<std::vector<uint8_t>> &Section,
                         std::optional<uint16_t> Count) -> bool {
    if (!Count.has_value()) {
      return true;
    }
    if (Count.value() > Section.size()) {
      return false;
    }
    Section.resize(Count.value());
    return true;
  };

  if (!trimOrReject(Layout->AnswerRRs, Mutation.ANCOUNT) ||
      !trimOrReject(Layout->AuthorityRRs, Mutation.NSCOUNT) ||
      !trimOrReject(Layout->AdditionalRRs, Mutation.ARCOUNT)) {
    return std::nullopt;
  }

  if (Mutation.NSCOUNT.has_value() && Mutation.AuthorityRRs.has_value() &&
      Mutation.NSCOUNT.value() != Layout->AuthorityRRs.size()) {
    return std::nullopt;
  }
  if (Mutation.ARCOUNT.has_value() &&
      (Mutation.AdditionalRRs.has_value() || Mutation.GlueRRs.has_value()) &&
      Mutation.ARCOUNT.value() != Layout->AdditionalRRs.size()) {
    return std::nullopt;
  }

  auto Rebuilt = buildResponsePacket(*Layout);
  if (!Rebuilt || !parseResponseLayout(*Rebuilt).has_value()) {
    return std::nullopt;
  }

  return Rebuilt;
}

bool checkPostQueryNameAndType(const std::vector<uint8_t> &Query,
                               const std::vector<uint8_t> &PostCheckQuery) {
  auto Q = parseSingleQuestion(Query);
  auto P = parseSingleQuestion(PostCheckQuery);
  return Q.has_value() && P.has_value() && Q->Name == P->Name &&
         Q->Type == P->Type;
}

}

std::optional<DST1Mutator::Transcript>
DST1Mutator::parse(const std::vector<uint8_t> &Input) {
  if (Input.size() < dst1::computePrefixSize(0)) {
    return std::nullopt;
  }

  if (!std::equal(dst1::MAGIC.begin(), dst1::MAGIC.end(), Input.begin())) {
    return std::nullopt;
  }

  const uint8_t response_count = Input[dst1::RESPONSE_COUNT_OFFSET];
  if (response_count > dst1::MAX_RESPONSES ||
      Input[dst1::RESERVED_OFFSET] != dst1::RESERVED_VALUE) {
    return std::nullopt;
  }

  const size_t PrefixSize = dst1::computePrefixSize(response_count);
  if (PrefixSize > Input.size()) {
    return std::nullopt;
  }

  auto QueryLengthOpt = dst1::readU16Le(Input, dst1::QUERY_LENGTH_OFFSET);
  auto PostCheckLengthOpt =
      dst1::readU16Le(Input, dst1::POST_CHECK_LENGTH_OFFSET);
  if (!QueryLengthOpt || !PostCheckLengthOpt) {
    return std::nullopt;
  }

  std::vector<uint16_t> ResponseLengths;
  ResponseLengths.reserve(response_count);
  for (uint8_t I = 0; I < response_count; ++I) {
    auto Len = dst1::readU16Le(
        Input, dst1::RESPONSE_LENGTHS_OFFSET +
                   (static_cast<size_t>(I) * dst1::LENGTH_FIELD_SIZE));
    if (!Len) {
      return std::nullopt;
    }
    ResponseLengths.push_back(*Len);
  }

  size_t Cursor = PrefixSize;
  if (Cursor + *QueryLengthOpt > Input.size()) {
    return std::nullopt;
  }

  Transcript Parsed;
  Parsed.ClientQuery.assign(Input.begin() + Cursor,
                            Input.begin() + Cursor + *QueryLengthOpt);
  Cursor += *QueryLengthOpt;

  Parsed.Responses.reserve(response_count);
  for (uint16_t Length : ResponseLengths) {
    if (Cursor + Length > Input.size()) {
      return std::nullopt;
    }
    Parsed.Responses.emplace_back(Input.begin() + Cursor,
                                  Input.begin() + Cursor + Length);
    Cursor += Length;
  }

  if (Cursor + *PostCheckLengthOpt != Input.size()) {
    return std::nullopt;
  }

  Parsed.PostCheckQuery.assign(Input.begin() + Cursor, Input.end());

  if (!dst1::validateSegments(Parsed.ClientQuery, Parsed.Responses,
                              Parsed.PostCheckQuery)) {
    return std::nullopt;
  }

  return Parsed;
}

std::optional<std::vector<uint8_t>>
mutateTranscriptImpl(const std::vector<uint8_t> &Input,
                     const DST1Mutator::MutationRequest &Request) {
  auto Parsed = DST1Mutator::parse(Input);
  if (!Parsed) {
    return std::nullopt;
  }

  if (Request.Query.has_value()) {
    auto MutatedQuery = applyQuestionMutation(Parsed->ClientQuery, *Request.Query);
    if (!MutatedQuery) {
      return std::nullopt;
    }
    Parsed->ClientQuery = std::move(*MutatedQuery);
  }

  if (Request.Response.has_value()) {
    if (Request.ResponseIndex >= Parsed->Responses.size()) {
      return std::nullopt;
    }
    auto MutatedResponse =
        applyResponseMutation(Parsed->Responses[Request.ResponseIndex],
                              *Request.Response);
    if (!MutatedResponse) {
      return std::nullopt;
    }
    if (Request.Response->Packet.has_value() &&
        !responsePacketMatchesQuery(*MutatedResponse, Parsed->ClientQuery)) {
      return std::nullopt;
    }
    Parsed->Responses[Request.ResponseIndex] = std::move(*MutatedResponse);
  }

  if (Request.Transcript.has_value()) {
    const auto &Mutation = *Request.Transcript;
    if (Mutation.Responses.has_value()) {
      if (!responseSetMatchesQuery(Mutation.Responses.value(),
                                   Parsed->ClientQuery)) {
        return std::nullopt;
      }
      Parsed->Responses = Mutation.Responses.value();
    }

    if (Mutation.ResponseCount.has_value()) {
      const uint8_t response_count = Mutation.ResponseCount.value();
      if (response_count > Parsed->Responses.size()) {
        return std::nullopt;
      }
      Parsed->Responses.resize(response_count);
    }

    if (Mutation.PostCheckName.has_value() || Mutation.PostCheckType.has_value()) {
      DST1Mutator::QueryMutation PostMutation;
      PostMutation.QNAME = Mutation.PostCheckName;
      PostMutation.QTYPE = Mutation.PostCheckType;
      auto UpdatedPost = applyQuestionMutation(Parsed->PostCheckQuery, PostMutation);
      if (!UpdatedPost) {
        return std::nullopt;
      }
      Parsed->PostCheckQuery = std::move(*UpdatedPost);
    }
  }

  if (!checkPostQueryNameAndType(Parsed->ClientQuery, Parsed->PostCheckQuery)) {
    return std::nullopt;
  }

  auto Output = DST1Mutator::serialize(*Parsed);
  if (!Output) {
    return std::nullopt;
  }

  if (!DST1Mutator::parse(*Output).has_value()) {
    return std::nullopt;
  }

  return Output;
}

std::optional<std::vector<uint8_t>>
DST1Mutator::serialize(const Transcript &InputTranscript) {
  auto Output = dst1::buildTranscript(InputTranscript.ClientQuery,
                                      InputTranscript.Responses,
                                      InputTranscript.PostCheckQuery);
  if (Output.empty()) {
    return std::nullopt;
  }

  if (!parse(Output).has_value()) {
    return std::nullopt;
  }

  return Output;
}

std::optional<std::vector<uint8_t>>
DST1Mutator::mutate(const std::vector<uint8_t> &Input,
                    const MutationRequest &Request) {
  return mutateTranscriptImpl(Input, Request);
}

std::optional<std::vector<uint8_t>>
DST1Mutator::mutate(const std::vector<uint8_t> &Input,
                    const MutationRequest &Request,
                    const std::vector<uint8_t> &DonorInput) {
  auto Donor = parse(DonorInput);
  if (!Donor || !Request.DonorFamily.has_value()) {
    return mutateTranscriptImpl(Input, Request);
  }

  auto Target = parse(Input);
  if (!Target) {
    return std::nullopt;
  }

  MutationRequest EffectiveRequest = Request;
  const bool DonorApplied =
      applyDonorMutationFamily(*Target, *Donor, EffectiveRequest);
  if (!DonorApplied) {
    return mutateTranscriptImpl(Input, Request);
  }

  auto DonorEnhanced = mutateTranscriptImpl(Input, EffectiveRequest);
  if (DonorEnhanced) {
    return DonorEnhanced;
  }

  return mutateTranscriptImpl(Input, Request);
}

}
