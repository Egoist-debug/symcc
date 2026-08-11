#include "../include/DST1Mutator.h"
#include "../include/DST1Transcript.h"
#include "../include/FormatAwareGenerator.h"

#include <algorithm>
#include <cctype>
#include <set>

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

struct ParsedDnsName {
  size_t WireEnd = 0;
  std::string CanonicalName;
};

struct DnsNameParseResult {
  std::optional<ParsedDnsName> Name;
  bool InvalidCompressionPointer = false;
};

DnsNameParseResult parseDnsName(const std::vector<uint8_t> &Packet,
                                size_t Offset) {
  size_t Position = Offset;
  size_t WireEnd = Offset;
  size_t DecodedLength = 0;
  bool Jumped = false;
  std::set<size_t> VisitedPointers;
  std::string Name;

  for (size_t Step = 0; Step <= Packet.size(); ++Step) {
    if (Position >= Packet.size()) {
      return {};
    }

    const uint8_t Len = Packet[Position];
    if ((Len & 0xC0) == 0xC0) {
      if (Position + 1 >= Packet.size()) {
        DnsNameParseResult Result;
        Result.InvalidCompressionPointer = true;
        return Result;
      }

      const size_t Target =
          (static_cast<size_t>(Len & 0x3F) << 8) | Packet[Position + 1];
      if (Target >= Position || Target >= Packet.size() ||
          !VisitedPointers.insert(Target).second) {
        DnsNameParseResult Result;
        Result.InvalidCompressionPointer = true;
        return Result;
      }

      if (!Jumped) {
        WireEnd = Position + 2;
      }
      Position = Target;
      Jumped = true;
      continue;
    }

    if ((Len & 0xC0) != 0 || Len > 63) {
      return {};
    }

    if (Len == 0) {
      if (!Jumped) {
        WireEnd = Position + 1;
      }
      DnsNameParseResult Result;
      Result.Name = ParsedDnsName{WireEnd, Name};
      return Result;
    }

    if (Position + 1 + Len > Packet.size() ||
        DecodedLength + static_cast<size_t>(Len) + 1 > 255) {
      return {};
    }

    if (!Name.empty()) {
      Name.push_back('.');
    }
    for (size_t Index = 0; Index < Len; ++Index) {
      Name.push_back(static_cast<char>(std::tolower(
          static_cast<unsigned char>(Packet[Position + 1 + Index]))));
    }
    DecodedLength += static_cast<size_t>(Len) + 1;
    Position += 1 + Len;
    if (!Jumped) {
      WireEnd = Position;
    }
  }

  DnsNameParseResult Result;
  Result.InvalidCompressionPointer = true;
  return Result;
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
parseSingleQuestion(const std::vector<uint8_t> &Packet,
                    bool *InvalidCompressionPointer = nullptr) {
  if (Packet.size() < 12 || readBe16(Packet, 4) != 1) {
    return std::nullopt;
  }

  ParsedQuestionInfo Info;
  Info.NameStart = 12;
  auto ParsedName = parseDnsName(Packet, Info.NameStart);
  if (!ParsedName.Name || ParsedName.Name->WireEnd + 4 > Packet.size()) {
    if (InvalidCompressionPointer != nullptr) {
      *InvalidCompressionPointer = ParsedName.InvalidCompressionPointer;
    }
    return std::nullopt;
  }

  Info.NameEnd = ParsedName.Name->WireEnd;
  Info.TypeOffset = ParsedName.Name->WireEnd;
  Info.ClassOffset = ParsedName.Name->WireEnd + 2;
  Info.EndOffset = ParsedName.Name->WireEnd + 4;
  Info.Name = ParsedName.Name->CanonicalName;
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
                                size_t Offset,
                                bool *InvalidCompressionPointer = nullptr) {
  RRInfo Info;
  Info.StartOffset = Offset;
  auto ParsedName = parseDnsName(Packet, Offset);
  if (!ParsedName.Name || ParsedName.Name->WireEnd + 10 > Packet.size()) {
    if (InvalidCompressionPointer != nullptr) {
      *InvalidCompressionPointer = ParsedName.InvalidCompressionPointer;
    }
    return std::nullopt;
  }

  Info.Type = readBe16(Packet, ParsedName.Name->WireEnd);
  Info.DnsClass = readBe16(Packet, ParsedName.Name->WireEnd + 2);
  Info.TTL = readBe32(Packet, ParsedName.Name->WireEnd + 4);
  const uint16_t RdLength = readBe16(Packet, ParsedName.Name->WireEnd + 8);
  const size_t RDataOffset = ParsedName.Name->WireEnd + 10;
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
parseResponseLayout(const std::vector<uint8_t> &Packet,
                    bool *InvalidCompressionPointer = nullptr) {
  if (Packet.size() < 12 || (Packet[2] & 0x80) == 0) {
    return std::nullopt;
  }

  const uint16_t QdCount = readBe16(Packet, 4);
  if (QdCount != 1) {
    return std::nullopt;
  }

  bool QuestionPointerInvalid = false;
  auto Question = parseSingleQuestion(Packet, &QuestionPointerInvalid);
  if (!Question) {
    if (InvalidCompressionPointer != nullptr) {
      *InvalidCompressionPointer = QuestionPointerInvalid;
    }
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
      bool OwnerPointerInvalid = false;
      auto RR = parseRRAt(Packet, Cursor, &OwnerPointerInvalid);
      if (!RR) {
        if (InvalidCompressionPointer != nullptr) {
          *InvalidCompressionPointer = OwnerPointerInvalid;
        }
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
    auto Normalized =
        DST1Mutator::normalizeResponseForQuery(Candidate, Target.ClientQuery);
    if (!Normalized) {
      return false;
    }

    ensureResponseMutation(Request).Packet = std::move(*Normalized);
    return true;
  }

  case DST1Mutator::DonorMutationFamily::AuthorityTransplant: {
    if (Request.ResponseIndex >= Target.Responses.size() ||
        Request.ResponseIndex >= Donor.Responses.size()) {
      return false;
    }

    const auto &Candidate = Donor.Responses[Request.ResponseIndex];
    auto Layout = parseResponseLayout(Candidate);
    if (!Layout) {
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
    if (!Layout) {
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
      for (size_t Index = Replacement.size(); Index < Donor.Responses.size();
           ++Index) {
        auto Normalized = DST1Mutator::normalizeResponseForQuery(
            Donor.Responses[Index], Target.ClientQuery);
        if (!Normalized) {
          return false;
        }
        Replacement.push_back(std::move(*Normalized));
      }
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
                                             Donor.PostCheckQuery) ||
        !responseSetMatchesQuery(Donor.Responses, Donor.ClientQuery)) {
      return false;
    }

    auto &Query = ensureQueryMutation(Request);
    Query.QNAME = DonorQuery->Name;
    Query.QTYPE = DonorQuery->Type;

    auto &Transcript = ensureTranscriptMutation(Request);
    Transcript.PostCheckName = DonorQuery->Name;
    Transcript.PostCheckType = DonorQuery->Type;
    Transcript.Responses = Donor.Responses;
    Transcript.ResponseCount = static_cast<uint8_t>(Donor.Responses.size());
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

  if (Mutation.QCLASS.has_value()) {
    writeBe16(Updated, Question->ClassOffset, Mutation.QCLASS.value());
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

bool checkPostQueryIdentity(const std::vector<uint8_t> &Query,
                            const std::vector<uint8_t> &PostCheckQuery) {
  auto Q = parseSingleQuestion(Query);
  auto P = parseSingleQuestion(PostCheckQuery);
  return Q.has_value() && P.has_value() &&
         haveMatchingQuestionIdentity(*Q, *P);
}

DST1Mutator::ValidationResult
validationError(DST1Mutator::ValidationError Error,
                size_t ResponseIndex = std::numeric_limits<size_t>::max()) {
  DST1Mutator::ValidationResult Result;
  Result.Error = Error;
  Result.ResponseIndex = ResponseIndex;
  return Result;
}

std::optional<DST1Mutator::Transcript>
parseWireTranscript(const std::vector<uint8_t> &Input,
                    DST1Mutator::ValidationResult &Validation) {
  using Error = DST1Mutator::ValidationError;

  if (Input.size() > dst1::MAX_TRANSCRIPT_INPUT) {
    Validation = validationError(Error::InputTooLarge);
    return std::nullopt;
  }
  if (Input.size() < dst1::computePrefixSize(0)) {
    Validation = validationError(Error::InputTooShort);
    return std::nullopt;
  }
  if (!std::equal(dst1::MAGIC.begin(), dst1::MAGIC.end(), Input.begin())) {
    Validation = validationError(Error::InvalidMagic);
    return std::nullopt;
  }
  if (Input[dst1::RESERVED_OFFSET] != dst1::RESERVED_VALUE) {
    Validation = validationError(Error::InvalidReserved);
    return std::nullopt;
  }

  const uint8_t ResponseCount = Input[dst1::RESPONSE_COUNT_OFFSET];
  if (ResponseCount > dst1::MAX_RESPONSES) {
    Validation = validationError(Error::TooManyResponses);
    return std::nullopt;
  }

  const size_t PrefixSize = dst1::computePrefixSize(ResponseCount);
  if (PrefixSize > Input.size()) {
    Validation = validationError(Error::TruncatedLengthTable);
    return std::nullopt;
  }

  const auto QueryLength =
      dst1::readU16Le(Input, dst1::QUERY_LENGTH_OFFSET);
  const auto PostCheckLength =
      dst1::readU16Le(Input, dst1::POST_CHECK_LENGTH_OFFSET);
  if (!QueryLength || !PostCheckLength) {
    Validation = validationError(Error::TruncatedLengthTable);
    return std::nullopt;
  }
  if (*QueryLength == 0) {
    Validation = validationError(Error::EmptyQuery);
    return std::nullopt;
  }

  std::vector<uint16_t> ResponseLengths;
  ResponseLengths.reserve(ResponseCount);
  size_t ExpectedSize = PrefixSize + *QueryLength + *PostCheckLength;
  for (uint8_t Index = 0; Index < ResponseCount; ++Index) {
    const auto Length = dst1::readU16Le(
        Input, dst1::RESPONSE_LENGTHS_OFFSET +
                   static_cast<size_t>(Index) * dst1::LENGTH_FIELD_SIZE);
    if (!Length) {
      Validation = validationError(Error::TruncatedLengthTable, Index);
      return std::nullopt;
    }
    if (*Length == 0) {
      Validation = validationError(Error::EmptyResponse, Index);
      return std::nullopt;
    }
    ResponseLengths.push_back(*Length);
    ExpectedSize += *Length;
  }

  if (ExpectedSize != Input.size()) {
    Validation = validationError(Error::LengthMismatch);
    return std::nullopt;
  }

  DST1Mutator::Transcript Parsed;
  size_t Cursor = PrefixSize;
  Parsed.ClientQuery.assign(Input.begin() + Cursor,
                            Input.begin() + Cursor + *QueryLength);
  Cursor += *QueryLength;

  Parsed.Responses.reserve(ResponseCount);
  for (uint16_t Length : ResponseLengths) {
    Parsed.Responses.emplace_back(Input.begin() + Cursor,
                                  Input.begin() + Cursor + Length);
    Cursor += Length;
  }

  Parsed.PostCheckQuery.assign(Input.begin() + Cursor, Input.end());
  Validation = {};
  return Parsed;
}

bool isCompleteDnsQuery(const std::vector<uint8_t> &Packet,
                        ParsedQuestionInfo &Question,
                        bool &InvalidCompressionPointer) {
  auto Parsed = parseSingleQuestion(Packet, &InvalidCompressionPointer);
  if (!Parsed || Packet.size() < 12 || (Packet[2] & 0x80) != 0 ||
      readBe16(Packet, 4) != 1 || readBe16(Packet, 6) != 0 ||
      readBe16(Packet, 8) != 0 || readBe16(Packet, 10) != 0 ||
      Parsed->EndOffset != Packet.size()) {
    return false;
  }

  Question = std::move(*Parsed);
  return true;
}

DST1Mutator::ValidationResult
validatePoisonTranscript(const DST1Mutator::Transcript &Input) {
  using Error = DST1Mutator::ValidationError;

  if (Input.Responses.empty()) {
    return validationError(Error::MissingResponse);
  }
  if (Input.PostCheckQuery.empty()) {
    return validationError(Error::EmptyPostCheck);
  }
  if (!dst1::validateSegments(Input.ClientQuery, Input.Responses,
                              Input.PostCheckQuery)) {
    return validationError(Error::LengthMismatch);
  }

  ParsedQuestionInfo Query;
  bool InvalidPointer = false;
  if (!isCompleteDnsQuery(Input.ClientQuery, Query, InvalidPointer)) {
    return validationError(InvalidPointer ? Error::InvalidCompressionPointer
                                          : Error::InvalidQuery);
  }

  ParsedQuestionInfo PostCheck;
  InvalidPointer = false;
  if (!isCompleteDnsQuery(Input.PostCheckQuery, PostCheck, InvalidPointer)) {
    return validationError(InvalidPointer ? Error::InvalidCompressionPointer
                                          : Error::InvalidPostCheck);
  }
  if (!haveMatchingQuestionIdentity(Query, PostCheck)) {
    return validationError(Error::QueryPostCheckMismatch);
  }

  for (size_t Index = 0; Index < Input.Responses.size(); ++Index) {
    bool ResponsePointerInvalid = false;
    const auto Layout =
        parseResponseLayout(Input.Responses[Index], &ResponsePointerInvalid);
    if (!Layout) {
      return validationError(ResponsePointerInvalid
                                 ? Error::InvalidCompressionPointer
                                 : Error::InvalidResponse,
                             Index);
    }
    if (!packetsHaveMatchingQuestionIdentity(Input.Responses[Index],
                                             Input.ClientQuery)) {
      return validationError(Error::ResponseQuestionMismatch, Index);
    }
  }

  return {};
}

}

std::optional<DST1Mutator::Transcript>
DST1Mutator::parse(const std::vector<uint8_t> &Input) {
  ValidationResult Validation;
  return parseWireTranscript(Input, Validation);
}

DST1Mutator::ValidationResult
DST1Mutator::validateWire(const std::vector<uint8_t> &Input) {
  ValidationResult Validation;
  (void)parseWireTranscript(Input, Validation);
  return Validation;
}

DST1Mutator::ValidationResult
DST1Mutator::validatePoisonEligible(const std::vector<uint8_t> &Input) {
  ValidationResult Validation;
  auto Parsed = parseWireTranscript(Input, Validation);
  if (!Parsed) {
    return Validation;
  }
  return validatePoisonTranscript(*Parsed);
}

DST1Mutator::ValidationResult
DST1Mutator::validatePoisonEligible(const Transcript &Input) {
  return validatePoisonTranscript(Input);
}

const char *DST1Mutator::validationErrorName(ValidationError Error) {
  switch (Error) {
  case ValidationError::None:
    return "none";
  case ValidationError::InputTooShort:
    return "input_too_short";
  case ValidationError::InputTooLarge:
    return "input_too_large";
  case ValidationError::InvalidMagic:
    return "invalid_magic";
  case ValidationError::InvalidReserved:
    return "invalid_reserved";
  case ValidationError::TooManyResponses:
    return "too_many_responses";
  case ValidationError::TruncatedLengthTable:
    return "truncated_length_table";
  case ValidationError::EmptyQuery:
    return "empty_query";
  case ValidationError::EmptyResponse:
    return "empty_response";
  case ValidationError::LengthMismatch:
    return "length_mismatch";
  case ValidationError::EmptyPostCheck:
    return "empty_post_check";
  case ValidationError::MissingResponse:
    return "missing_response";
  case ValidationError::InvalidQuery:
    return "invalid_query";
  case ValidationError::InvalidPostCheck:
    return "invalid_post_check";
  case ValidationError::QueryPostCheckMismatch:
    return "query_post_check_mismatch";
  case ValidationError::InvalidResponse:
    return "invalid_response";
  case ValidationError::InvalidCompressionPointer:
    return "invalid_compression_pointer";
  case ValidationError::ResponseQuestionMismatch:
    return "response_question_mismatch";
  }
  return "unknown";
}

std::optional<std::vector<uint8_t>> DST1Mutator::normalizeResponseForQuery(
    const std::vector<uint8_t> &Response,
    const std::vector<uint8_t> &Query) {
  ParsedQuestionInfo QueryQuestion;
  bool InvalidPointer = false;
  if (!isCompleteDnsQuery(Query, QueryQuestion, InvalidPointer)) {
    return std::nullopt;
  }

  auto Layout = parseResponseLayout(Response);
  if (!Layout) {
    return std::nullopt;
  }

  Layout->Header[0] = Query[0];
  Layout->Header[1] = Query[1];
  Layout->QuestionBytes.assign(Query.begin() + QueryQuestion.NameStart,
                               Query.begin() + QueryQuestion.EndOffset);

  auto Normalized = buildResponsePacket(*Layout);
  if (!Normalized || !responsePacketMatchesQuery(*Normalized, Query)) {
    return std::nullopt;
  }
  return Normalized;
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

    const bool IdentityChanged = Request.Query->QNAME.has_value() ||
                                 Request.Query->QTYPE.has_value() ||
                                 Request.Query->QCLASS.has_value();
    if (IdentityChanged) {
      DST1Mutator::QueryMutation CoupledMutation;
      CoupledMutation.QNAME = Request.Query->QNAME;
      CoupledMutation.QTYPE = Request.Query->QTYPE;
      CoupledMutation.QCLASS = Request.Query->QCLASS;

      auto MutatedPost =
          applyQuestionMutation(Parsed->PostCheckQuery, CoupledMutation);
      if (!MutatedPost) {
        return std::nullopt;
      }
      Parsed->PostCheckQuery = std::move(*MutatedPost);

      for (auto &Response : Parsed->Responses) {
        auto Normalized = DST1Mutator::normalizeResponseForQuery(
            Response, Parsed->ClientQuery);
        if (!Normalized) {
          return std::nullopt;
        }
        Response = std::move(*Normalized);
      }
    }
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

    if (Mutation.PostCheckName.has_value() ||
        Mutation.PostCheckType.has_value() ||
        Mutation.PostCheckClass.has_value()) {
      DST1Mutator::QueryMutation PostMutation;
      PostMutation.QNAME = Mutation.PostCheckName;
      PostMutation.QTYPE = Mutation.PostCheckType;
      PostMutation.QCLASS = Mutation.PostCheckClass;
      auto UpdatedPost = applyQuestionMutation(Parsed->PostCheckQuery, PostMutation);
      if (!UpdatedPost) {
        return std::nullopt;
      }
      Parsed->PostCheckQuery = std::move(*UpdatedPost);
    }
  }

  if (!responseSetMatchesQuery(Parsed->Responses, Parsed->ClientQuery)) {
    return std::nullopt;
  }

  if (!checkPostQueryIdentity(Parsed->ClientQuery, Parsed->PostCheckQuery)) {
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
