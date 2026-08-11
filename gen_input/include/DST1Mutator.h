// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GENINPUT_DST1MUTATOR_H
#define GENINPUT_DST1MUTATOR_H

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace geninput {

class DST1Mutator {
public:
  enum class ValidationError {
    None,
    InputTooShort,
    InputTooLarge,
    InvalidMagic,
    InvalidReserved,
    TooManyResponses,
    TruncatedLengthTable,
    EmptyQuery,
    EmptyResponse,
    LengthMismatch,
    EmptyPostCheck,
    MissingResponse,
    InvalidQuery,
    InvalidPostCheck,
    QueryPostCheckMismatch,
    InvalidResponse,
    InvalidCompressionPointer,
    ResponseQuestionMismatch,
  };

  struct ValidationResult {
    ValidationError Error = ValidationError::None;
    size_t ResponseIndex = std::numeric_limits<size_t>::max();

    bool ok() const { return Error == ValidationError::None; }
  };

  enum class DonorMutationFamily {
    ResponseSpliceSameIndex,
    AuthorityTransplant,
    AdditionalOrGlueTransplant,
    ResponseCountExpandOrShrinkFromDonor,
    PostCheckCoupledNameOrTypeShift,
  };

  struct Transcript {
    std::vector<uint8_t> ClientQuery;
    std::vector<std::vector<uint8_t>> Responses;
    std::vector<uint8_t> PostCheckQuery;
  };

  struct QueryMutation {
    std::optional<std::string> QNAME;
    std::optional<uint16_t> QTYPE;
    std::optional<bool> RD;
    std::optional<bool> TC;
    std::optional<bool> CD;
    std::optional<uint16_t> QCLASS;
  };

  struct ResponseMutation {
    std::optional<std::vector<uint8_t>> Packet;
    std::optional<bool> AA;
    std::optional<bool> RA;
    std::optional<uint8_t> RCODE;
    std::optional<uint16_t> ANCOUNT;
    std::optional<uint16_t> NSCOUNT;
    std::optional<uint16_t> ARCOUNT;
    std::optional<std::vector<std::vector<uint8_t>>> AuthorityRRs;
    std::optional<std::vector<std::vector<uint8_t>>> AdditionalRRs;
    std::optional<std::vector<std::vector<uint8_t>>> GlueRRs;
  };

  struct TranscriptMutation {
    std::optional<uint8_t> ResponseCount;
    std::optional<std::vector<std::vector<uint8_t>>> Responses;
    std::optional<std::string> PostCheckName;
    std::optional<uint16_t> PostCheckType;
    std::optional<uint16_t> PostCheckClass;
  };

  struct MutationRequest {
    std::optional<QueryMutation> Query;
    std::optional<ResponseMutation> Response;
    std::optional<TranscriptMutation> Transcript;
    std::optional<DonorMutationFamily> DonorFamily;
    size_t ResponseIndex = 0;
  };

  static std::optional<Transcript> parse(const std::vector<uint8_t> &Input);
  static ValidationResult validateWire(const std::vector<uint8_t> &Input);
  static ValidationResult
  validatePoisonEligible(const std::vector<uint8_t> &Input);
  static ValidationResult validatePoisonEligible(const Transcript &Input);
  static const char *validationErrorName(ValidationError Error);

  static std::optional<std::vector<uint8_t>> normalizeResponseForQuery(
      const std::vector<uint8_t> &Response,
      const std::vector<uint8_t> &Query);
  static std::optional<std::vector<uint8_t>>
  serialize(const Transcript &InputTranscript);
  static std::optional<std::vector<uint8_t>>
  mutate(const std::vector<uint8_t> &Input, const MutationRequest &Request);
  static std::optional<std::vector<uint8_t>>
  mutate(const std::vector<uint8_t> &Input, const MutationRequest &Request,
         const std::vector<uint8_t> &DonorInput);
};

}

#endif
