// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GENINPUT_DST1MUTATOR_H
#define GENINPUT_DST1MUTATOR_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace geninput {

class DST1Mutator {
public:
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
  };

  struct ResponseMutation {
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
    std::optional<std::string> PostCheckName;
    std::optional<uint16_t> PostCheckType;
  };

  struct MutationRequest {
    std::optional<QueryMutation> Query;
    std::optional<ResponseMutation> Response;
    std::optional<TranscriptMutation> Transcript;
    size_t ResponseIndex = 0;
  };

  static std::optional<Transcript> parse(const std::vector<uint8_t> &Input);
  static std::optional<std::vector<uint8_t>>
  serialize(const Transcript &InputTranscript);
  static std::optional<std::vector<uint8_t>>
  mutate(const std::vector<uint8_t> &Input, const MutationRequest &Request);
};

}

#endif
