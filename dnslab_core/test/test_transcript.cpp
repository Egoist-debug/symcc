#include "dnslab_core/transcript.hpp"

#include "DST1Transcript.h"

#include <cassert>
#include <vector>

int main() {
  const std::vector<uint8_t> Query = {0x12, 0x34, 0x01, 0x00};
  const std::vector<std::vector<uint8_t>> Responses = {
      {0xde, 0xad, 0xbe, 0xef},
      {0xca, 0xfe, 0xba, 0xbe},
  };
  const std::vector<uint8_t> PostCheck = {0x56, 0x78, 0x81, 0x80};

  const auto Wire =
      geninput::dst1::buildTranscript(Query, Responses, PostCheck);
  assert(!Wire.empty());

  const auto Parsed = dnslab::parseTranscript(Wire);
  assert(Parsed.has_value());
  assert(Parsed->ClientQuery == Query);
  assert(Parsed->ForgedResponses == Responses);
  assert(Parsed->PostCheckQuery == PostCheck);

  const auto Summary = dnslab::summarizeTranscript(*Parsed);
  assert(Summary.ResponseCount == 2U);
  assert(Summary.ClientQuerySize == Query.size());
  assert(Summary.PostCheckQuerySize == PostCheck.size());
  assert(Summary.TotalResponseBytes == 8U);

  const auto RoundTrip = dnslab::serializeTranscript(*Parsed);
  assert(RoundTrip == Wire);

  const auto Identity = dnslab::buildSampleIdentity("id:000001", Wire);
  assert(Identity.SampleSize == Wire.size());
  assert(Identity.SampleId.rfind("id:000001__", 0) == 0);
  assert(Identity.SampleSha1.size() == 40U);
  return 0;
}
