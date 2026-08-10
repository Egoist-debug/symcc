#include "dnslab_core/transcript.hpp"

#include "DST1Transcript.h"

#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

void require(bool Condition, const char *Message) {
  if (Condition) {
    return;
  }
  std::fprintf(stderr, "%s\n", Message);
  std::abort();
}

} // namespace

int main() {
  const std::vector<uint8_t> Query = {0x12, 0x34, 0x01, 0x00};
  const std::vector<std::vector<uint8_t>> Responses = {
      {0xde, 0xad, 0xbe, 0xef},
      {0xca, 0xfe, 0xba, 0xbe},
  };
  const std::vector<uint8_t> PostCheck = {0x56, 0x78, 0x81, 0x80};

  const auto Wire =
      geninput::dst1::buildTranscript(Query, Responses, PostCheck);
  require(!Wire.empty(), "DST1 transcript 构造失败");

  const auto Parsed = dnslab::parseTranscript(Wire);
  require(Parsed.has_value(), "DST1 transcript 解析失败");
  require(Parsed->ClientQuery == Query, "ClientQuery 不匹配");
  require(Parsed->ForgedResponses == Responses, "ForgedResponses 不匹配");
  require(Parsed->PostCheckQuery == PostCheck, "PostCheckQuery 不匹配");

  const auto Summary = dnslab::summarizeTranscript(*Parsed);
  require(Summary.ResponseCount == 2U, "ResponseCount 不匹配");
  require(Summary.ClientQuerySize == Query.size(), "ClientQuerySize 不匹配");
  require(Summary.PostCheckQuerySize == PostCheck.size(),
          "PostCheckQuerySize 不匹配");
  require(Summary.TotalResponseBytes == 8U, "TotalResponseBytes 不匹配");

  const auto RoundTrip = dnslab::serializeTranscript(*Parsed);
  require(RoundTrip == Wire, "serializeTranscript round-trip 失败");

  const auto Identity = dnslab::buildSampleIdentity("id:000001", Wire);
  require(Identity.QueueEventId == "id:000001", "QueueEventId 不匹配");
  require(Identity.SampleSize == Wire.size(), "SampleSize 不匹配");
  require(Identity.SampleId.rfind("id:000001__", 0) == 0,
          "SampleId 前缀不匹配");
  require(Identity.SampleSha1.size() == 40U, "SampleSha1 长度不匹配");
  return 0;
}
