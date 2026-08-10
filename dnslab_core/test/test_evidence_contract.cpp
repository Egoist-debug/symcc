#include "dnslab_core/evidence_contract.hpp"

#include <cassert>
#include <vector>

namespace {

dnslab::SampleMeta makeMeta(const std::string &SampleId) {
  dnslab::SampleMeta Meta = dnslab::buildSampleMeta(SampleId);
  Meta.SourceResolver = "bind9";
  Meta.SampleSha1 = "0123456789abcdef0123456789abcdef01234567";
  Meta.SampleSize = 128;
  Meta.IsStateful = true;
  Meta.Status = "completed";
  Meta.Aggregation.ResolverPair = "bind9->unbound";
  Meta.Aggregation.ProducerProfile = "poison-stateful";
  Meta.Aggregation.InputModel = "DST1 transcript";
  Meta.Aggregation.SourceQueueDir = "/queue";
  Meta.Aggregation.BudgetSec = 3600;
  Meta.Aggregation.SeedTimeoutSec = 5;
  Meta.Aggregation.VariantName = "full_stack";
  Meta.Aggregation.AblationStatus =
      std::map<std::string, std::string>{{"mutator", "on"},
                                         {"cache-delta", "on"},
                                         {"triage", "on"},
                                         {"symcc", "on"}};
  Meta.BaselineCompare.ResolverPair = "bind9->unbound";
  Meta.BaselineCompare.ProducerProfile = "poison-stateful";
  Meta.BaselineCompare.InputModel = "DST1 transcript";
  Meta.BaselineCompare.SourceQueueDir = "/queue";
  Meta.BaselineCompare.BudgetSec = 3600;
  Meta.BaselineCompare.SeedTimeoutSec = 5;
  Meta.BaselineCompare.RepeatCount = 5;
  return Meta;
}

} // namespace

int main() {
  auto Included = makeMeta("sample-a");
  const auto Errors = dnslab::validateSampleMeta(Included);
  assert(Errors.empty());

  auto Excluded = Included;
  Excluded.SampleId = "sample-b";
  Excluded.State = dnslab::AnalysisState::Excluded;
  Excluded.ExcludeReason = "infra_failure";
  const auto ExcludedErrors = dnslab::validateSampleMeta(Excluded);
  assert(ExcludedErrors.empty());

  const auto Payload =
      dnslab::buildRunComparabilityPayload({Included, Excluded});
  assert(Payload.Comparable);
  assert(Payload.Status == "comparable");
  assert(Payload.SampleCount == 2U);
  assert(Payload.Aggregation.has_value());
  assert(Payload.BaselineCompare.has_value());

  auto Diverged = Included;
  Diverged.SampleId = "sample-c";
  Diverged.Aggregation.BudgetSec = 7200;
  const auto DivergedPayload =
      dnslab::buildRunComparabilityPayload({Included, Diverged});
  assert(!DivergedPayload.Comparable);
  assert(DivergedPayload.Reason == "aggregation_key_conflict");
  assert(!DivergedPayload.AggregationKeyConflictFields.empty());

  dnslab::FailureEvidence Failure;
  Failure.Kind = "replay_error";
  Failure.Reason = "timeout";
  Failure.TimeoutSec = 7;
  const auto FailurePayload =
      std::get<dnslab::json::Value::Object>(dnslab::toJson(Failure).storage());
  assert(std::get<std::int64_t>(FailurePayload.at("timeout_sec").storage()) ==
         7);
  return 0;
}
