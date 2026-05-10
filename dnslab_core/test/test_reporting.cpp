#include "dnslab_core/reporting.hpp"

#include <cassert>

namespace {

dnslab::ClusterRecord makeRecord(const std::string &SampleId,
                                 const std::string &VariantName) {
  dnslab::ClusterRecord Record;
  Record.Meta = dnslab::buildSampleMeta(SampleId);
  Record.Meta.State = dnslab::AnalysisState::Included;
  Record.Meta.Aggregation.ResolverPair = "bind9->unbound";
  Record.Meta.Aggregation.VariantName = VariantName;
  Record.Meta.Aggregation.ProducerProfile = "poison-stateful";
  Record.Meta.Aggregation.InputModel = "DST1 transcript";
  Record.Meta.Aggregation.SourceQueueDir = "/queue";
  Record.Meta.Aggregation.BudgetSec = 3600;
  Record.Meta.Aggregation.SeedTimeoutSec = 5;
  Record.Meta.Aggregation.AblationStatus = "enabled";
  Record.Meta.BaselineCompare.ResolverPair = "bind9->unbound";
  Record.Meta.BaselineCompare.ProducerProfile = "poison-stateful";
  Record.Meta.BaselineCompare.InputModel = "DST1 transcript";
  Record.Meta.BaselineCompare.SourceQueueDir = "/queue";
  Record.Meta.BaselineCompare.BudgetSec = 3600;
  Record.Meta.BaselineCompare.SeedTimeoutSec = 5;
  Record.Meta.BaselineCompare.RepeatCount = 5;

  Record.Fingerprint.SchemaVersion = dnslab::kSchemaVersion;
  Record.Fingerprint.GeneratedAt = dnslab::utcTimestampNow();
  Record.Fingerprint.SampleId = SampleId;
  Record.Fingerprint.Bind9ForwardingPath = "iterative";
  Record.Fingerprint.Bind9RetrySeen = false;
  Record.Fingerprint.Bind9MsgCacheSeen = true;
  Record.Fingerprint.Bind9RrsetCacheSeen = true;
  Record.Fingerprint.Bind9NegativeCacheSeen = false;
  Record.Fingerprint.UnboundForwardingPath = "iterative";
  Record.Fingerprint.UnboundRetrySeen = false;
  Record.Fingerprint.UnboundMsgCacheSeen = true;
  Record.Fingerprint.UnboundRrsetCacheSeen = true;
  Record.Fingerprint.UnboundNegativeCacheSeen = false;
  return Record;
}

} // namespace

int main() {
  const auto Clusters = dnslab::clusterByFingerprint(
      {makeRecord("sample-a", "full_stack"), makeRecord("sample-b", "full_stack"),
       makeRecord("sample-c", "afl_only")});
  assert(Clusters.size() == 2U);
  assert(Clusters[0].SampleCount >= 1U);

  const auto Comparability = dnslab::buildRunComparabilityPayload(
      {makeRecord("sample-a", "full_stack").Meta,
       makeRecord("sample-b", "full_stack").Meta});
  dnslab::ReportArtifact Artifact;
  Artifact.Kind = "summary";
  Artifact.Path = "campaign_reports/2026-05-09/summary.json";
  Artifact.RegenerateCommand = "python3 -m tools.dns_diff.cli campaign-report";

  const auto Bundle = dnslab::buildEvidenceBundle(
      std::optional<std::string>("run-001"), std::nullopt, Comparability,
      Clusters, {Artifact});
  const auto Json = dnslab::toJson(Bundle).dump(2);
  assert(Json.find("\"run_id\": \"run-001\"") != std::string::npos);
  assert(Json.find("\"kind\": \"summary\"") != std::string::npos);
  return 0;
}
