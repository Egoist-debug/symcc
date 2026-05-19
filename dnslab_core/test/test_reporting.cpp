#include "dnslab_core/reporting.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>

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

void writeTextFile(const std::filesystem::path &Path, const std::string &Content) {
  std::filesystem::create_directories(Path.parent_path());
  std::ofstream Output(Path);
  assert(Output.good());
  Output << Content;
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

  const auto TempRoot =
      std::filesystem::temp_directory_path() / "dnslab_core_reporting_test";
  std::filesystem::remove_all(TempRoot);
  std::filesystem::create_directories(TempRoot);
  writeTextFile(TempRoot / "sample-a" / "sample.meta.json",
                "{\n"
                "  \"sample_id\": \"sample-a\"\n"
                "}\n");
  writeTextFile(TempRoot / "sample-a" / "triage.json",
                "{\n"
                "  \"sample_id\": \"sample-a\",\n"
                "  \"status\": \"completed\",\n"
                "  \"cluster_key\": \"cluster-a\",\n"
                "  \"analysis_state\": \"included\",\n"
                "  \"semantic_outcome\": \"oracle_diff\",\n"
                "  \"oracle_audit_candidate\": true,\n"
                "  \"needs_manual_review\": true,\n"
                "  \"filter_labels\": []\n"
                "}\n");
  writeTextFile(TempRoot / "sample-a" / "sample.bin", "sample-a");

  const auto ReportArtifacts = dnslab::generateTriageReportArtifacts(TempRoot);
  assert(std::filesystem::is_regular_file(ReportArtifacts.ClusterSummaryPath));
  assert(std::filesystem::is_regular_file(ReportArtifacts.StatusSummaryPath));
  assert(std::filesystem::is_regular_file(ReportArtifacts.HighValueManifestPath));
  assert(std::filesystem::is_regular_file(
      ReportArtifacts.SemanticFrontierManifestPath));
  assert(std::filesystem::is_regular_file(
      ReportArtifacts.TriageReportMarkdownPath));
  assert(ReportArtifacts.SampleCount == 1U);
  assert(ReportArtifacts.SemanticFrontierEntryCount == 1U);
  const auto ReportJson = dnslab::toJson(ReportArtifacts).dump(2);
  assert(ReportJson.find("\"sample_count\": 1") != std::string::npos);
  std::filesystem::remove_all(TempRoot);
  return 0;
}
