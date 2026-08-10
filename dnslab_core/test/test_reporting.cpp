#include "dnslab_core/reporting.hpp"

#include <cassert>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

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
  Record.Meta.Aggregation.AblationStatus =
      std::map<std::string, std::string>{{"mutator", "on"},
                                         {"cache-delta", "on"},
                                         {"triage", "on"},
                                         {"symcc", "on"}};
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

std::string readTextFile(const std::filesystem::path &Path) {
  std::ifstream Input(Path);
  assert(Input.good());
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  return Buffer.str();
}

std::string normalizeJsonText(const std::string &Input) {
  std::string Output;
  Output.reserve(Input.size());
  bool InString = false;
  bool Escaped = false;
  for (const unsigned char Ch : Input) {
    if (Escaped) {
      Output.push_back(static_cast<char>(Ch));
      Escaped = false;
      continue;
    }
    if (Ch == '\\') {
      Output.push_back(static_cast<char>(Ch));
      Escaped = true;
      continue;
    }
    if (Ch == '"') {
      Output.push_back(static_cast<char>(Ch));
      InString = !InString;
      continue;
    }
    if (!InString && std::isspace(Ch)) {
      continue;
    }
    Output.push_back(static_cast<char>(Ch));
  }
  return Output;
}

dnslab::json::Value::Object buildSampleMetaPayload(const std::string &SampleId) {
  return {
      {"schema_version", dnslab::kSchemaVersion},
      {"generated_at", "2026-03-23T00:00:00Z"},
      {"sample_id", SampleId},
      {"contract_version", dnslab::kContractVersion},
      {"aggregation_key",
       dnslab::json::Value::Object{
           {"resolver_pair", "bind9_vs_unbound"},
           {"producer_profile", "poison-stateful"},
           {"input_model", "DST1 transcript"},
           {"source_queue_dir", "/tmp/follow/queue"},
           {"budget_sec", 5},
           {"seed_timeout_sec", 1},
           {"variant_name", "control"},
           {"ablation_status",
            dnslab::json::Value::Object{{"mutator", "off"},
                                        {"cache-delta", "on"},
                                        {"triage", "on"},
                                        {"symcc", "on"}}},
           {"contract_version", dnslab::kContractVersion},
       }},
      {"baseline_compare_key",
       dnslab::json::Value::Object{
           {"resolver_pair", "bind9_vs_unbound"},
           {"producer_profile", "poison-stateful"},
           {"input_model", "DST1 transcript"},
           {"source_queue_dir", "/tmp/follow/queue"},
           {"budget_sec", 5},
           {"seed_timeout_sec", 1},
           {"repeat_count", 3},
           {"contract_version", dnslab::kContractVersion},
       }},
      {"executed_resolvers",
       dnslab::json::Value::Array{"bind9", "unbound"}},
      {"seed_provenance",
       dnslab::json::Value::Object{
           {"cold_start", false},
           {"seed_source_dir", "/tmp/follow/source"},
           {"seed_materialization_method", "reused_filtered_corpus"},
           {"seed_snapshot_id", "1111111111111111111111111111111111111111"},
           {"regen_seeds", false},
           {"refilter_queries", false},
           {"stable_input_dir", "/tmp/follow/stable"},
           {"recorded_at", "2026-03-23T00:00:00Z"},
       }},
  };
}

void writeCampaignSample(const std::filesystem::path &Root,
                         const std::string &SampleId, const std::string &Status,
                         const std::string &ClusterKey,
                         const std::string &SemanticOutcome,
                         bool NeedsManualReview, bool DiffDetected,
                         const dnslab::json::Value::Array &ResolverDiffs,
                         const dnslab::json::Value::Object &OraclePayload,
                         const dnslab::json::Value::Object &CacheDiffPayload) {
  const auto SampleDir = Root / SampleId;
  writeTextFile(SampleDir / "sample.bin", SampleId + "\n");
  writeTextFile(SampleDir / "sample.meta.json",
                dnslab::json::Value(buildSampleMetaPayload(SampleId)).dump(2) +
                    "\n");
  writeTextFile(
      SampleDir / "triage.json",
      dnslab::json::Value(dnslab::json::Value::Object{
                              {"schema_version", dnslab::kSchemaVersion},
                              {"generated_at", "2026-03-23T00:00:00Z"},
                              {"sample_id", SampleId},
                              {"status", Status},
                              {"diff_class", SemanticOutcome},
                              {"analysis_state", "included"},
                              {"exclude_reason", dnslab::json::Value()},
                              {"semantic_outcome", SemanticOutcome},
                              {"filter_labels",
                               NeedsManualReview
                                   ? dnslab::json::Value::Array{"cache_delta_review"}
                                   : dnslab::json::Value::Array{}},
                              {"cluster_key", ClusterKey},
                              {"cache_delta_triggered", DiffDetected},
                              {"interesting_delta_count", DiffDetected ? 1 : 0},
                              {"needs_manual_review", NeedsManualReview},
                              {"notes", dnslab::json::Value::Array{}},
                              {"resolver_diffs", ResolverDiffs},
                          })
          .dump(2) +
          "\n");
  writeTextFile(SampleDir / "oracle.json",
                dnslab::json::Value(OraclePayload).dump(2) + "\n");
  writeTextFile(SampleDir / "cache_diff.json",
                dnslab::json::Value(CacheDiffPayload).dump(2) + "\n");
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
  assert(ReportJson.find("\"root\": \"" + TempRoot.string() + "\"") !=
         std::string::npos);
  assert(ReportJson.find("\"cluster_summary\": \"" +
                             ReportArtifacts.ClusterSummaryPath.string() + "\"") !=
         std::string::npos);
  assert(ReportJson.find("\"status_summary\": \"" +
                             ReportArtifacts.StatusSummaryPath.string() + "\"") !=
         std::string::npos);
  assert(ReportJson.find("\"high_value_manifest\": \"" +
                             ReportArtifacts.HighValueManifestPath.string() +
                             "\"") != std::string::npos);
  assert(ReportJson.find("\"semantic_frontier_manifest\": \"" +
                             ReportArtifacts.SemanticFrontierManifestPath.string() +
                             "\"") != std::string::npos);
  assert(ReportJson.find("\"triage_report_markdown\": \"" +
                             ReportArtifacts.TriageReportMarkdownPath.string() +
                             "\"") != std::string::npos);
  assert(ReportJson.find("\"sample_count\": 1") != std::string::npos);
  assert(ReportJson.find("\"semantic_frontier_entry_count\": 1") !=
         std::string::npos);
  std::filesystem::remove_all(TempRoot);

  const auto TranscriptCaseRoot =
      std::filesystem::temp_directory_path() /
      "dnslab_core_case_study_transcript_test";
  std::filesystem::remove_all(TranscriptCaseRoot);
  std::filesystem::create_directories(TranscriptCaseRoot / "sample-transcript");
  writeTextFile(TranscriptCaseRoot / "sample-transcript" / "sample.meta.json",
                dnslab::json::Value(buildSampleMetaPayload("sample-transcript"))
                        .dump(2) +
                    "\n");
  writeTextFile(
      TranscriptCaseRoot / "sample-transcript" / "triage.json",
      dnslab::json::Value(dnslab::json::Value::Object{
                              {"schema_version", dnslab::kSchemaVersion},
                              {"generated_at", "2026-03-23T00:00:00Z"},
                              {"sample_id", "sample-transcript"},
                              {"status", "completed_oracle_diff"},
                              {"diff_class", "oracle_diff"},
                              {"analysis_state", "included"},
                              {"exclude_reason", dnslab::json::Value()},
                              {"semantic_outcome", "oracle_diff"},
                              {"failure_taxonomy_version",
                               dnslab::json::Value(1)},
                              {"failure_bucket_primary", "semantic_diff"},
                              {"failure_bucket_detail", "oracle_diff"},
                              {"oracle_audit_candidate", true},
                              {"case_study_candidate", true},
                              {"manual_truth_status", "not_started"},
                              {"filter_labels",
                               dnslab::json::Value::Array{"oracle_diff"}},
                              {"cluster_key",
                               "completed_oracle_diff|oracle_diff|oracle_diff|fp:iterative->iterative"},
                              {"cache_delta_triggered", false},
                              {"interesting_delta_count", 0},
                              {"needs_manual_review", true},
                              {"notes",
                               dnslab::json::Value::Array{"transcript fallback"}},
                          })
          .dump(2) +
          "\n");
  writeTextFile(
      TranscriptCaseRoot / "sample-transcript" / "oracle.json",
      dnslab::json::Value(dnslab::json::Value::Object{
                              {"schema_version", dnslab::kSchemaVersion},
                              {"generated_at", "2026-03-23T00:00:00Z"},
                              {"sample_id", "sample-transcript"},
                              {"bind9.parse_ok", true},
                              {"unbound.parse_ok", false},
                              {"bind9.response_accepted", true},
                              {"unbound.response_accepted", true},
                              {"bind9.second_query_hit", false},
                              {"unbound.second_query_hit", false},
                              {"bind9.cache_entry_created", false},
                              {"unbound.cache_entry_created", false},
                          })
          .dump(2) +
          "\n");
  writeTextFile(
      TranscriptCaseRoot / "sample-transcript" / "cache_diff.json",
      dnslab::json::Value(dnslab::json::Value::Object{
                              {"schema_version", dnslab::kSchemaVersion},
                              {"generated_at", "2026-03-23T00:00:00Z"},
                              {"sample_id", "sample-transcript"},
                              {"diff_detected", false},
                              {"bind9",
                               dnslab::json::Value::Object{
                                   {"has_cache_diff", false},
                                   {"interesting_delta_count", 0},
                               }},
                              {"unbound",
                               dnslab::json::Value::Object{
                                   {"has_cache_diff", false},
                                   {"interesting_delta_count", 0},
                               }},
                          })
          .dump(2) +
          "\n");
  writeTextFile(TranscriptCaseRoot / "sample-transcript" / "transcript",
                "hello-world");
  writeTextFile(TranscriptCaseRoot / "sample-transcript" / "bind9.stderr",
                "bind9 stderr\n");
  writeTextFile(TranscriptCaseRoot / "sample-transcript" / "unbound.stderr",
                "unbound stderr\n");
  const auto TranscriptCaseArtifacts = dnslab::exportCaseStudies(
      TranscriptCaseRoot, TranscriptCaseRoot / "campaign_report", 1);
  assert(TranscriptCaseArtifacts.SelectedCount == 1U);
  const auto TranscriptCaseJson = readTextFile(
      TranscriptCaseArtifacts.OutputDir / "sample-transcript.json");
  assert(TranscriptCaseJson.find(
             "\"sample_bin_path\": \"" +
             (TranscriptCaseRoot / "sample-transcript" / "transcript").string() +
             "\"") != std::string::npos);
  assert(TranscriptCaseJson.find("\"size\": 11") != std::string::npos);
  assert(TranscriptCaseJson.find("triage.json、transcript、bind9.stderr、unbound.stderr") !=
         std::string::npos);
  std::filesystem::remove_all(TranscriptCaseRoot);

  const auto CampaignRoot =
      std::filesystem::temp_directory_path() / "dnslab_core_campaign_summary_test";
  std::filesystem::remove_all(CampaignRoot);
  std::filesystem::create_directories(CampaignRoot);
  writeCampaignSample(
      CampaignRoot, "sample-a", "completed_no_diff", "cluster-a", "no_diff",
      false, false, dnslab::json::Value::Array{},
      dnslab::json::Value::Object{
          {"bind9.parse_ok", true},
          {"unbound.parse_ok", true},
          {"bind9.response_accepted", true},
          {"unbound.response_accepted", true},
          {"bind9.second_query_hit", false},
          {"unbound.second_query_hit", false},
          {"bind9.cache_entry_created", false},
          {"unbound.cache_entry_created", false},
      },
      dnslab::json::Value::Object{
          {"diff_detected", false},
          {"bind9", dnslab::json::Value::Object{{"has_cache_diff", false}}},
          {"unbound", dnslab::json::Value::Object{{"has_cache_diff", false}}},
      });
  writeCampaignSample(
      CampaignRoot, "sample-b", "completed_cache_changed_needs_review",
      "cluster-b", "cache_diff_interesting", true, true,
      dnslab::json::Value::Array{dnslab::json::Value::Object{
          {"left_resolver", "bind9"},
          {"right_resolver", "unbound"},
          {"oracle_diff_fields",
           dnslab::json::Value::Array{"response_accepted"}},
          {"cache_diff_fields", dnslab::json::Value::Array{}},
      }},
      dnslab::json::Value::Object{
          {"bind9.parse_ok", true},
          {"unbound.parse_ok", true},
          {"bind9.response_accepted", true},
          {"unbound.response_accepted", false},
          {"bind9.second_query_hit", false},
          {"unbound.second_query_hit", true},
          {"bind9.cache_entry_created", false},
          {"unbound.cache_entry_created", true},
      },
      dnslab::json::Value::Object{
          {"diff_detected", true},
          {"bind9", dnslab::json::Value::Object{{"has_cache_diff", true}}},
          {"unbound", dnslab::json::Value::Object{{"has_cache_diff", false}}},
      });

  const auto SummaryPayload = dnslab::buildCampaignSummaryPayload(CampaignRoot);
  const auto CampaignArtifacts =
      dnslab::generateCampaignReportArtifacts(CampaignRoot);
  std::ifstream SummaryInput(CampaignArtifacts.SummaryPath);
  std::ostringstream SummaryBuffer;
  SummaryBuffer << SummaryInput.rdbuf();
  const auto NormalizedSummary = normalizeJsonText(SummaryBuffer.str());
  const std::vector<std::string> SharedKeys = {
      "total_samples",
      "needs_review_count",
      "cluster_count",
      "contract_version",
      "metric_denominators",
      "semantic_counts",
      "semantic_diff_count",
      "oracle_audit_candidate_count",
      "diff_detected_sample_count",
      "executed_resolvers",
      "executed_resolver_sample_counts",
      "skipped_resolver_sample_counts",
      "resolver_pair_diff_counts",
      "comparability",
      "run_id",
      "ablation_status",
      "seed_provenance",
      "manifest_size",
      "reproduced_count",
      "repro_rate",
  };
  for (const auto &Key : SharedKeys) {
    const auto Found = SummaryPayload.find(Key);
    assert(Found != SummaryPayload.end());
    const auto ExpectedField =
        "\"" + Key + "\":" + normalizeJsonText(Found->second.dump(2));
    assert(NormalizedSummary.find(ExpectedField) != std::string::npos);
  }
  const auto CampaignArtifactsJson = dnslab::toJson(CampaignArtifacts).dump(2);
  assert(CampaignArtifactsJson.find("\"root\": \"" + CampaignRoot.string() +
                                    "\"") != std::string::npos);
  assert(CampaignArtifactsJson.find("\"report_dir\": \"" +
                                        CampaignArtifacts.ReportDir.string() +
                                        "\"") != std::string::npos);
  assert(CampaignArtifactsJson.find("\"summary\": \"" +
                                        CampaignArtifacts.SummaryPath.string() +
                                        "\"") != std::string::npos);
  assert(CampaignArtifactsJson.find(
             "\"ablation_matrix\": \"" +
             CampaignArtifacts.AblationMatrixPath.string() + "\"") !=
         std::string::npos);
  assert(CampaignArtifactsJson.find(
             "\"cluster_counts\": \"" +
             CampaignArtifacts.ClusterCountsPath.string() + "\"") !=
         std::string::npos);
  assert(CampaignArtifactsJson.find(
             "\"failure_taxonomy\": \"" +
             CampaignArtifacts.FailureTaxonomyPath.string() + "\"") !=
         std::string::npos);
  assert(CampaignArtifactsJson.find(
             "\"exclusion_summary\": \"" +
             CampaignArtifacts.ExclusionSummaryPath.string() + "\"") !=
         std::string::npos);
  assert(CampaignArtifactsJson.find("\"repro_rate\": \"" +
                                        CampaignArtifacts.ReproRatePath.string() +
                                        "\"") != std::string::npos);
  assert(CampaignArtifactsJson.find("\"oracle_audit\": \"" +
                                        CampaignArtifacts.OracleAuditPath.string() +
                                        "\"") != std::string::npos);
  assert(CampaignArtifactsJson.find(
             "\"oracle_reliability\": \"" +
             CampaignArtifacts.OracleReliabilityPath.string() + "\"") !=
         std::string::npos);
  assert(CampaignArtifactsJson.find("\"evidence_bundle\": \"" +
                                        CampaignArtifacts.EvidenceBundlePath.string() +
                                        "\"") != std::string::npos);
  assert(CampaignArtifactsJson.find("\"sample_count\": 2") !=
         std::string::npos);
  assert(CampaignArtifactsJson.find("\"cluster_count\": 2") !=
         std::string::npos);
  assert(CampaignArtifactsJson.find("\"oracle_audit_candidate_count\": 0") !=
         std::string::npos);
  assert(CampaignArtifactsJson.find("\"semantic_diff_count\": 1") !=
         std::string::npos);
  std::filesystem::remove_all(CampaignRoot);

  const auto AssociatedSummaryRoot =
      std::filesystem::temp_directory_path() /
      "dnslab_core_campaign_summary_associated_manifest_test";
  const auto AssociatedWorkDir =
      std::filesystem::temp_directory_path() /
      "dnslab_core_campaign_summary_associated_manifest_workdir";
  std::filesystem::remove_all(AssociatedSummaryRoot);
  std::filesystem::remove_all(AssociatedWorkDir);
  std::filesystem::create_directories(AssociatedSummaryRoot);
  std::filesystem::create_directories(AssociatedWorkDir);
  writeCampaignSample(
      AssociatedSummaryRoot, "sample-associated",
      "completed_cache_changed_needs_review", "cluster-associated",
      "cache_diff_interesting", true, true,
      dnslab::json::Value::Array{},
      dnslab::json::Value::Object{
          {"bind9.parse_ok", true},
          {"unbound.parse_ok", true},
          {"bind9.response_accepted", true},
          {"unbound.response_accepted", true},
          {"bind9.second_query_hit", false},
          {"unbound.second_query_hit", false},
          {"bind9.cache_entry_created", false},
          {"unbound.cache_entry_created", false},
      },
      dnslab::json::Value::Object{
          {"diff_detected", true},
          {"bind9", dnslab::json::Value::Object{{"has_cache_diff", true}}},
          {"unbound", dnslab::json::Value::Object{{"has_cache_diff", false}}},
      });
  writeTextFile(AssociatedWorkDir / "high_value_samples.txt",
                (AssociatedSummaryRoot / "sample-associated" / "missing.bin")
                        .string() +
                    "\n");
  const auto AssociatedSummary = dnslab::buildCampaignSummaryPayload(
      AssociatedSummaryRoot, AssociatedWorkDir);
  const auto *ManifestSize =
      std::get_if<std::int64_t>(&AssociatedSummary.at("manifest_size").storage());
  const auto *ReproducedCount = std::get_if<std::int64_t>(
      &AssociatedSummary.at("reproduced_count").storage());
  const auto *ReproRate =
      std::get_if<double>(&AssociatedSummary.at("repro_rate").storage());
  if (ManifestSize == nullptr || *ManifestSize != 0) {
    throw std::runtime_error("associated manifest_size 未消费 workdir manifest");
  }
  if (ReproducedCount == nullptr || *ReproducedCount != 0) {
    throw std::runtime_error(
        "associated reproduced_count 未消费 workdir manifest");
  }
  if (ReproRate == nullptr || *ReproRate != 0.0) {
    throw std::runtime_error("associated repro_rate 未消费 workdir manifest");
  }
  std::filesystem::remove_all(AssociatedSummaryRoot);
  std::filesystem::remove_all(AssociatedWorkDir);
  return 0;
}
