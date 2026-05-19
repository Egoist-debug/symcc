#pragma once

#include "dnslab_core/evidence_contract.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace dnslab {

struct ClusterRecord {
  SampleMeta Meta;
  StateFingerprint Fingerprint;
};

struct ClusterSummary {
  std::string ClusterKey;
  AnalysisState State = AnalysisState::Unknown;
  std::optional<std::string> ResolverPair;
  std::optional<std::string> VariantName;
  std::string FingerprintKey;
  size_t SampleCount = 0;
  std::vector<std::string> SampleIds;
};

struct ReportArtifact {
  std::string Kind;
  std::string Path;
  std::optional<std::string> RegenerateCommand;
};

struct EvidenceBundle {
  int ContractVersion = kContractVersion;
  std::string GeneratedAt;
  std::optional<std::string> RunId;
  std::optional<SeedProvenance> Provenance;
  RunComparabilityPayload Comparability;
  std::vector<ClusterSummary> Clusters;
  std::vector<ReportArtifact> Artifacts;
};

struct SemanticFrontierEntry {
  std::string SamplePath;
  std::string SampleId;
  std::string AnalysisState;
  std::string SemanticOutcome;
  bool OracleAuditCandidate = false;
  bool NeedsManualReview = false;
  int PriorityTier = 0;
};

struct TriageReportArtifacts {
  std::filesystem::path Root;
  std::filesystem::path ClusterSummaryPath;
  std::filesystem::path StatusSummaryPath;
  std::filesystem::path HighValueManifestPath;
  std::filesystem::path SemanticFrontierManifestPath;
  std::filesystem::path TriageReportMarkdownPath;
  size_t SampleCount = 0;
  size_t SemanticFrontierEntryCount = 0;
};

struct CampaignReportArtifacts {
  std::filesystem::path Root;
  std::filesystem::path ReportDir;
  std::filesystem::path SummaryPath;
  std::filesystem::path AblationMatrixPath;
  std::filesystem::path ClusterCountsPath;
  std::filesystem::path FailureTaxonomyPath;
  std::filesystem::path ExclusionSummaryPath;
  std::filesystem::path ReproRatePath;
  std::filesystem::path OracleAuditPath;
  std::filesystem::path OracleReliabilityPath;
  std::filesystem::path EvidenceBundlePath;
  size_t SampleCount = 0;
  size_t ClusterCount = 0;
  size_t OracleAuditCandidateCount = 0;
  size_t SemanticDiffCount = 0;
};

std::string buildStateFingerprintKey(const StateFingerprint &Input);
std::vector<ClusterSummary>
clusterByFingerprint(const std::vector<ClusterRecord> &Records);
EvidenceBundle buildEvidenceBundle(
    const std::optional<std::string> &RunId,
    const std::optional<SeedProvenance> &Provenance,
    const RunComparabilityPayload &Comparability,
    const std::vector<ClusterSummary> &Clusters,
    const std::vector<ReportArtifact> &Artifacts);
TriageReportArtifacts
generateTriageReportArtifacts(const std::filesystem::path &Root,
                              const std::optional<std::filesystem::path>
                                  &HighValueManifestPath = std::nullopt);
CampaignReportArtifacts
generateCampaignReportArtifacts(const std::filesystem::path &Root,
                                const std::optional<std::filesystem::path>
                                    &ReportBase = std::nullopt,
                                const std::optional<std::filesystem::path>
                                    &AssociatedWorkDir = std::nullopt);
json::Value::Object
buildCampaignSummaryPayload(const std::filesystem::path &Root,
                            const std::optional<std::filesystem::path>
                                &AssociatedWorkDir = std::nullopt);

json::Value toJson(const ClusterSummary &Input);
json::Value toJson(const ReportArtifact &Input);
json::Value toJson(const EvidenceBundle &Input);
json::Value toJson(const SemanticFrontierEntry &Input);
json::Value toJson(const TriageReportArtifacts &Input);
json::Value toJson(const CampaignReportArtifacts &Input);

} // namespace dnslab
