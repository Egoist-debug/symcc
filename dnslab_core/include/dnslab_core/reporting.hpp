#pragma once

#include "dnslab_core/evidence_contract.hpp"

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

std::string buildStateFingerprintKey(const StateFingerprint &Input);
std::vector<ClusterSummary>
clusterByFingerprint(const std::vector<ClusterRecord> &Records);
EvidenceBundle buildEvidenceBundle(
    const std::optional<std::string> &RunId,
    const std::optional<SeedProvenance> &Provenance,
    const RunComparabilityPayload &Comparability,
    const std::vector<ClusterSummary> &Clusters,
    const std::vector<ReportArtifact> &Artifacts);

json::Value toJson(const ClusterSummary &Input);
json::Value toJson(const ReportArtifact &Input);
json::Value toJson(const EvidenceBundle &Input);

} // namespace dnslab
