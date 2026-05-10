#include "dnslab_core/reporting.hpp"

#include <algorithm>
#include <map>
#include <sstream>

namespace dnslab {

namespace {

std::string renderOptionalString(const std::optional<std::string> &Input) {
  return Input.has_value() ? *Input : "null";
}

std::string renderOptionalBool(const std::optional<bool> &Input) {
  if (!Input.has_value()) {
    return "null";
  }
  return *Input ? "true" : "false";
}

} // namespace

std::string buildStateFingerprintKey(const StateFingerprint &Input) {
  std::ostringstream Stream;
  Stream << "bind9.forwarding_path=" << renderOptionalString(Input.Bind9ForwardingPath)
         << "|bind9.retry_seen=" << renderOptionalBool(Input.Bind9RetrySeen)
         << "|bind9.msg_cache_seen="
         << renderOptionalBool(Input.Bind9MsgCacheSeen)
         << "|bind9.rrset_cache_seen="
         << renderOptionalBool(Input.Bind9RrsetCacheSeen)
         << "|bind9.negative_cache_seen="
         << renderOptionalBool(Input.Bind9NegativeCacheSeen)
         << "|unbound.forwarding_path="
         << renderOptionalString(Input.UnboundForwardingPath)
         << "|unbound.retry_seen=" << renderOptionalBool(Input.UnboundRetrySeen)
         << "|unbound.msg_cache_seen="
         << renderOptionalBool(Input.UnboundMsgCacheSeen)
         << "|unbound.rrset_cache_seen="
         << renderOptionalBool(Input.UnboundRrsetCacheSeen)
         << "|unbound.negative_cache_seen="
         << renderOptionalBool(Input.UnboundNegativeCacheSeen);
  return Stream.str();
}

std::vector<ClusterSummary>
clusterByFingerprint(const std::vector<ClusterRecord> &Records) {
  std::map<std::string, ClusterSummary> Clusters;
  for (const auto &Record : Records) {
    const SampleMeta Meta = applySampleMetaContractDefaults(Record.Meta);
    const std::string FingerprintKey = buildStateFingerprintKey(Record.Fingerprint);
    const std::string ResolverPair =
        renderOptionalString(Meta.Aggregation.ResolverPair);
    const std::string VariantName =
        renderOptionalString(Meta.Aggregation.VariantName);
    const std::string ClusterKey = toString(Meta.State) + "|" + ResolverPair +
                                   "|" + VariantName + "|" + FingerprintKey;

    auto &Cluster = Clusters[ClusterKey];
    if (Cluster.SampleCount == 0U) {
      Cluster.ClusterKey = ClusterKey;
      Cluster.State = Meta.State;
      Cluster.ResolverPair = Meta.Aggregation.ResolverPair;
      Cluster.VariantName = Meta.Aggregation.VariantName;
      Cluster.FingerprintKey = FingerprintKey;
    }
    ++Cluster.SampleCount;
    Cluster.SampleIds.push_back(Meta.SampleId);
  }

  std::vector<ClusterSummary> Output;
  Output.reserve(Clusters.size());
  for (auto &[Key, Cluster] : Clusters) {
    (void)Key;
    std::sort(Cluster.SampleIds.begin(), Cluster.SampleIds.end());
    Output.push_back(std::move(Cluster));
  }
  return Output;
}

EvidenceBundle buildEvidenceBundle(
    const std::optional<std::string> &RunId,
    const std::optional<SeedProvenance> &Provenance,
    const RunComparabilityPayload &Comparability,
    const std::vector<ClusterSummary> &Clusters,
    const std::vector<ReportArtifact> &Artifacts) {
  EvidenceBundle Output;
  Output.GeneratedAt = utcTimestampNow();
  Output.RunId = RunId;
  Output.Provenance = Provenance;
  Output.Comparability = Comparability;
  Output.Clusters = Clusters;
  Output.Artifacts = Artifacts;
  return Output;
}

json::Value toJson(const ClusterSummary &Input) {
  json::Value::Object Output;
  Output["cluster_key"] = Input.ClusterKey;
  Output["analysis_state"] = toString(Input.State);
  json::setOptional(Output, "resolver_pair", Input.ResolverPair);
  json::setOptional(Output, "variant_name", Input.VariantName);
  Output["fingerprint_key"] = Input.FingerprintKey;
  Output["sample_count"] = static_cast<std::int64_t>(Input.SampleCount);
  json::Value::Array SampleIds;
  for (const auto &SampleId : Input.SampleIds) {
    SampleIds.emplace_back(SampleId);
  }
  Output["sample_ids"] = SampleIds;
  return Output;
}

json::Value toJson(const ReportArtifact &Input) {
  json::Value::Object Output;
  Output["kind"] = Input.Kind;
  Output["path"] = Input.Path;
  json::setOptional(Output, "regenerate_command", Input.RegenerateCommand);
  return Output;
}

json::Value toJson(const EvidenceBundle &Input) {
  json::Value::Object Output;
  Output["contract_version"] = Input.ContractVersion;
  Output["generated_at"] = Input.GeneratedAt;
  json::setOptional(Output, "run_id", Input.RunId);
  if (Input.Provenance.has_value()) {
    Output["seed_provenance"] = toJson(*Input.Provenance);
  }
  Output["comparability"] = toJson(Input.Comparability);

  json::Value::Array Clusters;
  for (const auto &Cluster : Input.Clusters) {
    Clusters.emplace_back(toJson(Cluster));
  }
  Output["clusters"] = Clusters;

  json::Value::Array Artifacts;
  for (const auto &Artifact : Input.Artifacts) {
    Artifacts.emplace_back(toJson(Artifact));
  }
  Output["artifacts"] = Artifacts;
  return Output;
}

} // namespace dnslab
