#pragma once

#include "dnslab_core/evidence_contract.hpp"
#include "dnslab_core/json_value.hpp"
#include "dnslab_core/oracle.hpp"

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace dnslab {

struct CacheRecord {
  std::string Resolver;
  std::string View;
  std::string QName;
  std::string QType;
  std::string RRType;
  std::string Section;
  std::string CacheType;
  std::string TTL;
  std::string RDataNorm;
  std::string Flags;

  std::vector<std::string> toFields() const;
};

struct CacheDeltaItem {
  std::string Kind;
  int CountBefore = 0;
  int CountAfter = 0;
  int Delta = 0;
  CacheRecord Fields;
};

struct ResolverCacheDiff {
  int EntriesBefore = 0;
  int EntriesAfter = 0;
  bool HasCacheDiff = false;
  int InterestingDeltaCount = 0;
  std::vector<CacheDeltaItem> DeltaItems;
};

struct ResolverPairCacheDifference {
  std::string LeftResolver;
  std::string RightResolver;
  std::vector<std::string> DifferenceFields;
};

struct ResolverPairDifference {
  std::string LeftResolver;
  std::string RightResolver;
  std::vector<std::string> OracleDiffFields;
  std::vector<std::string> CacheDiffFields;
};

struct CacheDiffResult {
  std::string SampleId;
  bool CacheDeltaTriggered = false;
  bool DiffDetected = false;
  std::string CompatibilitySecondaryResolver = "unbound";
  std::vector<std::string> ExecutedResolvers;
  ResolverCacheDiff Bind9;
  ResolverCacheDiff Unbound;
  std::map<std::string, ResolverCacheDiff> Resolvers;
  std::vector<ResolverPairCacheDifference> ResolverDifferences;
};

struct TriageRecord {
  std::string SampleId;
  std::string GeneratedAt;
  std::string Status;
  std::string DiffClass;
  std::string AnalysisState;
  std::optional<std::string> ExcludeReason;
  std::string SemanticOutcome;
  int FailureTaxonomyVersion = 1;
  std::string FailureBucketPrimary;
  std::string FailureBucketDetail;
  std::vector<std::string> FilterLabels;
  std::string ClusterKey;
  bool CacheDeltaTriggered = false;
  bool DiffDetected = false;
  int InterestingDeltaCount = 0;
  bool NeedsManualReview = false;
  bool OracleAuditCandidate = false;
  bool CaseStudyCandidate = false;
  std::string ManualTruthStatus = "not_started";
  std::vector<std::string> ExecutedResolvers;
  std::vector<ResolverPairDifference> ResolverDifferences;
  std::vector<std::string> Notes;
};

std::vector<CacheRecord> parseCacheDump(const std::string &Resolver,
                                        const std::filesystem::path &DumpPath);
CacheDiffResult buildCacheDiff(const std::string &SampleId,
                               const std::vector<CacheRecord> &Bind9Before,
                               const std::vector<CacheRecord> &Bind9After,
                               const std::vector<CacheRecord> &UnboundBefore,
                               const std::vector<CacheRecord> &UnboundAfter,
                               bool Triggered);
CacheDiffResult buildCacheDiff(
    const std::string &SampleId,
    const std::map<std::string, std::vector<CacheRecord>> &BeforeByResolver,
    const std::map<std::string, std::vector<CacheRecord>> &AfterByResolver,
    bool Triggered,
    const std::string &CompatibilitySecondaryResolver);
TriageRecord buildTriageRecord(const std::string &SampleId,
                               const json::Value::Object &OraclePayload,
                               const CacheDiffResult &CacheDiff,
                               const StateFingerprint &Fingerprint,
                               const std::optional<FailureEvidence> &Failure);
TriageRecord buildTriageRecord(
    const std::string &SampleId,
    const std::map<std::string, json::Value::Object> &OracleByResolver,
    const CacheDiffResult &CacheDiff, const StateFingerprint &Fingerprint,
    const std::optional<FailureEvidence> &Failure);

json::Value toJson(const CacheDeltaItem &Input);
json::Value toJson(const ResolverCacheDiff &Input);
json::Value toJson(const ResolverPairCacheDifference &Input);
json::Value toJson(const ResolverPairDifference &Input);
json::Value toJson(const CacheDiffResult &Input);
json::Value toJson(const TriageRecord &Input);

} // namespace dnslab
