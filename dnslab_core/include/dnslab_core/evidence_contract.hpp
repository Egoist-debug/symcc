#pragma once

#include "dnslab_core/json_value.hpp"

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace dnslab {

inline constexpr int kSchemaVersion = 1;
inline constexpr int kContractVersion = 1;

enum class AnalysisState {
  Included,
  Excluded,
  Unknown,
};

struct AggregationKey {
  std::optional<std::string> ResolverPair;
  std::optional<std::string> ProducerProfile;
  std::optional<std::string> InputModel;
  std::optional<std::string> SourceQueueDir;
  std::optional<int> BudgetSec;
  std::optional<int> SeedTimeoutSec;
  std::optional<std::string> VariantName;
  std::optional<std::map<std::string, std::string>> AblationStatus;
  int ContractVersion = kContractVersion;
};

struct BaselineCompareKey {
  std::optional<std::string> ResolverPair;
  std::optional<std::string> ProducerProfile;
  std::optional<std::string> InputModel;
  std::optional<std::string> SourceQueueDir;
  std::optional<int> BudgetSec;
  std::optional<int> SeedTimeoutSec;
  std::optional<int> RepeatCount;
  int ContractVersion = kContractVersion;
};

struct SeedProvenance {
  bool ColdStart = false;
  std::optional<std::string> SeedSourceDir;
  std::optional<std::string> SeedMaterializationMethod;
  std::optional<std::string> SeedSnapshotId;
  bool RegenSeeds = false;
  bool RefilterQueries = false;
  std::optional<std::string> StableInputDir;
  std::optional<int> TranscriptFormatVersion;
  std::optional<int> TranscriptMaxResponses;
  std::optional<int> ResponsePreserve;
  std::optional<std::string> RecordedAt;
};

struct FailureEvidence {
  std::optional<std::string> Kind;
  std::optional<std::string> Reason;
  std::optional<std::string> Message;
  std::optional<int> ExitCode;
  std::optional<int> ReturnCode;
  std::optional<int> TimeoutSec;
  std::optional<std::string> Stage;
  std::optional<std::string> Resolver;
  std::optional<bool> ProcessStarted;
  std::optional<std::string> ArtifactPath;
  std::optional<std::string> StderrPath;
  std::optional<std::string> ExecutablePath;
};

struct SampleMeta {
  int SchemaVersion = kSchemaVersion;
  int ContractVersion = kContractVersion;
  std::string GeneratedAt;
  std::string SampleId;
  std::optional<std::string> QueueEventId;
  std::optional<std::string> SourceQueueFile;
  std::optional<std::string> SourceResolver;
  std::optional<std::string> SampleSha1;
  std::optional<int> SampleSize;
  std::optional<bool> IsStateful;
  std::vector<std::string> AflTags;
  std::string FirstSeenTs;
  std::optional<std::string> Status;
  AnalysisState State = AnalysisState::Unknown;
  std::optional<std::string> ExcludeReason;
  AggregationKey Aggregation;
  BaselineCompareKey BaselineCompare;
  std::optional<SeedProvenance> Provenance;
  std::optional<FailureEvidence> Failure;
};

struct StateFingerprint {
  int SchemaVersion = kSchemaVersion;
  std::string GeneratedAt;
  std::optional<std::string> SampleId;
  std::optional<std::string> Bind9ForwardingPath;
  std::optional<bool> Bind9RetrySeen;
  std::optional<bool> Bind9MsgCacheSeen;
  std::optional<bool> Bind9RrsetCacheSeen;
  std::optional<bool> Bind9NegativeCacheSeen;
  std::optional<std::string> UnboundForwardingPath;
  std::optional<bool> UnboundRetrySeen;
  std::optional<bool> UnboundMsgCacheSeen;
  std::optional<bool> UnboundRrsetCacheSeen;
  std::optional<bool> UnboundNegativeCacheSeen;
};

struct FollowDiffWindowSummary {
  double BudgetSec = 0;
  std::string DeadlineTs;
  std::optional<std::string> QueueTailId;
  std::string ExitReason;
  int ExitCode = 0;
  int CompletedCount = 0;
  int FailedCount = 0;
  std::optional<std::string> LastQueueEventId;
  AggregationKey Aggregation;
  BaselineCompareKey BaselineCompare;
  std::optional<SeedProvenance> Provenance;
};

struct ComparabilityIssue {
  std::string SampleId;
  std::string Reason;
  std::vector<std::string> MissingAggregationKeyFields;
  std::vector<std::string> MissingBaselineCompareKeyFields;
  std::vector<std::string> AggregationKeyConflictFields;
  std::vector<std::string> BaselineCompareKeyConflictFields;
};

struct RunComparabilityPayload {
  std::string Status;
  bool Comparable = false;
  bool AggregationComparable = false;
  bool BaselineComparable = false;
  std::string Reason;
  size_t SampleCount = 0;
  size_t FullKeySampleCount = 0;
  size_t ComparableSampleCount = 0;
  size_t NonComparableSampleCount = 0;
  std::vector<std::string> NonComparableSampleIds;
  std::vector<std::string> AggregationKeyConflictFields;
  std::vector<std::string> BaselineCompareKeyConflictFields;
  std::optional<AggregationKey> Aggregation;
  std::optional<BaselineCompareKey> BaselineCompare;
  std::vector<ComparabilityIssue> Issues;
};

std::string utcTimestampNow();
std::string toString(AnalysisState Input);
AnalysisState analysisStateFromString(const std::optional<std::string> &Input);

SampleMeta buildSampleMeta(const std::string &SampleId);
SampleMeta applySampleMetaContractDefaults(const SampleMeta &Input);
std::vector<std::string> validateSeedProvenance(const SeedProvenance &Input);
std::vector<std::string> validateSampleMeta(const SampleMeta &Input);
std::vector<std::string> validateStateFingerprint(const StateFingerprint &Input);
RunComparabilityPayload
buildRunComparabilityPayload(const std::vector<SampleMeta> &Records);

json::Value toJson(const AggregationKey &Input);
json::Value toJson(const BaselineCompareKey &Input);
json::Value toJson(const SeedProvenance &Input);
json::Value toJson(const FailureEvidence &Input);
json::Value toJson(const SampleMeta &Input);
json::Value toJson(const StateFingerprint &Input);
json::Value toJson(const FollowDiffWindowSummary &Input);
json::Value toJson(const ComparabilityIssue &Input);
json::Value toJson(const RunComparabilityPayload &Input);

} // namespace dnslab
