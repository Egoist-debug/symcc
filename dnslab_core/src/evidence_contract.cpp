#include "dnslab_core/evidence_contract.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <set>
#include <sstream>

namespace dnslab {

namespace {

template <typename T>
std::optional<T> normalizeOptional(const std::optional<T> &Input) {
  if (!Input.has_value()) {
    return std::nullopt;
  }
  if constexpr (std::is_same_v<T, std::string>) {
    if (Input->empty()) {
      return std::nullopt;
    }
  }
  return Input;
}

bool isIsoTimestamp(const std::string &Input) {
  if (Input.size() < 20U) {
    return false;
  }
  return Input[4] == '-' && Input[7] == '-' && Input[10] == 'T' &&
         Input.back() == 'Z';
}

AggregationKey normalizeAggregationKey(const AggregationKey &Input,
                                       int ContractVersion) {
  AggregationKey Output = Input;
  Output.ContractVersion = ContractVersion;
  return Output;
}

BaselineCompareKey normalizeBaselineKey(const BaselineCompareKey &Input,
                                        int ContractVersion) {
  BaselineCompareKey Output = Input;
  Output.ContractVersion = ContractVersion;
  return Output;
}

bool sameAggregationKey(const AggregationKey &Left, const AggregationKey &Right,
                        std::vector<std::string> *ConflictFields) {
  const auto check = [&](const auto &FieldLeft, const auto &FieldRight,
                         const char *FieldName) {
    if (FieldLeft != FieldRight) {
      ConflictFields->push_back(FieldName);
    }
  };

  check(Left.ResolverPair, Right.ResolverPair, "resolver_pair");
  check(Left.ProducerProfile, Right.ProducerProfile, "producer_profile");
  check(Left.InputModel, Right.InputModel, "input_model");
  check(Left.SourceQueueDir, Right.SourceQueueDir, "source_queue_dir");
  check(Left.BudgetSec, Right.BudgetSec, "budget_sec");
  check(Left.SeedTimeoutSec, Right.SeedTimeoutSec, "seed_timeout_sec");
  check(Left.VariantName, Right.VariantName, "variant_name");
  check(Left.AblationStatus, Right.AblationStatus, "ablation_status");
  if (Left.ContractVersion != Right.ContractVersion) {
    ConflictFields->push_back("contract_version");
  }

  return ConflictFields->empty();
}

bool sameBaselineKey(const BaselineCompareKey &Left,
                     const BaselineCompareKey &Right,
                     std::vector<std::string> *ConflictFields) {
  const auto check = [&](const auto &FieldLeft, const auto &FieldRight,
                         const char *FieldName) {
    if (FieldLeft != FieldRight) {
      ConflictFields->push_back(FieldName);
    }
  };

  check(Left.ResolverPair, Right.ResolverPair, "resolver_pair");
  check(Left.ProducerProfile, Right.ProducerProfile, "producer_profile");
  check(Left.InputModel, Right.InputModel, "input_model");
  check(Left.SourceQueueDir, Right.SourceQueueDir, "source_queue_dir");
  check(Left.BudgetSec, Right.BudgetSec, "budget_sec");
  check(Left.SeedTimeoutSec, Right.SeedTimeoutSec, "seed_timeout_sec");
  check(Left.RepeatCount, Right.RepeatCount, "repeat_count");
  if (Left.ContractVersion != Right.ContractVersion) {
    ConflictFields->push_back("contract_version");
  }

  return ConflictFields->empty();
}

std::vector<std::string> missingAggregationFields(const AggregationKey &Input) {
  std::vector<std::string> Output;
  if (!Input.ResolverPair.has_value()) {
    Output.push_back("resolver_pair");
  }
  if (!Input.ProducerProfile.has_value()) {
    Output.push_back("producer_profile");
  }
  if (!Input.InputModel.has_value()) {
    Output.push_back("input_model");
  }
  if (!Input.SourceQueueDir.has_value()) {
    Output.push_back("source_queue_dir");
  }
  if (!Input.BudgetSec.has_value()) {
    Output.push_back("budget_sec");
  }
  if (!Input.SeedTimeoutSec.has_value()) {
    Output.push_back("seed_timeout_sec");
  }
  if (!Input.VariantName.has_value()) {
    Output.push_back("variant_name");
  }
  if (!Input.AblationStatus.has_value()) {
    Output.push_back("ablation_status");
  }
  if (Input.ContractVersion < 1) {
    Output.push_back("contract_version");
  }
  return Output;
}

std::vector<std::string> missingBaselineFields(const BaselineCompareKey &Input) {
  std::vector<std::string> Output;
  if (!Input.ResolverPair.has_value()) {
    Output.push_back("resolver_pair");
  }
  if (!Input.ProducerProfile.has_value()) {
    Output.push_back("producer_profile");
  }
  if (!Input.InputModel.has_value()) {
    Output.push_back("input_model");
  }
  if (!Input.SourceQueueDir.has_value()) {
    Output.push_back("source_queue_dir");
  }
  if (!Input.BudgetSec.has_value()) {
    Output.push_back("budget_sec");
  }
  if (!Input.SeedTimeoutSec.has_value()) {
    Output.push_back("seed_timeout_sec");
  }
  if (!Input.RepeatCount.has_value()) {
    Output.push_back("repeat_count");
  }
  if (Input.ContractVersion < 1) {
    Output.push_back("contract_version");
  }
  return Output;
}

void sortUnique(std::vector<std::string> &Values) {
  std::sort(Values.begin(), Values.end());
  Values.erase(std::unique(Values.begin(), Values.end()), Values.end());
}

} // namespace

std::string utcTimestampNow() {
  const auto Now = std::chrono::system_clock::now();
  const std::time_t Seconds = std::chrono::system_clock::to_time_t(Now);
  std::tm Utc {};
  gmtime_r(&Seconds, &Utc);
  char Buffer[32] = {0};
  std::strftime(Buffer, sizeof(Buffer), "%Y-%m-%dT%H:%M:%SZ", &Utc);
  return Buffer;
}

std::string toString(AnalysisState Input) {
  switch (Input) {
  case AnalysisState::Included:
    return "included";
  case AnalysisState::Excluded:
    return "excluded";
  case AnalysisState::Unknown:
    return "unknown";
  }
  return "unknown";
}

AnalysisState analysisStateFromString(const std::optional<std::string> &Input) {
  if (!Input.has_value()) {
    return AnalysisState::Unknown;
  }
  if (*Input == "included") {
    return AnalysisState::Included;
  }
  if (*Input == "excluded") {
    return AnalysisState::Excluded;
  }
  return AnalysisState::Unknown;
}

SampleMeta buildSampleMeta(const std::string &SampleId) {
  SampleMeta Output;
  Output.SampleId = SampleId;
  Output.GeneratedAt = utcTimestampNow();
  Output.FirstSeenTs = Output.GeneratedAt;
  return Output;
}

SampleMeta applySampleMetaContractDefaults(const SampleMeta &Input) {
  SampleMeta Output = Input;
  if (Output.SchemaVersion < 1) {
    Output.SchemaVersion = kSchemaVersion;
  }
  if (Output.ContractVersion < 1) {
    Output.ContractVersion = Output.SchemaVersion;
  }
  if (Output.GeneratedAt.empty()) {
    Output.GeneratedAt = utcTimestampNow();
  }
  if (Output.FirstSeenTs.empty()) {
    Output.FirstSeenTs = Output.GeneratedAt;
  }
  Output.ExcludeReason = normalizeOptional(Output.ExcludeReason);
  Output.Aggregation =
      normalizeAggregationKey(Output.Aggregation, Output.ContractVersion);
  Output.BaselineCompare =
      normalizeBaselineKey(Output.BaselineCompare, Output.ContractVersion);
  if (Output.Provenance.has_value()) {
    Output.Provenance->SeedSourceDir =
        normalizeOptional(Output.Provenance->SeedSourceDir);
    Output.Provenance->SeedMaterializationMethod =
        normalizeOptional(Output.Provenance->SeedMaterializationMethod);
    Output.Provenance->SeedSnapshotId =
        normalizeOptional(Output.Provenance->SeedSnapshotId);
    Output.Provenance->StableInputDir =
        normalizeOptional(Output.Provenance->StableInputDir);
    Output.Provenance->RecordedAt =
        normalizeOptional(Output.Provenance->RecordedAt);
  }
  return Output;
}

std::vector<std::string> validateSeedProvenance(const SeedProvenance &Input) {
  std::vector<std::string> Errors;
  if (!Input.SeedSourceDir.has_value()) {
    Errors.push_back("seed_source_dir 缺失");
  }
  if (!Input.SeedMaterializationMethod.has_value()) {
    Errors.push_back("seed_materialization_method 缺失");
  }
  if (!Input.SeedSnapshotId.has_value()) {
    Errors.push_back("seed_snapshot_id 缺失");
  }
  if (!Input.StableInputDir.has_value()) {
    Errors.push_back("stable_input_dir 缺失");
  }
  if (!Input.RecordedAt.has_value()) {
    Errors.push_back("recorded_at 缺失");
  } else if (!isIsoTimestamp(*Input.RecordedAt)) {
    Errors.push_back("recorded_at 必须是 ISO-8601 UTC 时间戳");
  }
  if (Input.TranscriptFormatVersion.has_value() &&
      *Input.TranscriptFormatVersion < 1) {
    Errors.push_back("transcript_format_version 必须 >= 1");
  }
  if (Input.TranscriptMaxResponses.has_value() &&
      *Input.TranscriptMaxResponses < 1) {
    Errors.push_back("transcript_max_responses 必须 >= 1");
  }
  if (Input.ResponsePreserve.has_value() && *Input.ResponsePreserve < 0) {
    Errors.push_back("response_preserve 必须 >= 0");
  }
  return Errors;
}

std::vector<std::string> validateSampleMeta(const SampleMeta &Input) {
  const SampleMeta Normalized = applySampleMetaContractDefaults(Input);
  std::vector<std::string> Errors;
  if (Normalized.SampleId.empty()) {
    Errors.push_back("sample_id 缺失");
  }
  if (!isIsoTimestamp(Normalized.GeneratedAt)) {
    Errors.push_back("generated_at 必须是 ISO-8601 UTC 时间戳");
  }
  if (!isIsoTimestamp(Normalized.FirstSeenTs)) {
    Errors.push_back("first_seen_ts 必须是 ISO-8601 UTC 时间戳");
  }
  if (Normalized.ContractVersion < 1) {
    Errors.push_back("contract_version 必须 >= 1");
  }
  if (Normalized.SchemaVersion < 1) {
    Errors.push_back("schema_version 必须 >= 1");
  }
  if (Normalized.State == AnalysisState::Excluded &&
      !Normalized.ExcludeReason.has_value()) {
    Errors.push_back("analysis_state=excluded 时必须提供 exclude_reason");
  }

  const auto MissingAggregation = missingAggregationFields(Normalized.Aggregation);
  for (const auto &Field : MissingAggregation) {
    Errors.push_back("aggregation_key 缺少字段: " + Field);
  }
  const auto MissingBaseline = missingBaselineFields(Normalized.BaselineCompare);
  for (const auto &Field : MissingBaseline) {
    Errors.push_back("baseline_compare_key 缺少字段: " + Field);
  }

  if (Normalized.Provenance.has_value()) {
    const auto NestedErrors = validateSeedProvenance(*Normalized.Provenance);
    Errors.insert(Errors.end(), NestedErrors.begin(), NestedErrors.end());
  }
  return Errors;
}

std::vector<std::string>
validateStateFingerprint(const StateFingerprint &Input) {
  std::vector<std::string> Errors;
  if (Input.SchemaVersion < 1) {
    Errors.push_back("schema_version 必须 >= 1");
  }
  if (!isIsoTimestamp(Input.GeneratedAt)) {
    Errors.push_back("generated_at 必须是 ISO-8601 UTC 时间戳");
  }
  return Errors;
}

RunComparabilityPayload
buildRunComparabilityPayload(const std::vector<SampleMeta> &Records) {
  RunComparabilityPayload Output;
  Output.SampleCount = Records.size();
  Output.Status = "non_comparable";
  Output.Reason = Records.empty() ? "no_samples" : "ok";

  std::optional<AggregationKey> ReferenceAggregation;
  std::optional<BaselineCompareKey> ReferenceBaseline;

  for (size_t Index = 0; Index < Records.size(); ++Index) {
    const SampleMeta Normalized = applySampleMetaContractDefaults(Records[Index]);
    const auto MissingAggregation = missingAggregationFields(Normalized.Aggregation);
    const auto MissingBaseline = missingBaselineFields(Normalized.BaselineCompare);
    if (!MissingAggregation.empty() || !MissingBaseline.empty()) {
      ComparabilityIssue Issue;
      Issue.SampleId = Normalized.SampleId.empty()
                           ? ("sample-" + std::to_string(Index + 1))
                           : Normalized.SampleId;
      Issue.Reason = "missing_comparability_fields";
      Issue.MissingAggregationKeyFields = MissingAggregation;
      Issue.MissingBaselineCompareKeyFields = MissingBaseline;
      Output.NonComparableSampleIds.push_back(Issue.SampleId);
      Output.Issues.push_back(Issue);
      Output.Reason = "missing_comparability_fields";
      continue;
    }

    ++Output.FullKeySampleCount;
    if (!ReferenceAggregation.has_value()) {
      ReferenceAggregation = Normalized.Aggregation;
    } else {
      std::vector<std::string> Conflicts;
      if (!sameAggregationKey(*ReferenceAggregation, Normalized.Aggregation,
                              &Conflicts)) {
        ComparabilityIssue Issue;
        Issue.SampleId = Normalized.SampleId;
        Issue.Reason = "aggregation_key_conflict";
        Issue.AggregationKeyConflictFields = Conflicts;
        Output.NonComparableSampleIds.push_back(Issue.SampleId);
        Output.Issues.push_back(Issue);
        Output.AggregationKeyConflictFields.insert(
            Output.AggregationKeyConflictFields.end(), Conflicts.begin(),
            Conflicts.end());
        if (Output.Reason == "ok") {
          Output.Reason = "aggregation_key_conflict";
        }
      }
    }

    if (!ReferenceBaseline.has_value()) {
      ReferenceBaseline = Normalized.BaselineCompare;
    } else {
      std::vector<std::string> Conflicts;
      if (!sameBaselineKey(*ReferenceBaseline, Normalized.BaselineCompare,
                           &Conflicts)) {
        ComparabilityIssue Issue;
        Issue.SampleId = Normalized.SampleId;
        Issue.Reason = "baseline_compare_key_conflict";
        Issue.BaselineCompareKeyConflictFields = Conflicts;
        Output.NonComparableSampleIds.push_back(Issue.SampleId);
        Output.Issues.push_back(Issue);
        Output.BaselineCompareKeyConflictFields.insert(
            Output.BaselineCompareKeyConflictFields.end(), Conflicts.begin(),
            Conflicts.end());
        if (Output.Reason == "ok") {
          Output.Reason = "baseline_compare_key_conflict";
        }
      }
    }
  }

  sortUnique(Output.NonComparableSampleIds);
  sortUnique(Output.AggregationKeyConflictFields);
  sortUnique(Output.BaselineCompareKeyConflictFields);

  Output.AggregationComparable =
      !Records.empty() && Output.FullKeySampleCount == Records.size() &&
      Output.AggregationKeyConflictFields.empty();
  Output.BaselineComparable =
      !Records.empty() && Output.FullKeySampleCount == Records.size() &&
      Output.BaselineCompareKeyConflictFields.empty();
  Output.Comparable =
      Output.AggregationComparable && Output.BaselineComparable;
  Output.Status = Output.Comparable ? "comparable" : "non_comparable";
  Output.ComparableSampleCount = Output.Comparable ? Records.size() : 0;
  Output.NonComparableSampleCount =
      Output.SampleCount - Output.ComparableSampleCount;

  if (Output.AggregationComparable && ReferenceAggregation.has_value()) {
    Output.Aggregation = ReferenceAggregation;
  }
  if (Output.BaselineComparable && ReferenceBaseline.has_value()) {
    Output.BaselineCompare = ReferenceBaseline;
  }
  return Output;
}

json::Value toJson(const AggregationKey &Input) {
  json::Value::Object Output;
  json::setOptional(Output, "resolver_pair", Input.ResolverPair);
  json::setOptional(Output, "producer_profile", Input.ProducerProfile);
  json::setOptional(Output, "input_model", Input.InputModel);
  json::setOptional(Output, "source_queue_dir", Input.SourceQueueDir);
  json::setOptional(Output, "budget_sec", Input.BudgetSec);
  json::setOptional(Output, "seed_timeout_sec", Input.SeedTimeoutSec);
  json::setOptional(Output, "variant_name", Input.VariantName);
  json::setOptional(Output, "ablation_status", Input.AblationStatus);
  Output["contract_version"] = Input.ContractVersion;
  return Output;
}

json::Value toJson(const BaselineCompareKey &Input) {
  json::Value::Object Output;
  json::setOptional(Output, "resolver_pair", Input.ResolverPair);
  json::setOptional(Output, "producer_profile", Input.ProducerProfile);
  json::setOptional(Output, "input_model", Input.InputModel);
  json::setOptional(Output, "source_queue_dir", Input.SourceQueueDir);
  json::setOptional(Output, "budget_sec", Input.BudgetSec);
  json::setOptional(Output, "seed_timeout_sec", Input.SeedTimeoutSec);
  json::setOptional(Output, "repeat_count", Input.RepeatCount);
  Output["contract_version"] = Input.ContractVersion;
  return Output;
}

json::Value toJson(const SeedProvenance &Input) {
  json::Value::Object Output;
  Output["cold_start"] = Input.ColdStart;
  json::setOptional(Output, "seed_source_dir", Input.SeedSourceDir);
  json::setOptional(Output, "seed_materialization_method",
                    Input.SeedMaterializationMethod);
  json::setOptional(Output, "seed_snapshot_id", Input.SeedSnapshotId);
  Output["regen_seeds"] = Input.RegenSeeds;
  Output["refilter_queries"] = Input.RefilterQueries;
  json::setOptional(Output, "stable_input_dir", Input.StableInputDir);
  json::setOptional(Output, "transcript_format_version",
                    Input.TranscriptFormatVersion);
  json::setOptional(Output, "transcript_max_responses",
                    Input.TranscriptMaxResponses);
  json::setOptional(Output, "response_preserve", Input.ResponsePreserve);
  json::setOptional(Output, "recorded_at", Input.RecordedAt);
  return Output;
}

json::Value toJson(const FailureEvidence &Input) {
  json::Value::Object Output;
  json::setOptional(Output, "kind", Input.Kind);
  json::setOptional(Output, "reason", Input.Reason);
  json::setOptional(Output, "message", Input.Message);
  json::setOptional(Output, "exit_code", Input.ExitCode);
  json::setOptional(Output, "returncode", Input.ReturnCode);
  json::setOptional(Output, "stage", Input.Stage);
  json::setOptional(Output, "resolver", Input.Resolver);
  json::setOptional(Output, "process_started", Input.ProcessStarted);
  json::setOptional(Output, "artifact_path", Input.ArtifactPath);
  json::setOptional(Output, "stderr_path", Input.StderrPath);
  json::setOptional(Output, "executable_path", Input.ExecutablePath);
  return Output;
}

json::Value toJson(const SampleMeta &Input) {
  const SampleMeta Normalized = applySampleMetaContractDefaults(Input);
  json::Value::Object Output;
  Output["schema_version"] = Normalized.SchemaVersion;
  Output["contract_version"] = Normalized.ContractVersion;
  Output["generated_at"] = Normalized.GeneratedAt;
  Output["sample_id"] = Normalized.SampleId;
  json::setOptional(Output, "queue_event_id", Normalized.QueueEventId);
  json::setOptional(Output, "source_queue_file", Normalized.SourceQueueFile);
  json::setOptional(Output, "source_resolver", Normalized.SourceResolver);
  json::setOptional(Output, "sample_sha1", Normalized.SampleSha1);
  json::setOptional(Output, "sample_size", Normalized.SampleSize);
  json::setOptional(Output, "is_stateful", Normalized.IsStateful);
  json::Value::Array Tags;
  for (const auto &Tag : Normalized.AflTags) {
    Tags.emplace_back(Tag);
  }
  Output["afl_tags"] = Tags;
  Output["first_seen_ts"] = Normalized.FirstSeenTs;
  json::setOptional(Output, "status", Normalized.Status);
  Output["analysis_state"] = toString(Normalized.State);
  json::setOptional(Output, "exclude_reason", Normalized.ExcludeReason);
  Output["aggregation_key"] = toJson(Normalized.Aggregation);
  Output["baseline_compare_key"] = toJson(Normalized.BaselineCompare);
  if (Normalized.Provenance.has_value()) {
    Output["seed_provenance"] = toJson(*Normalized.Provenance);
  }
  if (Normalized.Failure.has_value()) {
    Output["failure"] = toJson(*Normalized.Failure);
  }
  return Output;
}

json::Value toJson(const StateFingerprint &Input) {
  json::Value::Object Output;
  Output["schema_version"] = Input.SchemaVersion;
  Output["generated_at"] = Input.GeneratedAt;
  json::setOptional(Output, "sample_id", Input.SampleId);
  json::setOptional(Output, "bind9.forwarding_path", Input.Bind9ForwardingPath);
  json::setOptional(Output, "bind9.retry_seen", Input.Bind9RetrySeen);
  json::setOptional(Output, "bind9.msg_cache_seen", Input.Bind9MsgCacheSeen);
  json::setOptional(Output, "bind9.rrset_cache_seen", Input.Bind9RrsetCacheSeen);
  json::setOptional(Output, "bind9.negative_cache_seen",
                    Input.Bind9NegativeCacheSeen);
  json::setOptional(Output, "unbound.forwarding_path",
                    Input.UnboundForwardingPath);
  json::setOptional(Output, "unbound.retry_seen", Input.UnboundRetrySeen);
  json::setOptional(Output, "unbound.msg_cache_seen", Input.UnboundMsgCacheSeen);
  json::setOptional(Output, "unbound.rrset_cache_seen",
                    Input.UnboundRrsetCacheSeen);
  json::setOptional(Output, "unbound.negative_cache_seen",
                    Input.UnboundNegativeCacheSeen);
  return Output;
}

json::Value toJson(const FollowDiffWindowSummary &Input) {
  json::Value::Object Output;
  Output["budget_sec"] = Input.BudgetSec;
  Output["deadline_ts"] = Input.DeadlineTs;
  json::setOptional(Output, "queue_tail_id", Input.QueueTailId);
  Output["exit_reason"] = Input.ExitReason;
  Output["exit_code"] = Input.ExitCode;
  Output["completed_count"] = Input.CompletedCount;
  Output["failed_count"] = Input.FailedCount;
  json::setOptional(Output, "last_queue_event_id", Input.LastQueueEventId);
  Output["aggregation_key"] = toJson(Input.Aggregation);
  Output["baseline_compare_key"] = toJson(Input.BaselineCompare);
  if (Input.Provenance.has_value()) {
    Output["seed_provenance"] = toJson(*Input.Provenance);
  }
  return Output;
}

json::Value toJson(const ComparabilityIssue &Input) {
  json::Value::Object Output;
  Output["sample_id"] = Input.SampleId;
  Output["reason"] = Input.Reason;
  json::Value::Array MissingAggregation;
  for (const auto &Field : Input.MissingAggregationKeyFields) {
    MissingAggregation.emplace_back(Field);
  }
  Output["missing_aggregation_key_fields"] = MissingAggregation;
  json::Value::Array MissingBaseline;
  for (const auto &Field : Input.MissingBaselineCompareKeyFields) {
    MissingBaseline.emplace_back(Field);
  }
  Output["missing_baseline_compare_key_fields"] = MissingBaseline;
  json::Value::Array AggregationConflicts;
  for (const auto &Field : Input.AggregationKeyConflictFields) {
    AggregationConflicts.emplace_back(Field);
  }
  Output["aggregation_key_conflict_fields"] = AggregationConflicts;
  json::Value::Array BaselineConflicts;
  for (const auto &Field : Input.BaselineCompareKeyConflictFields) {
    BaselineConflicts.emplace_back(Field);
  }
  Output["baseline_compare_key_conflict_fields"] = BaselineConflicts;
  return Output;
}

json::Value toJson(const RunComparabilityPayload &Input) {
  json::Value::Object Output;
  Output["status"] = Input.Status;
  Output["comparable"] = Input.Comparable;
  Output["aggregation_comparable"] = Input.AggregationComparable;
  Output["baseline_comparable"] = Input.BaselineComparable;
  Output["reason"] = Input.Reason;
  Output["sample_count"] = static_cast<std::int64_t>(Input.SampleCount);
  Output["full_key_sample_count"] =
      static_cast<std::int64_t>(Input.FullKeySampleCount);
  Output["comparable_sample_count"] =
      static_cast<std::int64_t>(Input.ComparableSampleCount);
  Output["non_comparable_sample_count"] =
      static_cast<std::int64_t>(Input.NonComparableSampleCount);

  json::Value::Array SampleIds;
  for (const auto &SampleId : Input.NonComparableSampleIds) {
    SampleIds.emplace_back(SampleId);
  }
  Output["non_comparable_sample_ids"] = SampleIds;

  json::Value::Array AggregationConflicts;
  for (const auto &Field : Input.AggregationKeyConflictFields) {
    AggregationConflicts.emplace_back(Field);
  }
  Output["aggregation_key_conflict_fields"] = AggregationConflicts;

  json::Value::Array BaselineConflicts;
  for (const auto &Field : Input.BaselineCompareKeyConflictFields) {
    BaselineConflicts.emplace_back(Field);
  }
  Output["baseline_compare_key_conflict_fields"] = BaselineConflicts;

  if (Input.Aggregation.has_value()) {
    Output["aggregation_key"] = toJson(*Input.Aggregation);
  } else {
    Output["aggregation_key"] = json::Value();
  }
  if (Input.BaselineCompare.has_value()) {
    Output["baseline_compare_key"] = toJson(*Input.BaselineCompare);
  } else {
    Output["baseline_compare_key"] = json::Value();
  }

  json::Value::Array Issues;
  for (const auto &Issue : Input.Issues) {
    Issues.emplace_back(toJson(Issue));
  }
  Output["issues"] = Issues;
  return Output;
}

} // namespace dnslab
