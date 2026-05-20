#include "dnslab_core/reporting.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace dnslab {

namespace {

constexpr const char *kSemanticFrontierManifestFileName =
    "semantic_frontier_manifest.json";
constexpr const char *kSemanticFrontierManifestContractName =
    "semantic_frontier_manifest";
constexpr const char *kPublicationEvidenceBundleContractName =
    "publication_evidence_bundle";
constexpr size_t kMaxCaseStudies = 5;

const std::vector<std::string> kOracleFields = {
    "parse_ok",          "resolver_fetch_started", "response_accepted",
    "second_query_hit",  "cache_entry_created",    "timeout",
};
const std::vector<std::string> kAuditColumns = {
    "sample_id",
    "triage_status",
    "analysis_state",
    "semantic_outcome",
    "oracle_audit_candidate",
    "manual_truth_status",
    "executed_resolvers",
    "skipped_resolvers_json",
    "diff_detected",
    "oracle_diff_fields",
    "response_accepted_any",
    "second_query_hit_any",
    "cache_entry_created_any",
    "resolver_diffs_json",
    "parse_ok_by_resolver_json",
    "response_accepted_by_resolver_json",
    "second_query_hit_by_resolver_json",
    "cache_entry_created_by_resolver_json",
    "sample_meta_path",
    "oracle_path",
    "cache_diff_path",
    "triage_path",
};
const std::vector<std::string> kFailureBucketPrimaryOrder = {
    "semantic_diff",       "valid_negative",       "input_parse_failure",
    "infra_artifact_failure", "orchestrator_compat_failure",
    "target_runtime_failure",
};
const std::map<std::string, std::string> kExclusionStateByPrimary = {
    {"semantic_diff", "included"},
    {"valid_negative", "included"},
    {"input_parse_failure", "unknown"},
    {"infra_artifact_failure", "excluded"},
    {"orchestrator_compat_failure", "excluded"},
    {"target_runtime_failure", "unknown"},
};
const std::vector<std::string> kAggregationKeyFields = {
    "resolver_pair",      "producer_profile", "input_model",
    "source_queue_dir",   "budget_sec",       "seed_timeout_sec",
    "variant_name",       "ablation_status",  "contract_version",
};
const std::vector<std::string> kBaselineCompareKeyFields = {
    "resolver_pair",      "producer_profile", "input_model",
    "source_queue_dir",   "budget_sec",       "seed_timeout_sec",
    "repeat_count",       "contract_version",
};

struct CampaignAuditRecord {
  std::string SampleId;
  std::string TriageStatus = "unknown";
  std::string AnalysisState = "unknown";
  std::string SemanticOutcome = "unknown";
  bool OracleAuditCandidate = false;
  std::string ManualTruthStatus = "not_applicable";
  std::vector<std::string> ExecutedResolvers;
  json::Value::Object SkippedResolvers;
  bool DiffDetected = false;
  json::Value::Object ParseOkByResolver;
  json::Value::Object ResponseAcceptedByResolver;
  json::Value::Object SecondQueryHitByResolver;
  json::Value::Object CacheEntryCreatedByResolver;
  std::vector<std::string> OracleDiffFields;
  json::Value::Array ResolverDiffs;
  std::filesystem::path SampleMetaPath;
  std::filesystem::path OraclePath;
  std::filesystem::path CacheDiffPath;
  std::filesystem::path TriagePath;
  bool SignalResponseAcceptedAny = false;
  bool SignalSecondQueryHitAny = false;
  bool SignalCacheEntryCreatedAny = false;
  bool SignalOracleDiffAny = false;
  bool SignalOracleDiffPlusCacheDiff = false;
};

struct CampaignReportSnapshot {
  std::filesystem::path Root;
  std::map<std::string, size_t> StatusCounter;
  std::map<std::string, size_t> ClusterCounter;
  std::map<std::string, std::vector<std::string>> ClusterSamples;
  std::vector<SemanticFrontierEntry> SemanticFrontierEntries;
  size_t TotalSamples = 0;
  std::vector<std::filesystem::path> SampleDirs;
  std::vector<json::Value::Object> SampleMetaPayloads;
  std::vector<CampaignAuditRecord> AuditRecords;
  std::map<std::string, size_t> AnalysisStateCounter;
  std::map<std::string, size_t> FailureBucketPrimaryCounter;
  std::map<std::pair<std::string, std::string>, size_t> FailureTaxonomyCounter;
  std::map<std::string, size_t> SemanticCounts;
  size_t NeedsReviewCount = 0;
  size_t OracleAuditCandidateCount = 0;
  size_t SemanticDiffCount = 0;
  std::optional<json::Value::Object> Comparability;
  std::optional<std::string> RunId;
  std::optional<json::Value::Object> StatePayload;
  std::optional<json::Value::Object> WindowSummaryPayload;
  std::optional<json::Value> SeedProvenance;
};

struct ContractKeyExtraction {
  std::optional<json::Value::Object> Value;
  std::vector<std::string> MissingFields;
};

std::string renderOptionalString(const std::optional<std::string> &Input) {
  return Input.has_value() ? *Input : "null";
}

std::string renderOptionalBool(const std::optional<bool> &Input) {
  if (!Input.has_value()) {
    return "null";
  }
  return *Input ? "true" : "false";
}

std::filesystem::path normalizePath(const std::filesystem::path &Input) {
  std::error_code Error;
  const auto Absolute = std::filesystem::absolute(Input, Error);
  if (Error) {
    return Input.lexically_normal();
  }
  return Absolute.lexically_normal();
}

bool isAnalysisStateValue(const std::string &Value) {
  return Value == "included" || Value == "excluded" || Value == "unknown";
}

bool isTier3SemanticOutcome(const std::string &Value) {
  return Value == "oracle_and_cache_diff" || Value == "oracle_diff" ||
         Value == "cache_diff_interesting";
}

int semanticOutcomeRank(const std::string &Value) {
  if (Value == "oracle_and_cache_diff") {
    return 0;
  }
  if (Value == "oracle_diff") {
    return 1;
  }
  if (Value == "cache_diff_interesting") {
    return 2;
  }
  return 3;
}

class JsonParser {
public:
  explicit JsonParser(const std::string &Input) : Input_(Input) {}

  json::Value parse() {
    auto Value = parseValue();
    skipWhitespace();
    if (Position_ != Input_.size()) {
      fail("存在多余尾随字符");
    }
    return Value;
  }

private:
  const std::string &Input_;
  size_t Position_ = 0;

  [[noreturn]] void fail(const std::string &Reason) const {
    throw std::runtime_error("JSON 解析失败: byte=" +
                             std::to_string(Position_) + " reason=" + Reason);
  }

  void skipWhitespace() {
    while (Position_ < Input_.size() &&
           std::isspace(static_cast<unsigned char>(Input_[Position_]))) {
      ++Position_;
    }
  }

  bool consumeIf(char Expected) {
    skipWhitespace();
    if (Position_ < Input_.size() && Input_[Position_] == Expected) {
      ++Position_;
      return true;
    }
    return false;
  }

  void expect(char Expected) {
    if (!consumeIf(Expected)) {
      fail(std::string("期望字符 ") + Expected);
    }
  }

  void expectLiteral(const std::string &Literal) {
    skipWhitespace();
    if (Input_.compare(Position_, Literal.size(), Literal) != 0) {
      fail("期望字面量 " + Literal);
    }
    Position_ += Literal.size();
  }

  static void appendUtf8(std::string &Output, std::uint32_t CodePoint) {
    if (CodePoint <= 0x7F) {
      Output.push_back(static_cast<char>(CodePoint));
      return;
    }
    if (CodePoint <= 0x7FF) {
      Output.push_back(static_cast<char>(0xC0U | ((CodePoint >> 6) & 0x1FU)));
      Output.push_back(static_cast<char>(0x80U | (CodePoint & 0x3FU)));
      return;
    }
    if (CodePoint <= 0xFFFF) {
      Output.push_back(static_cast<char>(0xE0U | ((CodePoint >> 12) & 0x0FU)));
      Output.push_back(static_cast<char>(0x80U | ((CodePoint >> 6) & 0x3FU)));
      Output.push_back(static_cast<char>(0x80U | (CodePoint & 0x3FU)));
      return;
    }
    Output.push_back(static_cast<char>(0xF0U | ((CodePoint >> 18) & 0x07U)));
    Output.push_back(static_cast<char>(0x80U | ((CodePoint >> 12) & 0x3FU)));
    Output.push_back(static_cast<char>(0x80U | ((CodePoint >> 6) & 0x3FU)));
    Output.push_back(static_cast<char>(0x80U | (CodePoint & 0x3FU)));
  }

  std::string parseString() {
    skipWhitespace();
    if (Position_ >= Input_.size() || Input_[Position_] != '"') {
      fail("期望字符串");
    }

    ++Position_;
    std::string Output;
    while (Position_ < Input_.size()) {
      const char Current = Input_[Position_++];
      if (Current == '"') {
        return Output;
      }
      if (Current != '\\') {
        Output.push_back(Current);
        continue;
      }

      if (Position_ >= Input_.size()) {
        fail("转义序列不完整");
      }
      const char Escaped = Input_[Position_++];
      switch (Escaped) {
      case '"':
      case '\\':
      case '/':
        Output.push_back(Escaped);
        break;
      case 'b':
        Output.push_back('\b');
        break;
      case 'f':
        Output.push_back('\f');
        break;
      case 'n':
        Output.push_back('\n');
        break;
      case 'r':
        Output.push_back('\r');
        break;
      case 't':
        Output.push_back('\t');
        break;
      case 'u': {
        if (Position_ + 4 > Input_.size()) {
          fail("Unicode 转义不完整");
        }
        std::uint32_t CodePoint = 0;
        for (int Index = 0; Index < 4; ++Index) {
          const char Hex = Input_[Position_++];
          CodePoint <<= 4;
          if (Hex >= '0' && Hex <= '9') {
            CodePoint |= static_cast<std::uint32_t>(Hex - '0');
          } else if (Hex >= 'a' && Hex <= 'f') {
            CodePoint |= static_cast<std::uint32_t>(10 + Hex - 'a');
          } else if (Hex >= 'A' && Hex <= 'F') {
            CodePoint |= static_cast<std::uint32_t>(10 + Hex - 'A');
          } else {
            fail("Unicode 转义非法");
          }
        }
        appendUtf8(Output, CodePoint);
        break;
      }
      default:
        fail(std::string("不支持的转义序列 \\") + Escaped);
      }
    }

    fail("字符串缺少结束引号");
  }

  json::Value parseNumber() {
    skipWhitespace();
    const auto Begin = Position_;
    if (Position_ < Input_.size() && Input_[Position_] == '-') {
      ++Position_;
    }
    if (Position_ >= Input_.size() ||
        !std::isdigit(static_cast<unsigned char>(Input_[Position_]))) {
      fail("数字格式非法");
    }
    while (Position_ < Input_.size() &&
           std::isdigit(static_cast<unsigned char>(Input_[Position_]))) {
      ++Position_;
    }
    bool IsDouble = false;
    if (Position_ < Input_.size() && Input_[Position_] == '.') {
      IsDouble = true;
      ++Position_;
      if (Position_ >= Input_.size() ||
          !std::isdigit(static_cast<unsigned char>(Input_[Position_]))) {
        fail("小数格式非法");
      }
      while (Position_ < Input_.size() &&
             std::isdigit(static_cast<unsigned char>(Input_[Position_]))) {
        ++Position_;
      }
    }
    if (Position_ < Input_.size() &&
        (Input_[Position_] == 'e' || Input_[Position_] == 'E')) {
      IsDouble = true;
      ++Position_;
      if (Position_ < Input_.size() &&
          (Input_[Position_] == '+' || Input_[Position_] == '-')) {
        ++Position_;
      }
      if (Position_ >= Input_.size() ||
          !std::isdigit(static_cast<unsigned char>(Input_[Position_]))) {
        fail("指数格式非法");
      }
      while (Position_ < Input_.size() &&
             std::isdigit(static_cast<unsigned char>(Input_[Position_]))) {
        ++Position_;
      }
    }
    const auto Token = Input_.substr(Begin, Position_ - Begin);
    if (IsDouble) {
      return json::Value(std::stod(Token));
    }
    return json::Value(static_cast<std::int64_t>(std::stoll(Token)));
  }

  json::Value parseArray() {
    expect('[');
    json::Value::Array Items;
    skipWhitespace();
    if (consumeIf(']')) {
      return json::Value(std::move(Items));
    }
    while (true) {
      Items.emplace_back(parseValue());
      skipWhitespace();
      if (consumeIf(']')) {
        return json::Value(std::move(Items));
      }
      expect(',');
    }
  }

  json::Value parseObject() {
    expect('{');
    json::Value::Object Output;
    skipWhitespace();
    if (consumeIf('}')) {
      return json::Value(std::move(Output));
    }
    while (true) {
      const auto Key = parseString();
      expect(':');
      Output[Key] = parseValue();
      skipWhitespace();
      if (consumeIf('}')) {
        return json::Value(std::move(Output));
      }
      expect(',');
    }
  }

  json::Value parseValue() {
    skipWhitespace();
    if (Position_ >= Input_.size()) {
      fail("意外结束");
    }
    switch (Input_[Position_]) {
    case '{':
      return parseObject();
    case '[':
      return parseArray();
    case '"':
      return json::Value(parseString());
    case 't':
      expectLiteral("true");
      return json::Value(true);
    case 'f':
      expectLiteral("false");
      return json::Value(false);
    case 'n':
      expectLiteral("null");
      return json::Value();
    default:
      if (Input_[Position_] == '-' ||
          std::isdigit(static_cast<unsigned char>(Input_[Position_]))) {
        return parseNumber();
      }
      fail(std::string("未知值起始字符 ") + Input_[Position_]);
    }
  }
};

std::string readTextFile(const std::filesystem::path &InputPath) {
  std::ifstream Input(InputPath);
  if (!Input) {
    throw std::runtime_error("无法读取文件: " + InputPath.string());
  }
  return std::string((std::istreambuf_iterator<char>(Input)),
                     std::istreambuf_iterator<char>());
}

void writeTextFile(const std::filesystem::path &OutputPath,
                   const std::string &Content) {
  std::filesystem::create_directories(OutputPath.parent_path());
  std::ofstream Output(OutputPath);
  if (!Output) {
    throw std::runtime_error("无法写入文件: " + OutputPath.string());
  }
  Output << Content;
}

void writeJsonFile(const std::filesystem::path &OutputPath,
                   const json::Value &Payload) {
  writeTextFile(OutputPath, Payload.dump(2) + "\n");
}

const json::Value *findObjectValue(const json::Value::Object &Object,
                                   const std::string &Key) {
  const auto Found = Object.find(Key);
  if (Found == Object.end()) {
    return nullptr;
  }
  return &Found->second;
}

std::string coerceText(const json::Value *Value, const std::string &Fallback) {
  if (Value == nullptr) {
    return Fallback;
  }
  if (const auto *Text = std::get_if<std::string>(&Value->storage())) {
    if (!Text->empty()) {
      return *Text;
    }
  }
  return Fallback;
}

std::optional<std::string> coerceOptionalText(const json::Value *Value) {
  if (Value == nullptr) {
    return std::nullopt;
  }
  if (const auto *Text = std::get_if<std::string>(&Value->storage())) {
    if (!Text->empty()) {
      return *Text;
    }
  }
  return std::nullopt;
}

bool coerceBool(const json::Value *Value) {
  if (Value == nullptr) {
    return false;
  }
  if (const auto *BoolValue = std::get_if<bool>(&Value->storage())) {
    return *BoolValue;
  }
  return false;
}

std::string coerceAnalysisState(const json::Value *Value) {
  const auto Text = coerceText(Value, "unknown");
  return isAnalysisStateValue(Text) ? Text : "unknown";
}

std::vector<std::string> coerceLabels(const json::Value *Value) {
  std::set<std::string> Labels;
  if (Value == nullptr) {
    return {};
  }
  if (const auto *Array = std::get_if<json::Value::Array>(&Value->storage())) {
    for (const auto &Item : *Array) {
      if (const auto *Text = std::get_if<std::string>(&Item.storage())) {
        if (!Text->empty()) {
          Labels.insert(*Text);
        }
      }
    }
  }
  return {Labels.begin(), Labels.end()};
}

std::string joinCsv(const std::vector<std::string> &Items) {
  std::ostringstream Stream;
  for (size_t Index = 0; Index < Items.size(); ++Index) {
    if (Index != 0) {
      Stream << ',';
    }
    Stream << Items[Index];
  }
  return Stream.str();
}

std::runtime_error buildTruthSourceError(const std::filesystem::path &SampleDir,
                                         const std::filesystem::path &Path,
                                         const std::string &Label,
                                         const std::string &Reason,
                                         const std::optional<std::string> &Detail =
                                             std::nullopt);

std::string compactTimestampNow() {
  const std::time_t Now = std::time(nullptr);
  std::tm Calendar{};
#if defined(_WIN32)
  gmtime_s(&Calendar, &Now);
#else
  gmtime_r(&Now, &Calendar);
#endif
  char Buffer[32];
  std::strftime(Buffer, sizeof(Buffer), "%Y%m%d_%H%M%S", &Calendar);
  return Buffer;
}

bool isMissingContractValue(const json::Value *Value) {
  if (Value == nullptr) {
    return true;
  }
  if (std::holds_alternative<std::nullptr_t>(Value->storage())) {
    return true;
  }
  if (const auto *Text = std::get_if<std::string>(&Value->storage())) {
    return Text->empty();
  }
  return false;
}

std::string stableJsonText(const json::Value &Value) { return Value.dump(0); }

std::int64_t coerceInt64(const json::Value *Value, std::int64_t Fallback) {
  if (Value == nullptr) {
    return Fallback;
  }
  if (const auto *IntValue = std::get_if<std::int64_t>(&Value->storage())) {
    return *IntValue;
  }
  if (const auto *DoubleValue = std::get_if<double>(&Value->storage())) {
    return static_cast<std::int64_t>(*DoubleValue);
  }
  return Fallback;
}

std::optional<json::Value::Object>
loadOptionalObject(const std::filesystem::path &ArtifactPath,
                   const std::filesystem::path &SampleDir,
                   const std::string &Label) {
  if (!std::filesystem::is_regular_file(ArtifactPath)) {
    return std::nullopt;
  }
  json::Value Payload;
  try {
    Payload = JsonParser(readTextFile(ArtifactPath)).parse();
  } catch (const std::exception &Error) {
    throw buildTruthSourceError(SampleDir, ArtifactPath, Label, "JSON 损坏",
                                Error.what());
  }
  if (const auto *Object = std::get_if<json::Value::Object>(&Payload.storage())) {
    return *Object;
  }
  throw buildTruthSourceError(SampleDir, ArtifactPath, Label,
                              "JSON 顶层类型无效（期望 object）");
}

std::runtime_error buildTruthSourceError(const std::filesystem::path &SampleDir,
                                         const std::filesystem::path &Path,
                                         const std::string &Label,
                                         const std::string &Reason,
                                         const std::optional<std::string> &Detail) {
  std::ostringstream Stream;
  Stream << "样本 semantic truth-source 无效: sample_dir="
         << normalizePath(SampleDir).string() << " file=" << Label
         << " path=" << normalizePath(Path).string() << " reason=" << Reason;
  if (Detail.has_value() && !Detail->empty()) {
    Stream << " detail=" << *Detail;
  }
  return std::runtime_error(Stream.str());
}

json::Value::Object loadRequiredObject(const std::filesystem::path &SampleDir,
                                       const std::string &FileName,
                                       const std::string &Label) {
  const auto ArtifactPath = SampleDir / FileName;
  if (!std::filesystem::is_regular_file(ArtifactPath)) {
    throw buildTruthSourceError(SampleDir, ArtifactPath, Label, "文件缺失");
  }

  json::Value Payload;
  try {
    Payload = JsonParser(readTextFile(ArtifactPath)).parse();
  } catch (const std::exception &Error) {
    throw buildTruthSourceError(SampleDir, ArtifactPath, Label, "JSON 损坏",
                                Error.what());
  }

  if (const auto *Object = std::get_if<json::Value::Object>(&Payload.storage())) {
    return *Object;
  }
  throw buildTruthSourceError(SampleDir, ArtifactPath, Label,
                              "JSON 顶层类型无效（期望 object）");
}

bool isSampleDir(const std::filesystem::path &Path) {
  return std::filesystem::is_directory(Path) &&
         (std::filesystem::is_regular_file(Path / "triage.json") ||
          std::filesystem::is_regular_file(Path / "sample.meta.json"));
}

std::vector<std::filesystem::path>
collectSampleDirs(const std::filesystem::path &Root) {
  std::vector<std::filesystem::path> Output;
  for (const auto &Entry : std::filesystem::directory_iterator(Root)) {
    if (isSampleDir(Entry.path())) {
      Output.push_back(Entry.path());
    }
  }
  std::sort(Output.begin(), Output.end());
  return Output;
}

json::Value::Object loadSampleMetaPayload(const std::filesystem::path &SampleDir) {
  auto Payload = loadRequiredObject(SampleDir, "sample.meta.json", "sample.meta.json");
  if (!findObjectValue(Payload, "sample_id")) {
    Payload["sample_id"] = SampleDir.filename().string();
  }
  return Payload;
}

json::Value::Object loadTriagePayload(const std::filesystem::path &SampleDir) {
  auto Payload = loadRequiredObject(SampleDir, "triage.json", "triage.json");
  if (!findObjectValue(Payload, "sample_id")) {
    Payload["sample_id"] = SampleDir.filename().string();
  }
  if (!findObjectValue(Payload, "status")) {
    Payload["status"] = "unknown";
  }
  if (!findObjectValue(Payload, "cluster_key")) {
    Payload["cluster_key"] = "_";
  }
  if (!findObjectValue(Payload, "diff_class")) {
    Payload["diff_class"] = "unknown";
  }
  if (!findObjectValue(Payload, "analysis_state")) {
    Payload["analysis_state"] = "unknown";
  }
  if (!findObjectValue(Payload, "semantic_outcome")) {
    Payload["semantic_outcome"] = "unknown";
  }
  if (!findObjectValue(Payload, "filter_labels")) {
    Payload["filter_labels"] = json::Value::Array{};
  }
  return Payload;
}

json::Value::Object
buildTriageFallbackPayload(const std::filesystem::path &SampleDir,
                           const json::Value::Object &SampleMetaPayload) {
  json::Value::Object Payload;
  Payload["sample_id"] =
      coerceText(findObjectValue(SampleMetaPayload, "sample_id"),
                 SampleDir.filename().string());
  Payload["status"] =
      coerceText(findObjectValue(SampleMetaPayload, "status"), "unknown");
  Payload["cluster_key"] = "_";
  Payload["diff_class"] = "unknown";
  Payload["analysis_state"] =
      coerceAnalysisState(findObjectValue(SampleMetaPayload, "analysis_state"));
  Payload["semantic_outcome"] =
      coerceText(findObjectValue(SampleMetaPayload, "semantic_outcome"),
                 "unknown");
  Payload["oracle_audit_candidate"] = false;
  Payload["needs_manual_review"] = false;
  Payload["filter_labels"] = json::Value::Array{};
  return Payload;
}

std::optional<std::filesystem::path>
resolveSampleArtifactPath(const std::filesystem::path &SampleDir) {
  const auto SamplePath = SampleDir / "sample.bin";
  if (std::filesystem::is_regular_file(SamplePath)) {
    return SamplePath;
  }
  const auto TranscriptPath = SampleDir / "transcript";
  if (std::filesystem::is_regular_file(TranscriptPath)) {
    return TranscriptPath;
  }
  return std::nullopt;
}

std::optional<std::filesystem::path>
resolveSemanticFrontierSamplePath(const std::filesystem::path &SampleDir,
                                  const json::Value::Object &SampleMetaPayload) {
  if (const auto SourceQueueFile =
          coerceOptionalText(findObjectValue(SampleMetaPayload,
                                             "source_queue_file"))) {
    const auto QueuePath = normalizePath(*SourceQueueFile);
    if (std::filesystem::is_regular_file(QueuePath)) {
      return QueuePath;
    }
  }
  return resolveSampleArtifactPath(SampleDir);
}

int deriveSemanticFrontierPriorityTier(const std::string &AnalysisState,
                                       const std::string &SemanticOutcome,
                                       bool OracleAuditCandidate,
                                       bool NeedsManualReview) {
  if (AnalysisState == "included" && isTier3SemanticOutcome(SemanticOutcome)) {
    return 3;
  }
  if (OracleAuditCandidate) {
    return 2;
  }
  if (NeedsManualReview) {
    return 1;
  }
  return 0;
}

bool semanticFrontierEntryLess(const SemanticFrontierEntry &Left,
                               const SemanticFrontierEntry &Right) {
  if (Left.PriorityTier != Right.PriorityTier) {
    return Left.PriorityTier > Right.PriorityTier;
  }
  const auto LeftRank = semanticOutcomeRank(Left.SemanticOutcome);
  const auto RightRank = semanticOutcomeRank(Right.SemanticOutcome);
  if (LeftRank != RightRank) {
    return LeftRank < RightRank;
  }
  if (Left.SampleId != Right.SampleId) {
    return Left.SampleId < Right.SampleId;
  }
  return Left.SamplePath < Right.SamplePath;
}

struct TriageReportSnapshot {
  std::filesystem::path Root;
  std::map<std::string, size_t> StatusCounter;
  std::map<std::string, size_t> ClusterCounter;
  std::map<std::string, std::vector<std::string>> ClusterSamples;
  std::vector<SemanticFrontierEntry> SemanticFrontierEntries;
  size_t TotalSamples = 0;
};

struct ResolverEvidenceContext {
  std::string Primary = "bind9";
  std::string Secondary = "unbound";
  std::string PrimaryStderrName = "bind9.stderr";
  std::string SecondaryStderrName = "unbound.stderr";
};

struct CaseStudyCandidateRecord {
  std::string SampleId;
  std::filesystem::path SampleDir;
  std::string SemanticOutcome;
  std::string SelectionReason;
  json::Value::Object TriagePayload;
};

std::vector<std::string> coerceStringList(const json::Value *Value);
json::Value::Object coerceObjectOrEmpty(const json::Value *Value);

TriageReportSnapshot
collectTriageReportSnapshot(const std::filesystem::path &Root) {
  if (!std::filesystem::exists(Root) || !std::filesystem::is_directory(Root)) {
    throw std::runtime_error("follow_diff 根目录不存在或不是目录: " +
                             normalizePath(Root).string());
  }

  TriageReportSnapshot Snapshot;
  Snapshot.Root = normalizePath(Root);
  std::vector<SemanticFrontierEntry> PreparedEntries;
  for (const auto &SampleDir : collectSampleDirs(Snapshot.Root)) {
    const auto SampleMetaPayload = loadSampleMetaPayload(SampleDir);
    const auto TriagePath = SampleDir / "triage.json";
    const auto TriagePayload =
        std::filesystem::is_regular_file(TriagePath)
            ? loadTriagePayload(SampleDir)
            : buildTriageFallbackPayload(SampleDir, SampleMetaPayload);

    const auto SampleId =
        coerceText(findObjectValue(TriagePayload, "sample_id"),
                   SampleDir.filename().string());
    auto ClusterKey =
        coerceText(findObjectValue(TriagePayload, "cluster_key"), "_");
    const auto Labels = coerceLabels(findObjectValue(TriagePayload, "filter_labels"));
    if (ClusterKey == "_" && !Labels.empty()) {
      ClusterKey = joinCsv(Labels);
    }

    const auto Status =
        coerceText(findObjectValue(TriagePayload, "status"), "unknown");
    const auto AnalysisState =
        coerceAnalysisState(findObjectValue(TriagePayload, "analysis_state"));
    const auto SemanticOutcome =
        coerceText(findObjectValue(TriagePayload, "semantic_outcome"),
                   "unknown");
    const bool OracleAuditCandidate =
        coerceBool(findObjectValue(TriagePayload, "oracle_audit_candidate"));
    const bool NeedsManualReview =
        coerceBool(findObjectValue(TriagePayload, "needs_manual_review"));

    ++Snapshot.TotalSamples;
    ++Snapshot.StatusCounter[Status];
    ++Snapshot.ClusterCounter[ClusterKey];
    Snapshot.ClusterSamples[ClusterKey].push_back(SampleId);

    const auto SamplePath =
        resolveSemanticFrontierSamplePath(SampleDir, SampleMetaPayload);
    if (!SamplePath.has_value()) {
      continue;
    }

    SemanticFrontierEntry Entry;
    Entry.SamplePath = normalizePath(*SamplePath).string();
    Entry.SampleId = SampleId;
    Entry.AnalysisState = AnalysisState;
    Entry.SemanticOutcome = SemanticOutcome;
    Entry.OracleAuditCandidate = OracleAuditCandidate;
    Entry.NeedsManualReview = NeedsManualReview;
    Entry.PriorityTier = deriveSemanticFrontierPriorityTier(
        AnalysisState, SemanticOutcome, OracleAuditCandidate, NeedsManualReview);
    if (std::filesystem::is_regular_file(Entry.SamplePath)) {
      PreparedEntries.push_back(std::move(Entry));
    }
  }

  std::sort(PreparedEntries.begin(), PreparedEntries.end(),
            semanticFrontierEntryLess);
  std::set<std::string> SeenPaths;
  for (const auto &Entry : PreparedEntries) {
    if (!SeenPaths.insert(Entry.SamplePath).second) {
      continue;
    }
    Snapshot.SemanticFrontierEntries.push_back(Entry);
  }
  return Snapshot;
}

std::string buildClusterSummaryContent(const TriageReportSnapshot &Snapshot) {
  std::vector<std::string> Lines = {"cluster_key\tcount\tsample_ids"};
  for (const auto &[ClusterKey, Count] : Snapshot.ClusterCounter) {
    auto SampleIds = Snapshot.ClusterSamples.at(ClusterKey);
    std::sort(SampleIds.begin(), SampleIds.end());
    Lines.push_back(ClusterKey + "\t" + std::to_string(Count) + "\t" +
                    (SampleIds.empty() ? "-" : joinCsv(SampleIds)));
  }
  Lines.push_back("__total__\t" + std::to_string(Snapshot.TotalSamples) + "\t-");
  std::ostringstream Stream;
  for (const auto &Line : Lines) {
    Stream << Line << '\n';
  }
  return Stream.str();
}

std::string buildStatusSummaryContent(const TriageReportSnapshot &Snapshot) {
  std::ostringstream Stream;
  Stream << "status\tcount\n";
  for (const auto &[Status, Count] : Snapshot.StatusCounter) {
    Stream << Status << '\t' << Count << '\n';
  }
  Stream << "__total__\t" << Snapshot.TotalSamples << '\n';
  return Stream.str();
}

std::string buildHighValueManifestContent(
    const std::vector<SemanticFrontierEntry> &Entries) {
  std::ostringstream Stream;
  for (const auto &Entry : Entries) {
    if (Entry.PriorityTier > 0) {
      Stream << Entry.SamplePath << '\n';
    }
  }
  return Stream.str();
}

json::Value buildSemanticFrontierManifest(
    const std::filesystem::path &Root,
    const std::vector<SemanticFrontierEntry> &Entries) {
  json::Value::Object Output;
  Output["contract_name"] = kSemanticFrontierManifestContractName;
  Output["contract_version"] = kContractVersion;
  Output["generated_at"] = utcTimestampNow();
  Output["root"] = normalizePath(Root).string();
  json::Value::Array Items;
  for (const auto &Entry : Entries) {
    Items.emplace_back(toJson(Entry));
  }
  Output["entries"] = Items;
  return Output;
}

std::string buildTriageReportMarkdown(const TriageReportSnapshot &Snapshot) {
  std::ostringstream Stream;
  Stream << "# DNS Diff Triage Report\n\n";
  Stream << "- root: `" << normalizePath(Snapshot.Root).string() << "`\n";
  Stream << "- total_samples: " << Snapshot.TotalSamples << "\n";
  Stream << "- status_bucket_count: " << Snapshot.StatusCounter.size() << "\n";
  Stream << "- cluster_bucket_count: " << Snapshot.ClusterCounter.size()
         << "\n\n";
  Stream << "## Status Summary\n\n";
  Stream << "| status | count |\n";
  Stream << "|---|---:|\n";
  if (Snapshot.StatusCounter.empty()) {
    Stream << "| (none) | 0 |\n";
  } else {
    for (const auto &[Status, Count] : Snapshot.StatusCounter) {
      Stream << "| " << Status << " | " << Count << " |\n";
    }
  }
  Stream << "\n## Cluster Summary\n\n";
  Stream << "| cluster_key | count |\n";
  Stream << "|---|---:|\n";
  if (Snapshot.ClusterCounter.empty()) {
    Stream << "| (none) | 0 |\n";
  } else {
    for (const auto &[ClusterKey, Count] : Snapshot.ClusterCounter) {
      Stream << "| " << ClusterKey << " | " << Count << " |\n";
    }
  }
  return Stream.str() + '\n';
}

std::string buildCaseStudySelectionReason(const std::string &SemanticOutcome) {
  if (SemanticOutcome == "oracle_and_cache_diff" ||
      SemanticOutcome == "oracle_diff") {
    return "analysis_state=included 且 semantic_outcome=" + SemanticOutcome +
           "，属于高优先级 oracle 语义差异 case study 候选";
  }
  return "analysis_state=included 且 semantic_outcome=cache_diff_interesting，"
         "属于次优先级 cache 差异兴趣样本候选";
}

int caseStudyPriority(const std::string &SemanticOutcome) {
  if (SemanticOutcome == "oracle_and_cache_diff" ||
      SemanticOutcome == "oracle_diff") {
    return 0;
  }
  if (SemanticOutcome == "cache_diff_interesting") {
    return 1;
  }
  return 2;
}

bool caseStudyCandidateLess(const CaseStudyCandidateRecord &Left,
                            const CaseStudyCandidateRecord &Right) {
  const int LeftPriority = caseStudyPriority(Left.SemanticOutcome);
  const int RightPriority = caseStudyPriority(Right.SemanticOutcome);
  if (LeftPriority != RightPriority) {
    return LeftPriority < RightPriority;
  }
  if (Left.SampleId != Right.SampleId) {
    return Left.SampleId < Right.SampleId;
  }
  return Left.SampleDir < Right.SampleDir;
}

bool hasSuffix(const std::string &Value, const std::string &Suffix) {
  return Value.size() >= Suffix.size() &&
         Value.compare(Value.size() - Suffix.size(), Suffix.size(), Suffix) == 0;
}

std::string inferSecondaryResolverName(
    const json::Value::Object *SampleMetaPayload,
    const json::Value::Object &OraclePayload) {
  if (SampleMetaPayload != nullptr) {
    const auto *ArtifactsValue = findObjectValue(*SampleMetaPayload, "artifacts");
    const auto *ArtifactsObject =
        ArtifactsValue
            ? std::get_if<json::Value::Object>(&ArtifactsValue->storage())
            : nullptr;
    if (ArtifactsObject != nullptr) {
      for (const auto &[Key, Value] : *ArtifactsObject) {
        (void)Value;
        if (hasSuffix(Key, "_stderr") && Key != "bind9_stderr") {
          return Key.substr(0, Key.size() - std::string("_stderr").size());
        }
      }
    }
  }

  for (const auto &[Key, Value] : OraclePayload) {
    (void)Value;
    const auto Separator = Key.find('.');
    if (Separator == std::string::npos) {
      continue;
    }
    const auto Prefix = Key.substr(0, Separator);
    if (Prefix != "bind9") {
      return Prefix;
    }
  }
  return "unbound";
}

ResolverEvidenceContext buildResolverEvidenceContext(
    const json::Value::Object *SampleMetaPayload,
    const json::Value::Object &OraclePayload) {
  ResolverEvidenceContext Output;
  Output.Secondary = inferSecondaryResolverName(SampleMetaPayload, OraclePayload);
  Output.SecondaryStderrName = Output.Secondary + ".stderr";
  return Output;
}

json::Value::Array buildStringArray(const std::vector<std::string> &Items) {
  json::Value::Array Output;
  for (const auto &Item : Items) {
    Output.emplace_back(Item);
  }
  return Output;
}

std::string valueOrNullText(const json::Value *Value) {
  return Value == nullptr ? "null" : stableJsonText(*Value);
}

std::vector<std::string>
buildOracleDiffFields(const json::Value::Object &OraclePayload,
                      const std::string &SecondaryResolver) {
  std::vector<std::string> Output;
  for (const auto &Field : kOracleFields) {
    const auto Left = valueOrNullText(
        findObjectValue(OraclePayload, "bind9." + Field));
    const auto Right = valueOrNullText(
        findObjectValue(OraclePayload, SecondaryResolver + "." + Field));
    if (Left != Right) {
      Output.push_back(Field);
    }
  }
  return Output;
}

bool caseStudyResolverBool(const json::Value::Object &CacheDiffPayload,
                           const std::string &Resolver,
                           const std::string &Key) {
  const auto *ResolverValue = findObjectValue(CacheDiffPayload, Resolver);
  const auto ResolverObject = coerceObjectOrEmpty(ResolverValue);
  return coerceBool(findObjectValue(ResolverObject, Key));
}

std::int64_t caseStudyResolverInt(const json::Value::Object &CacheDiffPayload,
                                  const std::string &Resolver,
                                  const std::string &Key) {
  const auto *ResolverValue = findObjectValue(CacheDiffPayload, Resolver);
  const auto ResolverObject = coerceObjectOrEmpty(ResolverValue);
  return coerceInt64(findObjectValue(ResolverObject, Key), 0);
}

json::Value::Object buildStderrPreview(const std::filesystem::path &Path,
                                       size_t MaxLines = 20) {
  json::Value::Object Output;
  Output["path"] = normalizePath(Path).string();
  if (!std::filesystem::is_regular_file(Path)) {
    Output["exists"] = false;
    Output["tail_preview"] = json::Value::Array{};
    return Output;
  }

  Output["exists"] = true;
  std::istringstream Stream(readTextFile(Path));
  std::vector<std::string> Lines;
  std::string Line;
  while (std::getline(Stream, Line)) {
    Lines.push_back(Line);
  }
  const size_t Start =
      Lines.size() > MaxLines ? Lines.size() - MaxLines : 0U;
  json::Value::Array Preview;
  for (size_t Index = Start; Index < Lines.size(); ++Index) {
    Preview.emplace_back(Lines[Index]);
  }
  Output["tail_preview"] = Preview;
  return Output;
}

json::Value::Object buildSampleBinEvidence(const std::filesystem::path &Path) {
  json::Value::Object Output;
  Output["path"] = normalizePath(Path).string();
  if (!std::filesystem::is_regular_file(Path)) {
    Output["exists"] = false;
    Output["size"] = static_cast<std::int64_t>(0);
    return Output;
  }
  Output["exists"] = true;
  Output["size"] = static_cast<std::int64_t>(std::filesystem::file_size(Path));
  return Output;
}

std::vector<CaseStudyCandidateRecord>
collectCaseStudyCandidates(const std::filesystem::path &Root) {
  std::vector<CaseStudyCandidateRecord> Output;
  for (const auto &SampleDir : collectSampleDirs(Root)) {
    const auto TriagePayload = loadTriagePayload(SampleDir);
    const auto AnalysisState =
        coerceAnalysisState(findObjectValue(TriagePayload, "analysis_state"));
    const auto SemanticOutcome =
        coerceText(findObjectValue(TriagePayload, "semantic_outcome"),
                   "unknown");
    if (AnalysisState != "included") {
      continue;
    }
    if (SemanticOutcome != "oracle_diff" &&
        SemanticOutcome != "oracle_and_cache_diff" &&
        SemanticOutcome != "cache_diff_interesting") {
      continue;
    }

    CaseStudyCandidateRecord Candidate;
    Candidate.SampleId =
        coerceText(findObjectValue(TriagePayload, "sample_id"),
                   SampleDir.filename().string());
    Candidate.SampleDir = normalizePath(SampleDir);
    Candidate.SemanticOutcome = SemanticOutcome;
    Candidate.SelectionReason = buildCaseStudySelectionReason(SemanticOutcome);
    Candidate.TriagePayload = TriagePayload;
    Output.push_back(std::move(Candidate));
  }

  std::sort(Output.begin(), Output.end(), caseStudyCandidateLess);
  return Output;
}

json::Value::Object
buildCaseStudyAutomatedSummary(const std::string &SemanticOutcome,
                               const ResolverEvidenceContext &ResolverContext,
                               const json::Value::Object &TriagePayload,
                               const json::Value::Object &OraclePayload,
                               const json::Value::Object &CacheDiffPayload) {
  const auto OracleDiffFields =
      buildOracleDiffFields(OraclePayload, ResolverContext.Secondary);
  const auto TriageStatus =
      coerceText(findObjectValue(TriagePayload, "status"), "unknown");
  const auto InterestingDeltaCount =
      coerceInt64(findObjectValue(TriagePayload, "interesting_delta_count"), 0);
  const bool NeedsManualReview =
      coerceBool(findObjectValue(TriagePayload, "needs_manual_review"));
  std::string SummaryText;
  if (SemanticOutcome == "oracle_and_cache_diff") {
    SummaryText =
        "oracle 与 cache_diff 同时命中结构化差异，按固定规则属于最高优先级 case study。";
  } else if (SemanticOutcome == "oracle_diff") {
    SummaryText =
        "oracle 存在 resolver 间字段差异，按固定规则属于最高优先级 case study。";
  } else {
    SummaryText =
        "oracle 未命中优先差异，但 cache_diff 达到 interesting 阈值，按固定规则作为次优先级 case study。";
  }

  json::Value::Object Output;
  Output["triage_status"] = TriageStatus;
  Output["semantic_outcome"] = SemanticOutcome;
  Output["oracle_diff_fields"] = buildStringArray(OracleDiffFields);
  Output["cache_delta_triggered"] =
      coerceBool(findObjectValue(CacheDiffPayload, "cache_delta_triggered"));
  Output["interesting_delta_count"] = InterestingDeltaCount;
  Output["needs_manual_review"] = NeedsManualReview;
  Output["filter_labels"] =
      buildStringArray(coerceStringList(findObjectValue(TriagePayload,
                                                       "filter_labels")));
  Output["notes"] =
      buildStringArray(coerceStringList(findObjectValue(TriagePayload, "notes")));
  Output["bind9_has_cache_diff"] =
      caseStudyResolverBool(CacheDiffPayload, "bind9", "has_cache_diff");
  Output[ResolverContext.Secondary + "_has_cache_diff"] =
      caseStudyResolverBool(CacheDiffPayload, ResolverContext.Secondary,
                            "has_cache_diff");
  Output["bind9_interesting_delta_count"] =
      caseStudyResolverInt(CacheDiffPayload, "bind9",
                           "interesting_delta_count");
  Output[ResolverContext.Secondary + "_interesting_delta_count"] =
      caseStudyResolverInt(CacheDiffPayload, ResolverContext.Secondary,
                           "interesting_delta_count");
  Output["secondary_resolver"] = ResolverContext.Secondary;
  Output["summary_text"] = SummaryText;
  return Output;
}

json::Value::Object buildCaseStudyPayload(
    const CaseStudyCandidateRecord &Candidate) {
  const auto SampleDir = Candidate.SampleDir;
  const auto SampleMetaPath = normalizePath(SampleDir / "sample.meta.json");
  const auto OraclePath = normalizePath(SampleDir / "oracle.json");
  const auto CacheDiffPath = normalizePath(SampleDir / "cache_diff.json");
  const auto TriagePath = normalizePath(SampleDir / "triage.json");
  const auto SampleBinPath = normalizePath(SampleDir / "sample.bin");
  const auto SampleMetaPayload = loadSampleMetaPayload(SampleDir);
  const auto OraclePayload =
      loadRequiredObject(SampleDir, "oracle.json", "oracle.json");
  const auto CacheDiffPayload =
      loadRequiredObject(SampleDir, "cache_diff.json", "cache_diff.json");
  const auto ResolverContext =
      buildResolverEvidenceContext(&SampleMetaPayload, OraclePayload);
  const auto Bind9StderrPath =
      normalizePath(SampleDir / ResolverContext.PrimaryStderrName);
  const auto SecondaryStderrPath =
      normalizePath(SampleDir / ResolverContext.SecondaryStderrName);

  json::Value::Object Paths;
  Paths["sample_meta_path"] = SampleMetaPath.string();
  Paths["oracle_path"] = OraclePath.string();
  Paths["cache_diff_path"] = CacheDiffPath.string();
  Paths["triage_path"] = TriagePath.string();
  Paths["sample_bin_path"] = SampleBinPath.string();
  Paths["bind9_stderr_path"] = Bind9StderrPath.string();
  Paths[ResolverContext.Secondary + "_stderr_path"] =
      SecondaryStderrPath.string();

  json::Value::Object ResolverContextValue;
  ResolverContextValue["primary"] = ResolverContext.Primary;
  ResolverContextValue["secondary"] = ResolverContext.Secondary;

  json::Value::Object RawEvidence;
  RawEvidence["resolver_context"] = ResolverContextValue;
  RawEvidence["paths"] = Paths;
  RawEvidence["sample_meta"] = SampleMetaPayload;
  RawEvidence["oracle"] = OraclePayload;
  RawEvidence["cache_diff"] = CacheDiffPayload;
  RawEvidence["triage"] = Candidate.TriagePayload;
  RawEvidence["sample_bin"] = buildSampleBinEvidence(SampleBinPath);
  json::Value::Object Stderr;
  Stderr["bind9"] = buildStderrPreview(Bind9StderrPath);
  Stderr[ResolverContext.Secondary] = buildStderrPreview(SecondaryStderrPath);
  RawEvidence["stderr"] = Stderr;

  json::Value::Object ManualTruth;
  ManualTruth["status"] = "not_started";
  ManualTruth["reviewer_primary"] = "";
  ManualTruth["reviewer_secondary"] = "";
  ManualTruth["adjudicator"] = "";
  ManualTruth["judgment"] = "";
  ManualTruth["notes"] = "";
  ManualTruth["decided_at"] = "";

  json::Value::Array ClaimScope;
  ClaimScope.emplace_back(
      "选样仅消费 triage.json 中已冻结的 analysis_state 与 semantic_outcome，不重算 publication 语义。");
  ClaimScope.emplace_back(
      "原始证据路径严格限定在当前 sample_dir 的 sample.meta.json、oracle.json、cache_diff.json、triage.json、sample.bin、bind9.stderr、" +
      ResolverContext.Secondary + ".stderr。");

  json::Value::Array Limitations;
  Limitations.emplace_back(
      "manual_truth 仅为 not_started scaffold，当前尚无人工双评或 adjudication 结论。");
  Limitations.emplace_back(
      "stderr 仅收录尾部预览；如需完整上下文，必须回看 raw_evidence.paths 指向的原始文件。");
  Limitations.emplace_back(
      "automated_summary 仅基于现有 triage/oracle/cache_diff 工件自动整理，不能替代人工判断。");

  json::Value::Object Output;
  Output["sample_id"] = Candidate.SampleId;
  Output["selection_reason"] = Candidate.SelectionReason;
  Output["raw_evidence"] = RawEvidence;
  Output["automated_summary"] = buildCaseStudyAutomatedSummary(
      Candidate.SemanticOutcome, ResolverContext, Candidate.TriagePayload,
      OraclePayload, CacheDiffPayload);
  Output["manual_truth"] = ManualTruth;
  Output["claim_scope"] = ClaimScope;
  Output["limitations"] = Limitations;
  return Output;
}

std::string buildCaseStudyIndexContent(
    const std::filesystem::path &OutputDir,
    const std::vector<CaseStudyCandidateRecord> &Candidates) {
  std::ostringstream Stream;
  Stream << "sample_id\tsemantic_outcome\tselection_reason\tcase_study_path\n";
  for (const auto &Candidate : Candidates) {
    Stream << Candidate.SampleId << '\t' << Candidate.SemanticOutcome << '\t'
           << Candidate.SelectionReason << '\t'
           << normalizePath(OutputDir / (Candidate.SampleId + ".json")).string()
           << '\n';
  }
  return Stream.str();
}

std::optional<std::filesystem::path>
resolveAssociatedWorkDir(const std::filesystem::path &Root,
                        const std::optional<std::filesystem::path> &Hint) {
  if (Hint.has_value()) {
    return normalizePath(*Hint);
  }
  const auto Candidate = normalizePath(Root).parent_path();
  if (std::filesystem::is_regular_file(Candidate / "follow_diff.state.json") ||
      std::filesystem::is_regular_file(Candidate /
                                       "follow_diff.window.summary.json")) {
    return Candidate;
  }
  return std::nullopt;
}

std::string coerceFailureBucketPrimary(const json::Value *Value) {
  const auto Text = coerceText(Value, "missing_failure_bucket_primary");
  if (std::find(kFailureBucketPrimaryOrder.begin(),
                kFailureBucketPrimaryOrder.end(),
                Text) != kFailureBucketPrimaryOrder.end()) {
    return Text;
  }
  return "missing_failure_bucket_primary";
}

std::string coerceFailureBucketDetail(const json::Value *Value) {
  const auto Text = coerceText(Value, "missing_failure_bucket_detail");
  static const std::vector<std::string> KnownDetails = {
      "oracle_diff",
      "oracle_and_cache_diff",
      "cache_diff_interesting",
      "cache_diff_benign",
      "no_diff",
      "oracle_parse_incomplete",
      "replay_missing_artifact",
      "replay_missing_executable",
      "replay_subprocess_launch_error",
      "replay_timeout",
      "replay_subprocess_failed",
  };
  if (std::find(KnownDetails.begin(), KnownDetails.end(), Text) !=
      KnownDetails.end()) {
    return Text;
  }
  return "missing_failure_bucket_detail";
}

std::optional<json::Value::Object>
loadAuxiliaryObject(const std::filesystem::path &Path) {
  return loadOptionalObject(Path, Path.parent_path(), Path.filename().string());
}

ContractKeyExtraction
extractContractKeyPayload(const json::Value::Object &Record,
                         const std::string &KeyName,
                         const std::vector<std::string> &Fields) {
  const auto *KeyValue = findObjectValue(Record, KeyName);
  const auto *KeyObject =
      KeyValue ? std::get_if<json::Value::Object>(&KeyValue->storage()) : nullptr;
  if (KeyObject == nullptr) {
    return {std::nullopt, Fields};
  }

  json::Value::Object Normalized;
  std::vector<std::string> MissingFields;
  for (const auto &Field : Fields) {
    const auto *Value = findObjectValue(*KeyObject, Field);
    if (isMissingContractValue(Value)) {
      MissingFields.push_back(Field);
      continue;
    }
    Normalized[Field] = *Value;
  }
  if (!MissingFields.empty()) {
    return {std::nullopt, MissingFields};
  }
  return {Normalized, {}};
}

std::vector<std::string>
conflictingContractFields(const json::Value::Object &Reference,
                          const json::Value::Object &Candidate,
                          const std::vector<std::string> &Fields) {
  std::vector<std::string> Output;
  for (const auto &Field : Fields) {
    const auto *ReferenceValue = findObjectValue(Reference, Field);
    const auto *CandidateValue = findObjectValue(Candidate, Field);
    if (ReferenceValue == nullptr || CandidateValue == nullptr) {
      continue;
    }
    if (stableJsonText(*ReferenceValue) != stableJsonText(*CandidateValue)) {
      Output.push_back(Field);
    }
  }
  return Output;
}

json::Value::Object
buildComparabilityPayload(const std::vector<json::Value::Object> &Records) {
  std::optional<json::Value::Object> ReferenceAggregationKey;
  std::optional<json::Value::Object> ReferenceBaselineCompareKey;
  std::set<std::string> NonComparableSampleIds;
  std::vector<json::Value> Issues;
  std::set<std::string> AggregationKeyConflictFields;
  std::set<std::string> BaselineCompareKeyConflictFields;
  size_t FullKeySampleCount = 0;

  for (size_t Index = 0; Index < Records.size(); ++Index) {
    const auto &Record = Records[Index];
    const auto SampleId =
        coerceText(findObjectValue(Record, "sample_id"),
                   "sample-" + std::to_string(Index + 1));
    const auto AggregationKey =
        extractContractKeyPayload(Record, "aggregation_key", kAggregationKeyFields);
    const auto BaselineCompareKey = extractContractKeyPayload(
        Record, "baseline_compare_key", kBaselineCompareKeyFields);

    if (!AggregationKey.MissingFields.empty() ||
        !BaselineCompareKey.MissingFields.empty()) {
      NonComparableSampleIds.insert(SampleId);
      json::Value::Object Issue;
      Issue["sample_id"] = SampleId;
      Issue["reason"] = "missing_comparability_fields";
      json::Value::Array MissingAggregation;
      for (const auto &Field : AggregationKey.MissingFields) {
        MissingAggregation.emplace_back(Field);
      }
      json::Value::Array MissingBaseline;
      for (const auto &Field : BaselineCompareKey.MissingFields) {
        MissingBaseline.emplace_back(Field);
      }
      if (!AggregationKey.MissingFields.empty()) {
        Issue["missing_aggregation_key_fields"] = MissingAggregation;
      }
      if (!BaselineCompareKey.MissingFields.empty()) {
        Issue["missing_baseline_compare_key_fields"] = MissingBaseline;
      }
      Issues.emplace_back(Issue);
      continue;
    }

    if (!AggregationKey.Value.has_value() ||
        !BaselineCompareKey.Value.has_value()) {
      continue;
    }

    ++FullKeySampleCount;
    json::Value::Object Issue;
    Issue["sample_id"] = SampleId;

    if (!ReferenceAggregationKey.has_value()) {
      ReferenceAggregationKey = *AggregationKey.Value;
    } else {
      const auto Conflicts = conflictingContractFields(
          *ReferenceAggregationKey, *AggregationKey.Value, kAggregationKeyFields);
      if (!Conflicts.empty()) {
        NonComparableSampleIds.insert(SampleId);
        for (const auto &Field : Conflicts) {
          AggregationKeyConflictFields.insert(Field);
        }
        json::Value::Array ConflictArray;
        for (const auto &Field : Conflicts) {
          ConflictArray.emplace_back(Field);
        }
        Issue["reason"] = "aggregation_key_conflict";
        Issue["aggregation_key_conflict_fields"] = ConflictArray;
      }
    }

    if (!ReferenceBaselineCompareKey.has_value()) {
      ReferenceBaselineCompareKey = *BaselineCompareKey.Value;
    } else {
      const auto Conflicts = conflictingContractFields(
          *ReferenceBaselineCompareKey, *BaselineCompareKey.Value,
          kBaselineCompareKeyFields);
      if (!Conflicts.empty()) {
        NonComparableSampleIds.insert(SampleId);
        for (const auto &Field : Conflicts) {
          BaselineCompareKeyConflictFields.insert(Field);
        }
        json::Value::Array ConflictArray;
        for (const auto &Field : Conflicts) {
          ConflictArray.emplace_back(Field);
        }
        if (!findObjectValue(Issue, "reason")) {
          Issue["reason"] = "baseline_compare_key_conflict";
        } else if (coerceText(findObjectValue(Issue, "reason"), "") !=
                   "baseline_compare_key_conflict") {
          Issue["reason"] = "multiple_key_conflicts";
        }
        Issue["baseline_compare_key_conflict_fields"] = ConflictArray;
      }
    }

    if (Issue.size() > 1U) {
      Issues.emplace_back(Issue);
    }
  }

  const bool AggregationComparable =
      !Records.empty() && FullKeySampleCount == Records.size() &&
      AggregationKeyConflictFields.empty();
  const bool BaselineComparable =
      !Records.empty() && FullKeySampleCount == Records.size() &&
      BaselineCompareKeyConflictFields.empty();
  const bool Comparable = AggregationComparable && BaselineComparable;
  const size_t ComparableSampleCount = Comparable ? Records.size() : 0U;

  std::string Reason = "ok";
  if (Records.empty()) {
    Reason = "no_samples";
  } else {
    for (const auto &IssueValue : Issues) {
      const auto *IssueObject =
          std::get_if<json::Value::Object>(&IssueValue.storage());
      if (!IssueObject) {
        continue;
      }
      if (coerceText(findObjectValue(*IssueObject, "reason"), "") ==
          "missing_comparability_fields") {
        Reason = "missing_comparability_fields";
        break;
      }
    }
    if (Reason == "ok" && !AggregationKeyConflictFields.empty()) {
      Reason = "aggregation_key_conflict";
    } else if (Reason == "ok" && !BaselineCompareKeyConflictFields.empty()) {
      Reason = "baseline_compare_key_conflict";
    }
  }

  json::Value::Object Output;
  Output["status"] = Comparable ? "comparable" : "non_comparable";
  Output["comparable"] = Comparable;
  Output["aggregation_comparable"] = AggregationComparable;
  Output["baseline_comparable"] = BaselineComparable;
  Output["reason"] = Reason;
  Output["sample_count"] = static_cast<std::int64_t>(Records.size());
  Output["full_key_sample_count"] =
      static_cast<std::int64_t>(FullKeySampleCount);
  Output["comparable_sample_count"] =
      static_cast<std::int64_t>(ComparableSampleCount);
  Output["non_comparable_sample_count"] =
      static_cast<std::int64_t>(Records.size() - ComparableSampleCount);

  json::Value::Array SampleIds;
  for (const auto &SampleId : NonComparableSampleIds) {
    SampleIds.emplace_back(SampleId);
  }
  Output["non_comparable_sample_ids"] = SampleIds;

  json::Value::Array AggregationConflicts;
  for (const auto &Field : AggregationKeyConflictFields) {
    AggregationConflicts.emplace_back(Field);
  }
  Output["aggregation_key_conflict_fields"] = AggregationConflicts;

  json::Value::Array BaselineConflicts;
  for (const auto &Field : BaselineCompareKeyConflictFields) {
    BaselineConflicts.emplace_back(Field);
  }
  Output["baseline_compare_key_conflict_fields"] = BaselineConflicts;

  if (AggregationComparable && ReferenceAggregationKey.has_value()) {
    Output["aggregation_key"] = *ReferenceAggregationKey;
  } else {
    Output["aggregation_key"] = json::Value();
  }
  if (BaselineComparable && ReferenceBaselineCompareKey.has_value()) {
    Output["baseline_compare_key"] = *ReferenceBaselineCompareKey;
  } else {
    Output["baseline_compare_key"] = json::Value();
  }
  Output["issues"] = Issues;
  return Output;
}

std::optional<json::Value>
deriveSeedProvenance(const std::vector<json::Value::Object> &SampleMetaPayloads,
                    const std::optional<json::Value::Object> &WindowSummaryPayload) {
  if (WindowSummaryPayload.has_value()) {
    const auto *WindowValue =
        findObjectValue(*WindowSummaryPayload, "seed_provenance");
    if (WindowValue &&
        std::holds_alternative<json::Value::Object>(WindowValue->storage())) {
      return *WindowValue;
    }
  }

  std::map<std::string, json::Value> Unique;
  for (const auto &Payload : SampleMetaPayloads) {
    const auto *SeedProvenance = findObjectValue(Payload, "seed_provenance");
    if (SeedProvenance == nullptr ||
        !std::holds_alternative<json::Value::Object>(SeedProvenance->storage())) {
      continue;
    }
    Unique.emplace(stableJsonText(*SeedProvenance), *SeedProvenance);
  }
  if (Unique.size() == 1U) {
    return Unique.begin()->second;
  }
  return std::nullopt;
}

std::vector<std::string>
collectClaimReviewArtifacts(const std::vector<json::Value::Object> &SampleMetaPayloads) {
  std::vector<std::string> Ordered = {
      "sample.meta.json", "oracle.json", "cache_diff.json", "triage.json",
      "sample.bin"};
  std::set<std::string> Seen(Ordered.begin(), Ordered.end());
  for (const auto &Payload : SampleMetaPayloads) {
    const auto *Artifacts = findObjectValue(Payload, "artifacts");
    const auto *ArtifactsObject =
        Artifacts ? std::get_if<json::Value::Object>(&Artifacts->storage()) : nullptr;
    if (ArtifactsObject == nullptr) {
      continue;
    }
    for (const auto &[Key, Value] : *ArtifactsObject) {
      (void)Key;
      const auto *Text = std::get_if<std::string>(&Value.storage());
      if (Text == nullptr || Text->empty()) {
        continue;
      }
      if (!Seen.insert(*Text).second) {
        continue;
      }
      Ordered.push_back(*Text);
    }
  }
  return Ordered;
}

std::vector<std::string> coerceStringList(const json::Value *Value) {
  std::vector<std::string> Output;
  const auto *Array =
      Value ? std::get_if<json::Value::Array>(&Value->storage()) : nullptr;
  if (Array == nullptr) {
    return Output;
  }
  for (const auto &Item : *Array) {
    if (const auto *Text = std::get_if<std::string>(&Item.storage())) {
      if (!Text->empty()) {
        Output.push_back(*Text);
      }
    }
  }
  return Output;
}

json::Value::Object coerceObjectOrEmpty(const json::Value *Value) {
  const auto *Object =
      Value ? std::get_if<json::Value::Object>(&Value->storage()) : nullptr;
  if (Object == nullptr) {
    return {};
  }
  return *Object;
}

json::Value::Array coerceArrayOrEmpty(const json::Value *Value) {
  const auto *Array =
      Value ? std::get_if<json::Value::Array>(&Value->storage()) : nullptr;
  if (Array == nullptr) {
    return {};
  }
  return *Array;
}

bool anyTrueInObject(const json::Value::Object &Object) {
  for (const auto &[Key, Value] : Object) {
    (void)Key;
    if (const auto *BoolValue = std::get_if<bool>(&Value.storage())) {
      if (*BoolValue) {
        return true;
      }
    }
  }
  return false;
}

std::vector<std::string> collectResolverNames(
    const json::Value::Object &SampleMetaPayload,
    const json::Value::Object &OraclePayload) {
  auto Output = coerceStringList(findObjectValue(SampleMetaPayload, "executed_resolvers"));
  if (!Output.empty()) {
    return Output;
  }
  const auto ResolversObject =
      coerceObjectOrEmpty(findObjectValue(OraclePayload, "resolvers"));
  for (const auto &[ResolverName, Payload] : ResolversObject) {
    (void)Payload;
    Output.push_back(ResolverName);
  }
  if (!Output.empty()) {
    return Output;
  }
  std::set<std::string> Unique;
  for (const auto &[Key, Value] : OraclePayload) {
    (void)Value;
    const auto Dot = Key.find('.');
    if (Dot == std::string::npos) {
      continue;
    }
    const auto Prefix = Key.substr(0, Dot);
    if (Prefix == "bind9" || Prefix == "unbound" || Prefix == "dnsmasq" ||
        Prefix == "smartdns" || Prefix == "maradns" ||
        Prefix == "knot-resolver") {
      Unique.insert(Prefix);
    }
  }
  Output.assign(Unique.begin(), Unique.end());
  return Output;
}

json::Value::Object collectOracleSignalMap(
    const json::Value::Object &OraclePayload,
    const std::vector<std::string> &ResolverNames, const std::string &Field) {
  json::Value::Object Output;
  const auto ResolversObject =
      coerceObjectOrEmpty(findObjectValue(OraclePayload, "resolvers"));
  for (const auto &ResolverName : ResolverNames) {
    json::Value::Object ResolverPayload;
    const auto ResolverFound = ResolversObject.find(ResolverName);
    if (ResolverFound != ResolversObject.end()) {
      ResolverPayload = coerceObjectOrEmpty(&ResolverFound->second);
    }
    const auto *Value = findObjectValue(ResolverPayload, ResolverName + "." + Field);
    if (Value != nullptr) {
      Output[ResolverName] = *Value;
      continue;
    }
    const auto *LegacyValue =
        findObjectValue(OraclePayload, ResolverName + "." + Field);
    if (LegacyValue != nullptr) {
      Output[ResolverName] = *LegacyValue;
    } else {
      Output[ResolverName] = json::Value();
    }
  }
  return Output;
}

std::vector<std::string> collectOracleDiffFields(
    const json::Value::Object &TriagePayload,
    const json::Value::Object &OraclePayload,
    const std::vector<std::string> &ResolverNames) {
  std::set<std::string> FieldSet;
  const auto ResolverDiffs =
      coerceArrayOrEmpty(findObjectValue(TriagePayload, "resolver_diffs"));
  for (const auto &Item : ResolverDiffs) {
    const auto DiffObject = coerceObjectOrEmpty(&Item);
    const auto DiffFields =
        coerceStringList(findObjectValue(DiffObject, "oracle_diff_fields"));
    FieldSet.insert(DiffFields.begin(), DiffFields.end());
  }
  if (FieldSet.empty()) {
    for (const auto &Field : kOracleFields) {
      std::set<std::string> Values;
      for (const auto &ResolverName : ResolverNames) {
        const auto *Value =
            findObjectValue(OraclePayload, ResolverName + "." + Field);
        Values.insert(Value ? stableJsonText(*Value) : "null");
      }
      if (Values.size() > 1U) {
        FieldSet.insert(Field);
      }
    }
  }
  std::vector<std::string> Output;
  for (const auto &Field : kOracleFields) {
    if (FieldSet.count(Field)) {
      Output.push_back(Field);
    }
  }
  for (const auto &Field : FieldSet) {
    if (std::find(kOracleFields.begin(), kOracleFields.end(), Field) ==
        kOracleFields.end()) {
      Output.push_back(Field);
    }
  }
  return Output;
}

json::Value::Array collectResolverDiffs(
    const json::Value::Object &TriagePayload,
    const json::Value::Object &OraclePayload,
    const std::vector<std::string> &ResolverNames) {
  auto Output = coerceArrayOrEmpty(findObjectValue(TriagePayload, "resolver_diffs"));
  if (!Output.empty()) {
    return Output;
  }
  for (size_t LeftIndex = 0; LeftIndex < ResolverNames.size(); ++LeftIndex) {
    for (size_t RightIndex = LeftIndex + 1; RightIndex < ResolverNames.size();
         ++RightIndex) {
      std::vector<std::string> Fields;
      for (const auto &Field : kOracleFields) {
        const auto *LeftValue = findObjectValue(
            OraclePayload, ResolverNames[LeftIndex] + "." + Field);
        const auto *RightValue = findObjectValue(
            OraclePayload, ResolverNames[RightIndex] + "." + Field);
        const auto LeftText = LeftValue ? stableJsonText(*LeftValue) : "null";
        const auto RightText = RightValue ? stableJsonText(*RightValue) : "null";
        if (LeftText != RightText) {
          Fields.push_back(Field);
        }
      }
      if (Fields.empty()) {
        continue;
      }
      json::Value::Object Difference;
      Difference["left_resolver"] = ResolverNames[LeftIndex];
      Difference["right_resolver"] = ResolverNames[RightIndex];
      json::Value::Array OracleFields;
      for (const auto &Field : Fields) {
        OracleFields.emplace_back(Field);
      }
      Difference["oracle_diff_fields"] = OracleFields;
      Difference["cache_diff_fields"] = json::Value::Array{};
      Output.emplace_back(Difference);
    }
  }
  return Output;
}

bool cacheDiffAny(const json::Value::Object &CacheDiffPayload) {
  if (coerceBool(findObjectValue(CacheDiffPayload, "diff_detected"))) {
    return true;
  }
  const auto ResolverDiffs =
      coerceArrayOrEmpty(findObjectValue(CacheDiffPayload, "resolver_diffs"));
  if (!ResolverDiffs.empty()) {
    return true;
  }
  for (const auto &[ResolverName, ResolverValue] : CacheDiffPayload) {
    if (ResolverName == "schema_version" || ResolverName == "generated_at" ||
        ResolverName == "sample_id" || ResolverName == "cache_delta_triggered" ||
        ResolverName == "compatibility_secondary_resolver" ||
        ResolverName == "executed_resolvers" || ResolverName == "resolvers") {
      continue;
    }
    const auto ResolverObject = coerceObjectOrEmpty(&ResolverValue);
    if (coerceBool(findObjectValue(ResolverObject, "has_cache_diff"))) {
      return true;
    }
  }
  return false;
}

CampaignAuditRecord buildCampaignAuditRecord(
    const std::filesystem::path &SampleDir,
    const json::Value::Object &SampleMetaPayload,
    const json::Value::Object &TriagePayload) {
  const auto OraclePayload =
      loadOptionalObject(SampleDir / "oracle.json", SampleDir, "oracle.json")
          .value_or(json::Value::Object{});
  const auto CacheDiffPayload =
      loadOptionalObject(SampleDir / "cache_diff.json", SampleDir,
                         "cache_diff.json")
          .value_or(json::Value::Object{});
  const auto ExecutedResolvers =
      collectResolverNames(SampleMetaPayload, OraclePayload);

  CampaignAuditRecord Record;
  Record.SampleId =
      coerceText(findObjectValue(TriagePayload, "sample_id"),
                 SampleDir.filename().string());
  Record.TriageStatus = coerceText(findObjectValue(TriagePayload, "status"),
                                   "unknown");
  Record.AnalysisState =
      coerceAnalysisState(findObjectValue(TriagePayload, "analysis_state"));
  Record.SemanticOutcome =
      coerceText(findObjectValue(TriagePayload, "semantic_outcome"),
                 "unknown");
  Record.OracleAuditCandidate =
      coerceBool(findObjectValue(TriagePayload, "oracle_audit_candidate"));
  Record.ManualTruthStatus =
      coerceText(findObjectValue(TriagePayload, "manual_truth_status"),
                 "not_applicable");
  Record.ExecutedResolvers = ExecutedResolvers;
  Record.SkippedResolvers =
      coerceObjectOrEmpty(findObjectValue(SampleMetaPayload, "skipped_resolvers"));
  Record.DiffDetected = coerceBool(findObjectValue(TriagePayload, "diff_detected"));
  Record.ParseOkByResolver =
      collectOracleSignalMap(OraclePayload, ExecutedResolvers, "parse_ok");
  Record.ResponseAcceptedByResolver = collectOracleSignalMap(
      OraclePayload, ExecutedResolvers, "response_accepted");
  Record.SecondQueryHitByResolver =
      collectOracleSignalMap(OraclePayload, ExecutedResolvers, "second_query_hit");
  Record.CacheEntryCreatedByResolver = collectOracleSignalMap(
      OraclePayload, ExecutedResolvers, "cache_entry_created");
  Record.OracleDiffFields =
      collectOracleDiffFields(TriagePayload, OraclePayload, ExecutedResolvers);
  Record.ResolverDiffs =
      collectResolverDiffs(TriagePayload, OraclePayload, ExecutedResolvers);
  if (!Record.DiffDetected) {
    Record.DiffDetected = !Record.ResolverDiffs.empty();
  }
  Record.SampleMetaPath = normalizePath(SampleDir / "sample.meta.json");
  Record.OraclePath = normalizePath(SampleDir / "oracle.json");
  Record.CacheDiffPath = normalizePath(SampleDir / "cache_diff.json");
  Record.TriagePath = normalizePath(SampleDir / "triage.json");
  Record.SignalResponseAcceptedAny = anyTrueInObject(Record.ResponseAcceptedByResolver);
  Record.SignalSecondQueryHitAny = anyTrueInObject(Record.SecondQueryHitByResolver);
  Record.SignalCacheEntryCreatedAny =
      anyTrueInObject(Record.CacheEntryCreatedByResolver);
  Record.SignalOracleDiffAny = !Record.OracleDiffFields.empty();
  Record.SignalOracleDiffPlusCacheDiff =
      Record.SignalOracleDiffAny && cacheDiffAny(CacheDiffPayload);
  return Record;
}

std::string auditRow(const CampaignAuditRecord &Record) {
  std::ostringstream Stream;
  const std::vector<std::string> Columns = {
      Record.SampleId,
      Record.TriageStatus,
      Record.AnalysisState,
      Record.SemanticOutcome,
      Record.OracleAuditCandidate ? "true" : "false",
      Record.ManualTruthStatus,
      joinCsv(Record.ExecutedResolvers),
      stableJsonText(json::Value(Record.SkippedResolvers)),
      Record.DiffDetected ? "true" : "false",
      Record.OracleDiffFields.empty() ? "-" : joinCsv(Record.OracleDiffFields),
      Record.SignalResponseAcceptedAny ? "true" : "false",
      Record.SignalSecondQueryHitAny ? "true" : "false",
      Record.SignalCacheEntryCreatedAny ? "true" : "false",
      stableJsonText(json::Value(Record.ResolverDiffs)),
      stableJsonText(json::Value(Record.ParseOkByResolver)),
      stableJsonText(json::Value(Record.ResponseAcceptedByResolver)),
      stableJsonText(json::Value(Record.SecondQueryHitByResolver)),
      stableJsonText(json::Value(Record.CacheEntryCreatedByResolver)),
      Record.SampleMetaPath.string(),
      Record.OraclePath.string(),
      Record.CacheDiffPath.string(),
      Record.TriagePath.string(),
  };
  for (size_t Index = 0; Index < Columns.size(); ++Index) {
    if (Index != 0) {
      Stream << '\t';
    }
    Stream << Columns[Index];
  }
  return Stream.str();
}

json::Value buildOracleReliability(
    const std::vector<CampaignAuditRecord> &Records) {
  const auto newBucket = []() {
    json::Value::Object Bucket;
    Bucket["eligible_count"] = static_cast<std::int64_t>(0);
    Bucket["pending_manual_count"] = static_cast<std::int64_t>(0);
    Bucket["judged_count"] = static_cast<std::int64_t>(0);
    Bucket["confirmed_relevant_count"] = static_cast<std::int64_t>(0);
    Bucket["false_positive_count"] = static_cast<std::int64_t>(0);
    Bucket["inconclusive_count"] = static_cast<std::int64_t>(0);
    return Bucket;
  };
  const auto updateBucket = [](json::Value::Object &Bucket,
                               const std::string &ManualTruthStatus) {
    const auto bump = [&](const std::string &Key) {
      Bucket[Key] = coerceInt64(findObjectValue(Bucket, Key), 0) + 1;
    };
    bump("eligible_count");
    if (ManualTruthStatus == "confirmed_relevant") {
      bump("judged_count");
      bump("confirmed_relevant_count");
    } else if (ManualTruthStatus == "false_positive") {
      bump("judged_count");
      bump("false_positive_count");
    } else if (ManualTruthStatus == "inconclusive") {
      bump("judged_count");
      bump("inconclusive_count");
    } else if (ManualTruthStatus == "not_started" ||
               ManualTruthStatus == "pending" ||
               ManualTruthStatus == "in_progress") {
      bump("pending_manual_count");
    }
  };

  json::Value::Object Signals;
  Signals["response_accepted_any"] = newBucket();
  Signals["second_query_hit_any"] = newBucket();
  Signals["cache_entry_created_any"] = newBucket();
  Signals["oracle_diff_any"] = newBucket();
  json::Value::Object SignalCombos;
  SignalCombos["oracle_diff_plus_cache_diff"] = newBucket();

  for (const auto &Record : Records) {
    if (!(Record.AnalysisState == "included" && Record.OracleAuditCandidate)) {
      continue;
    }
    if (Record.SignalResponseAcceptedAny) {
      auto Bucket =
          std::get<json::Value::Object>(Signals["response_accepted_any"].storage());
      updateBucket(Bucket, Record.ManualTruthStatus);
      Signals["response_accepted_any"] = Bucket;
    }
    if (Record.SignalSecondQueryHitAny) {
      auto Bucket =
          std::get<json::Value::Object>(Signals["second_query_hit_any"].storage());
      updateBucket(Bucket, Record.ManualTruthStatus);
      Signals["second_query_hit_any"] = Bucket;
    }
    if (Record.SignalCacheEntryCreatedAny) {
      auto Bucket =
          std::get<json::Value::Object>(Signals["cache_entry_created_any"].storage());
      updateBucket(Bucket, Record.ManualTruthStatus);
      Signals["cache_entry_created_any"] = Bucket;
    }
    if (Record.SignalOracleDiffAny) {
      auto Bucket =
          std::get<json::Value::Object>(Signals["oracle_diff_any"].storage());
      updateBucket(Bucket, Record.ManualTruthStatus);
      Signals["oracle_diff_any"] = Bucket;
    }
    if (Record.SignalOracleDiffPlusCacheDiff) {
      auto Bucket = std::get<json::Value::Object>(
          SignalCombos["oracle_diff_plus_cache_diff"].storage());
      updateBucket(Bucket, Record.ManualTruthStatus);
      SignalCombos["oracle_diff_plus_cache_diff"] = Bucket;
    }
  }

  json::Value::Object Output;
  Output["signals"] = Signals;
  Output["signal_combos"] = SignalCombos;
  return Output;
}

json::Value::Object
buildMetricDenominators(size_t TotalSamples,
                        const std::map<std::string, size_t> &AnalysisStateCounter,
                        const json::Value::Object &Comparability) {
  const auto ComparableSampleCount = static_cast<size_t>(coerceInt64(
      findObjectValue(Comparability, "comparable_sample_count"), 0));
  size_t NonComparableSampleCount = static_cast<size_t>(coerceInt64(
      findObjectValue(Comparability, "non_comparable_sample_count"),
      static_cast<std::int64_t>(TotalSamples - ComparableSampleCount)));

  json::Value::Object AnalysisState;
  AnalysisState["included"] = static_cast<std::int64_t>(
      AnalysisStateCounter.count("included")
          ? AnalysisStateCounter.at("included")
          : 0U);
  AnalysisState["excluded"] = static_cast<std::int64_t>(
      AnalysisStateCounter.count("excluded")
          ? AnalysisStateCounter.at("excluded")
          : 0U);
  AnalysisState["unknown"] = static_cast<std::int64_t>(
      AnalysisStateCounter.count("unknown")
          ? AnalysisStateCounter.at("unknown")
          : 0U);

  json::Value::Object Output;
  Output["total_samples"] = static_cast<std::int64_t>(TotalSamples);
  Output["analysis_state"] = AnalysisState;
  Output["comparable_samples"] =
      static_cast<std::int64_t>(ComparableSampleCount);
  Output["non_comparable_samples"] =
      static_cast<std::int64_t>(NonComparableSampleCount);
  return Output;
}

CampaignReportSnapshot collectCampaignReportSnapshot(
    const std::filesystem::path &Root,
    const std::optional<std::filesystem::path> &AssociatedWorkDir) {
  CampaignReportSnapshot Snapshot;
  const auto TriageSnapshot = collectTriageReportSnapshot(Root);
  Snapshot.Root = TriageSnapshot.Root;
  Snapshot.StatusCounter = TriageSnapshot.StatusCounter;
  Snapshot.ClusterCounter = TriageSnapshot.ClusterCounter;
  Snapshot.ClusterSamples = TriageSnapshot.ClusterSamples;
  Snapshot.SemanticFrontierEntries = TriageSnapshot.SemanticFrontierEntries;
  Snapshot.TotalSamples = TriageSnapshot.TotalSamples;
  Snapshot.SampleDirs = collectSampleDirs(normalizePath(Root));
  Snapshot.NeedsReviewCount = 0;
  Snapshot.OracleAuditCandidateCount = 0;

  std::map<std::string, size_t> AnalysisStateCounter = {
      {"included", 0U}, {"excluded", 0U}, {"unknown", 0U}};
  for (const auto &SampleDir : Snapshot.SampleDirs) {
    const auto SampleMetaPayload = loadSampleMetaPayload(SampleDir);
    Snapshot.SampleMetaPayloads.push_back(SampleMetaPayload);
    const auto TriagePayload =
        std::filesystem::is_regular_file(SampleDir / "triage.json")
            ? loadTriagePayload(SampleDir)
            : buildTriageFallbackPayload(SampleDir, SampleMetaPayload);

    const auto FailureBucketPrimary = coerceFailureBucketPrimary(
        findObjectValue(TriagePayload, "failure_bucket_primary"));
    const auto FailureBucketDetail = coerceFailureBucketDetail(
        findObjectValue(TriagePayload, "failure_bucket_detail"));
    ++Snapshot.FailureBucketPrimaryCounter[FailureBucketPrimary];
    ++Snapshot.FailureTaxonomyCounter[{FailureBucketPrimary, FailureBucketDetail}];

    const auto SemanticOutcome =
        coerceText(findObjectValue(TriagePayload, "semantic_outcome"), "unknown");
    ++Snapshot.SemanticCounts[SemanticOutcome];

    const auto AnalysisState =
        coerceAnalysisState(findObjectValue(TriagePayload, "analysis_state"));
    ++AnalysisStateCounter[AnalysisState];

    if (coerceBool(findObjectValue(TriagePayload, "needs_manual_review"))) {
      ++Snapshot.NeedsReviewCount;
    }
    if (coerceBool(findObjectValue(TriagePayload, "oracle_audit_candidate"))) {
      ++Snapshot.OracleAuditCandidateCount;
    }
    Snapshot.AuditRecords.push_back(
        buildCampaignAuditRecord(SampleDir, SampleMetaPayload, TriagePayload));
  }

  Snapshot.SemanticDiffCount =
      Snapshot.FailureBucketPrimaryCounter.count("semantic_diff")
          ? Snapshot.FailureBucketPrimaryCounter.at("semantic_diff")
          : 0U;
  Snapshot.AnalysisStateCounter = AnalysisStateCounter;

  Snapshot.Comparability =
      buildComparabilityPayload(Snapshot.SampleMetaPayloads);

  const auto WorkDir = resolveAssociatedWorkDir(Root, AssociatedWorkDir);
  if (WorkDir.has_value()) {
    Snapshot.StatePayload = loadAuxiliaryObject(*WorkDir / "follow_diff.state.json");
    Snapshot.WindowSummaryPayload =
        loadAuxiliaryObject(*WorkDir / "follow_diff.window.summary.json");
    if (Snapshot.WindowSummaryPayload.has_value()) {
      Snapshot.RunId =
          coerceOptionalText(findObjectValue(*Snapshot.WindowSummaryPayload, "run_id"));
    }
    if (!Snapshot.RunId.has_value() && Snapshot.StatePayload.has_value()) {
      Snapshot.RunId =
          coerceOptionalText(findObjectValue(*Snapshot.StatePayload, "run_id"));
    }
  }
  Snapshot.SeedProvenance = deriveSeedProvenance(
      Snapshot.SampleMetaPayloads, Snapshot.WindowSummaryPayload);

  return Snapshot;
}

std::map<std::string, std::string>
buildRegenerationCommands(const std::filesystem::path &Root,
                          const std::filesystem::path &ReportDir,
                          const std::optional<std::filesystem::path> &ReportBase) {
  const auto DnslabctlBin =
      (std::filesystem::current_path() / "build/linux/x86_64/release/dnslabctl")
          .lexically_normal()
          .string();
  std::map<std::string, std::string> Commands;
  Commands["triage_rewrite"] =
      "python3 -m tools.dns_diff.cli triage --root " + Root.string() +
      " --rewrite";
  Commands["triage_report"] =
      DnslabctlBin + " report --root " + Root.string();
  Commands["campaign_report"] =
      DnslabctlBin + " campaign-report --root " + Root.string();
  if (ReportBase.has_value()) {
    Commands["campaign_report"] += " --output-dir " + ReportBase->string();
  }
  Commands["case_study_export"] =
      DnslabctlBin + " case-study-export --root " + Root.string() +
      " --campaign-report-dir " + ReportDir.string();
  return Commands;
}

json::Value buildPublicationEvidenceBundle(
    const std::filesystem::path &Root,
    const std::filesystem::path &ReportDir,
    const json::Value::Object &Summary,
    const CampaignReportSnapshot &Snapshot,
    const std::optional<std::filesystem::path> &ReportBase) {
  const auto Commands = buildRegenerationCommands(Root, ReportDir, ReportBase);
  const auto buildArtifactReference =
      [&](const std::filesystem::path &Path, const std::string &RegenerationCommand,
          bool Optional = false,
          const std::optional<std::vector<std::string>> &FieldPaths =
              std::nullopt,
          const std::optional<std::vector<std::string>> &ColumnPaths =
              std::nullopt) {
        json::Value::Object Payload;
        Payload["path"] = normalizePath(Path).string();
        Payload["exists"] = std::filesystem::is_regular_file(Path);
        Payload["optional"] = Optional;
        Payload["regeneration_command"] = RegenerationCommand;
        if (FieldPaths.has_value()) {
          json::Value::Array Items;
          for (const auto &Field : *FieldPaths) {
            Items.emplace_back(Field);
          }
          Payload["field_paths"] = Items;
        }
        if (ColumnPaths.has_value()) {
          json::Value::Array Items;
          for (const auto &Field : *ColumnPaths) {
            Items.emplace_back(Field);
          }
          Payload["column_paths"] = Items;
        }
        return Payload;
      };

  json::Value::Object Payload;
  Payload["contract_name"] = kPublicationEvidenceBundleContractName;
  Payload["contract_version"] = static_cast<std::int64_t>(kContractVersion);
  Payload["campaign_summary"] = buildArtifactReference(
      ReportDir / "summary.json", Commands.at("campaign_report"), false,
      std::vector<std::string>{"campaign_id",
                               "total_samples",
                               "needs_review_count",
                               "cluster_count",
                               "semantic_diff_count",
                               "metric_denominators.analysis_state.included",
                               "metric_denominators.analysis_state.excluded",
                               "metric_denominators.analysis_state.unknown",
                               "repro_rate",
                               "seed_provenance"});
  Payload["oracle_audit"] = buildArtifactReference(
      ReportDir / "oracle_audit.tsv", Commands.at("campaign_report"), false,
      std::nullopt, kAuditColumns);
  Payload["oracle_reliability"] = buildArtifactReference(
      ReportDir / "oracle_reliability.json", Commands.at("campaign_report"),
      false,
      std::vector<std::string>{"signals.response_accepted_any",
                               "signals.second_query_hit_any",
                               "signals.cache_entry_created_any",
                               "signals.oracle_diff_any",
                               "signal_combos.oracle_diff_plus_cache_diff"});
  Payload["failure_taxonomy"] = buildArtifactReference(
      ReportDir / "failure_taxonomy.tsv", Commands.at("campaign_report"), false,
      std::nullopt,
      std::vector<std::string>{"failure_bucket_primary",
                               "failure_bucket_detail", "count"});
  Payload["exclusion_summary"] = buildArtifactReference(
      ReportDir / "exclusion_summary.tsv", Commands.at("campaign_report"), false,
      std::nullopt,
      std::vector<std::string>{"failure_bucket_primary", "analysis_state",
                               "count"});
  Payload["case_study_index"] = buildArtifactReference(
      ReportDir / "case_studies/index.tsv", Commands.at("case_study_export"), true,
      std::nullopt,
      std::vector<std::string>{"sample_id", "semantic_outcome",
                               "selection_reason", "case_study_path"});

  json::Value::Object RawSampleRoot;
  RawSampleRoot["path"] = normalizePath(Root).string();
  RawSampleRoot["exists"] = std::filesystem::is_directory(Root);
  RawSampleRoot["sample_dir_pattern"] = "<raw_sample_root>/<sample_id>/";
  json::Value::Array ClaimReviewArtifacts;
  for (const auto &Artifact : collectClaimReviewArtifacts(Snapshot.SampleMetaPayloads)) {
    ClaimReviewArtifacts.emplace_back(Artifact);
  }
  RawSampleRoot["claim_review_artifacts"] = ClaimReviewArtifacts;
  Payload["raw_sample_root"] = RawSampleRoot;

  if (Snapshot.SeedProvenance.has_value()) {
    Payload["seed_provenance"] = *Snapshot.SeedProvenance;
  } else {
    Payload["seed_provenance"] = json::Value();
  }

  json::Value::Object CommandsValue;
  for (const auto &[Key, Value] : Commands) {
    CommandsValue[Key] = Value;
  }
  Payload["regeneration_commands"] = CommandsValue;

  json::Value::Array Claims;
  const auto buildClaim =
      [&](const std::string &Claim, const json::Value &Value,
          const std::string &FieldPath, const std::string &Guardrail) {
        json::Value::Object Item;
        Item["claim"] = Claim;
        Item["value"] = Value;
        Item["artifact"] = "campaign_summary";
        Item["source_file_path"] = normalizePath(ReportDir / "summary.json").string();
        Item["field_path"] = FieldPath;
        Item["regeneration_command"] = Commands.at("campaign_report");
        Item["guardrail"] = Guardrail;
        return Item;
      };
  auto SemanticDiffClaim = buildClaim(
      "semantic_diff_count",
      *findObjectValue(Summary, "semantic_diff_count"),
      "semantic_diff_count",
      "included、excluded、unknown 只是 publication-facing 状态，不等于人工确认真值。");
  json::Value::Array SupportingSources;
  json::Value::Object Support;
  Support["artifact"] = "failure_taxonomy";
  Support["source_file_path"] =
      normalizePath(ReportDir / "failure_taxonomy.tsv").string();
  Support["field_path"] = "rows[failure_bucket_primary=semantic_diff].count(sum)";
  SupportingSources.emplace_back(Support);
  SemanticDiffClaim["supporting_sources"] = SupportingSources;
  Claims.emplace_back(SemanticDiffClaim);
  const auto *MetricDenominatorsValue =
      findObjectValue(Summary, "metric_denominators");
  const auto *MetricDenominators =
      MetricDenominatorsValue
          ? std::get_if<json::Value::Object>(&MetricDenominatorsValue->storage())
          : nullptr;
  const auto *AnalysisStateValue =
      MetricDenominators ? findObjectValue(*MetricDenominators, "analysis_state")
                         : nullptr;
  const auto *AnalysisState =
      AnalysisStateValue
          ? std::get_if<json::Value::Object>(&AnalysisStateValue->storage())
          : nullptr;
  const auto analysisStateValue = [&](const std::string &Key) -> json::Value {
    if (AnalysisState == nullptr) {
      return json::Value(static_cast<std::int64_t>(0));
    }
    const auto *Value = findObjectValue(*AnalysisState, Key);
    return Value ? *Value : json::Value(static_cast<std::int64_t>(0));
  };
  const auto ProxyGuardrail =
      std::string("该统计只能说明候选样本的复现或聚类情况，不能把 proxy signal 直接写成漏洞已证实。");
  Claims.emplace_back(buildClaim(
      "included_samples", analysisStateValue("included"),
      "metric_denominators.analysis_state.included",
      "included、excluded、unknown 只是 publication-facing 状态，不等于人工确认真值。"));
  Claims.emplace_back(buildClaim(
      "excluded_samples", analysisStateValue("excluded"),
      "metric_denominators.analysis_state.excluded",
      "included、excluded、unknown 只是 publication-facing 状态，不等于人工确认真值。"));
  Claims.emplace_back(buildClaim(
      "unknown_samples", analysisStateValue("unknown"),
      "metric_denominators.analysis_state.unknown",
      "included、excluded、unknown 只是 publication-facing 状态，不等于人工确认真值。"));
  Claims.emplace_back(buildClaim(
      "repro_rate", *findObjectValue(Summary, "repro_rate"), "repro_rate",
      ProxyGuardrail));
  Claims.emplace_back(buildClaim(
      "cluster_count", *findObjectValue(Summary, "cluster_count"), "cluster_count",
      ProxyGuardrail));
  Payload["claims"] = Claims;
  return json::Value(Payload);
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

TriageReportArtifacts
generateTriageReportArtifacts(const std::filesystem::path &Root,
                              const std::optional<std::filesystem::path>
                                  &HighValueManifestPath) {
  const auto Snapshot = collectTriageReportSnapshot(Root);
  const auto ResolvedRoot = normalizePath(Root);
  const auto ManifestPath = normalizePath(
      HighValueManifestPath.value_or(ResolvedRoot / "high_value_samples.txt"));
  const auto SemanticManifestPath =
      normalizePath(ManifestPath.parent_path() /
                    kSemanticFrontierManifestFileName);
  const auto ClusterSummaryPath = ResolvedRoot / "cluster_summary.tsv";
  const auto StatusSummaryPath = ResolvedRoot / "status_summary.tsv";
  const auto TriageReportMarkdownPath = ResolvedRoot / "triage_report.md";

  writeTextFile(ClusterSummaryPath, buildClusterSummaryContent(Snapshot));
  writeTextFile(StatusSummaryPath, buildStatusSummaryContent(Snapshot));
  try {
    writeTextFile(ManifestPath,
                  buildHighValueManifestContent(Snapshot.SemanticFrontierEntries));
  } catch (const std::exception &Error) {
    throw std::runtime_error("写入 high_value_samples.txt 失败: " +
                             std::string(Error.what()));
  }
  writeJsonFile(SemanticManifestPath,
                buildSemanticFrontierManifest(ResolvedRoot,
                                              Snapshot.SemanticFrontierEntries));
  writeTextFile(TriageReportMarkdownPath, buildTriageReportMarkdown(Snapshot));

  TriageReportArtifacts Output;
  Output.Root = ResolvedRoot;
  Output.ClusterSummaryPath = ClusterSummaryPath;
  Output.StatusSummaryPath = StatusSummaryPath;
  Output.HighValueManifestPath = ManifestPath;
  Output.SemanticFrontierManifestPath = SemanticManifestPath;
  Output.TriageReportMarkdownPath = TriageReportMarkdownPath;
  Output.SampleCount = Snapshot.TotalSamples;
  Output.SemanticFrontierEntryCount = Snapshot.SemanticFrontierEntries.size();
  return Output;
}

CaseStudyExportArtifacts
exportCaseStudies(const std::filesystem::path &Root,
                  const std::filesystem::path &CampaignReportDir,
                  size_t TopN) {
  const auto ResolvedRoot = normalizePath(Root);
  if (!std::filesystem::exists(ResolvedRoot) ||
      !std::filesystem::is_directory(ResolvedRoot)) {
    throw std::runtime_error("follow_diff 根目录不存在或不是目录: " +
                             ResolvedRoot.string());
  }

  const auto ReportDir = normalizePath(CampaignReportDir);
  const auto OutputDir = normalizePath(ReportDir / "case_studies");
  std::filesystem::create_directories(OutputDir);

  auto Candidates = collectCaseStudyCandidates(ResolvedRoot);
  const auto Limit = std::min(TopN, kMaxCaseStudies);
  if (Candidates.size() > Limit) {
    Candidates.resize(Limit);
  }

  for (const auto &Candidate : Candidates) {
    writeJsonFile(OutputDir / (Candidate.SampleId + ".json"),
                  buildCaseStudyPayload(Candidate));
  }

  const auto IndexPath = normalizePath(OutputDir / "index.tsv");
  writeTextFile(IndexPath, buildCaseStudyIndexContent(OutputDir, Candidates));

  CaseStudyExportArtifacts Output;
  Output.Root = ResolvedRoot;
  Output.ReportDir = ReportDir;
  Output.OutputDir = OutputDir;
  Output.IndexPath = IndexPath;
  Output.SelectedCount = Candidates.size();
  return Output;
}

CampaignReportArtifacts
generateCampaignReportArtifacts(const std::filesystem::path &Root,
                                const std::optional<std::filesystem::path>
                                    &ReportBase,
                                const std::optional<std::filesystem::path>
                                    &AssociatedWorkDir) {
  const auto ResolvedRoot = normalizePath(Root);
  std::filesystem::create_directories(ResolvedRoot);
  const std::optional<std::filesystem::path> PreferredHighValueManifestPath =
      AssociatedWorkDir.has_value()
          ? std::optional<std::filesystem::path>(*AssociatedWorkDir /
                                                 "high_value_samples.txt")
          : std::nullopt;
  const auto TriageArtifacts =
      generateTriageReportArtifacts(ResolvedRoot, PreferredHighValueManifestPath);
  const auto Snapshot =
      collectCampaignReportSnapshot(ResolvedRoot, AssociatedWorkDir);

  const auto ReportBasePath = normalizePath(
      ReportBase.value_or(ResolvedRoot / "campaign_reports"));
  const auto ReportDir = ReportBasePath / compactTimestampNow();
  std::filesystem::create_directories(ReportDir);

  const auto HighValueManifestPath = TriageArtifacts.HighValueManifestPath;
  std::set<std::filesystem::path> ManifestPaths;
  std::set<std::filesystem::path> ManifestSampleDirs;
  if (std::filesystem::is_regular_file(HighValueManifestPath)) {
    std::istringstream ManifestStream(readTextFile(HighValueManifestPath));
    std::string Line;
    while (std::getline(ManifestStream, Line)) {
      if (Line.empty()) {
        continue;
      }
      const auto Path = normalizePath(Line);
      if (!std::filesystem::is_regular_file(Path)) {
        continue;
      }
      ManifestPaths.insert(Path);
      ManifestSampleDirs.insert(Path.parent_path());
    }
  }

  size_t ReproducedCount = 0;
  for (const auto &SampleDir : Snapshot.SampleDirs) {
    if (ManifestSampleDirs.count(normalizePath(SampleDir)) != 0U) {
      ++ReproducedCount;
    }
  }
  const size_t ManifestSize = ManifestPaths.size();
  const double ReproRate =
      ManifestSize == 0U
          ? 0.0
          : static_cast<double>(ReproducedCount) /
                static_cast<double>(ManifestSize);

  json::Value::Object MetricDenominators = buildMetricDenominators(
      Snapshot.TotalSamples, Snapshot.AnalysisStateCounter,
      *Snapshot.Comparability);

  json::Value::Object AblationStatus;
  AblationStatus["mutator"] =
      (std::getenv("ENABLE_DST1_MUTATOR") &&
       std::string(std::getenv("ENABLE_DST1_MUTATOR")) == "1")
          ? "on"
          : "off";
  AblationStatus["cache-delta"] =
      (!std::getenv("ENABLE_CACHE_DELTA") ||
       std::string(std::getenv("ENABLE_CACHE_DELTA")) == "1")
          ? "on"
          : "off";
  AblationStatus["triage"] =
      (!std::getenv("ENABLE_TRIAGE") ||
       std::string(std::getenv("ENABLE_TRIAGE")) == "1")
          ? "on"
          : "off";
  AblationStatus["symcc"] =
      (!std::getenv("ENABLE_SYMCC") ||
       std::string(std::getenv("ENABLE_SYMCC")) == "1")
          ? "on"
          : "off";

  json::Value::Object Summary;
  std::map<std::string, std::int64_t> ExecutedResolverCounts;
  std::map<std::string, std::int64_t> SkippedResolverCounts;
  std::map<std::string, std::int64_t> ResolverPairDiffCounts;
  size_t DiffDetectedCount = 0;
  for (const auto &Record : Snapshot.AuditRecords) {
    if (Record.DiffDetected) {
      ++DiffDetectedCount;
    }
    for (const auto &ResolverName : Record.ExecutedResolvers) {
      ++ExecutedResolverCounts[ResolverName];
    }
    for (const auto &[ResolverName, Reason] : Record.SkippedResolvers) {
      (void)Reason;
      ++SkippedResolverCounts[ResolverName];
    }
    for (const auto &DifferenceValue : Record.ResolverDiffs) {
      const auto Difference = coerceObjectOrEmpty(&DifferenceValue);
      const auto Left =
          coerceText(findObjectValue(Difference, "left_resolver"), "");
      const auto Right =
          coerceText(findObjectValue(Difference, "right_resolver"), "");
      if (!Left.empty() && !Right.empty()) {
        ++ResolverPairDiffCounts[Left + "_vs_" + Right];
      }
    }
  }
  Summary["campaign_id"] = ReportDir.filename().string();
  Summary["total_samples"] =
      static_cast<std::int64_t>(Snapshot.TotalSamples);
  Summary["needs_review_count"] =
      static_cast<std::int64_t>(Snapshot.NeedsReviewCount);
  Summary["cluster_count"] =
      static_cast<std::int64_t>(Snapshot.ClusterCounter.size());
  Summary["contract_version"] = static_cast<std::int64_t>(kContractVersion);
  Summary["metric_denominators"] = MetricDenominators;
  json::Value::Object SemanticCounts;
  for (const auto &[Outcome, Count] : Snapshot.SemanticCounts) {
    SemanticCounts[Outcome] = static_cast<std::int64_t>(Count);
  }
  Summary["semantic_counts"] = SemanticCounts;
  Summary["semantic_diff_count"] =
      static_cast<std::int64_t>(Snapshot.SemanticDiffCount);
  Summary["oracle_audit_candidate_count"] =
      static_cast<std::int64_t>(Snapshot.OracleAuditCandidateCount);
  Summary["diff_detected_sample_count"] =
      static_cast<std::int64_t>(DiffDetectedCount);
  json::Value::Array ExecutedResolvers;
  for (const auto &[ResolverName, Count] : ExecutedResolverCounts) {
    (void)Count;
    ExecutedResolvers.emplace_back(ResolverName);
  }
  Summary["executed_resolvers"] = ExecutedResolvers;
  json::Value::Object ExecutedResolverCountsPayload;
  for (const auto &[ResolverName, Count] : ExecutedResolverCounts) {
    ExecutedResolverCountsPayload[ResolverName] = Count;
  }
  Summary["executed_resolver_sample_counts"] =
      ExecutedResolverCountsPayload;
  json::Value::Object SkippedResolverCountsPayload;
  for (const auto &[ResolverName, Count] : SkippedResolverCounts) {
    SkippedResolverCountsPayload[ResolverName] = Count;
  }
  Summary["skipped_resolver_sample_counts"] =
      SkippedResolverCountsPayload;
  json::Value::Object ResolverPairDiffCountsPayload;
  for (const auto &[ResolverPair, Count] : ResolverPairDiffCounts) {
    ResolverPairDiffCountsPayload[ResolverPair] = Count;
  }
  Summary["resolver_pair_diff_counts"] = ResolverPairDiffCountsPayload;
  Summary["comparability"] = *Snapshot.Comparability;
  json::setOptional(Summary, "run_id", Snapshot.RunId);
  Summary["ablation_status"] = AblationStatus;
  if (Snapshot.SeedProvenance.has_value()) {
    Summary["seed_provenance"] = *Snapshot.SeedProvenance;
  } else {
    Summary["seed_provenance"] = json::Value();
  }
  Summary["manifest_size"] = static_cast<std::int64_t>(ManifestSize);
  Summary["reproduced_count"] = static_cast<std::int64_t>(ReproducedCount);
  Summary["repro_rate"] = ReproRate;

  const auto SummaryPath = ReportDir / "summary.json";
  const auto AblationMatrixPath = ReportDir / "ablation_matrix.tsv";
  const auto ClusterCountsPath = ReportDir / "cluster_counts.tsv";
  const auto FailureTaxonomyPath = ReportDir / "failure_taxonomy.tsv";
  const auto ExclusionSummaryPath = ReportDir / "exclusion_summary.tsv";
  const auto ReproRatePath = ReportDir / "repro_rate.tsv";
  const auto OracleAuditPath = ReportDir / "oracle_audit.tsv";
  const auto OracleReliabilityPath = ReportDir / "oracle_reliability.json";
  const auto EvidenceBundlePath = ReportDir / "evidence_bundle.json";

  writeJsonFile(SummaryPath, Summary);
  writeTextFile(AblationMatrixPath,
                "module\tstatus\n"
                "cache-delta\t" +
                    coerceText(findObjectValue(AblationStatus, "cache-delta"),
                               "off") +
                    "\nmutator\t" +
                    coerceText(findObjectValue(AblationStatus, "mutator"), "off") +
                    "\nsymcc\t" +
                    coerceText(findObjectValue(AblationStatus, "symcc"), "off") +
                    "\ntriage\t" +
                    coerceText(findObjectValue(AblationStatus, "triage"), "off") +
                    "\n");

  {
    std::ostringstream Stream;
    Stream << "cluster_key\tcount\n";
    if (Snapshot.ClusterCounter.empty()) {
      Stream << "_\t0\n";
    } else {
      for (const auto &[ClusterKey, Count] : Snapshot.ClusterCounter) {
        Stream << ClusterKey << '\t' << Count << '\n';
      }
    }
    writeTextFile(ClusterCountsPath, Stream.str());
  }

  {
    std::ostringstream Stream;
    Stream << "failure_bucket_primary\tfailure_bucket_detail\tcount\n";
    for (const auto &[Key, Count] : Snapshot.FailureTaxonomyCounter) {
      Stream << Key.first << '\t' << Key.second << '\t' << Count << '\n';
    }
    Stream << "__total__\t-\t" << Snapshot.TotalSamples << '\n';
    writeTextFile(FailureTaxonomyPath, Stream.str());
  }

  {
    std::ostringstream Stream;
    Stream << "failure_bucket_primary\tanalysis_state\tcount\n";
    for (const auto &Primary : kFailureBucketPrimaryOrder) {
      const auto Count = Snapshot.FailureBucketPrimaryCounter.count(Primary)
                             ? Snapshot.FailureBucketPrimaryCounter.at(Primary)
                             : 0U;
      Stream << Primary << '\t' << kExclusionStateByPrimary.at(Primary) << '\t'
             << Count << '\n';
    }
    Stream << "__total__\t-\t" << Snapshot.TotalSamples << '\n';
    writeTextFile(ExclusionSummaryPath, Stream.str());
  }

  {
    std::ostringstream Stream;
    Stream << "metric\tvalue\n";
    Stream << "manifest_size\t" << ManifestSize << '\n';
    Stream << "reproduced_count\t" << ReproducedCount << '\n';
    Stream.setf(std::ios::fixed, std::ios::floatfield);
    Stream.precision(4);
    Stream << "repro_rate\t" << ReproRate << '\n';
    writeTextFile(ReproRatePath, Stream.str());
  }

  {
    std::ostringstream Stream;
    for (size_t Index = 0; Index < kAuditColumns.size(); ++Index) {
      if (Index != 0) {
        Stream << '\t';
      }
      Stream << kAuditColumns[Index];
    }
    Stream << '\n';
    for (const auto &Record : Snapshot.AuditRecords) {
      Stream << auditRow(Record) << '\n';
    }
    writeTextFile(OracleAuditPath, Stream.str());
  }

  writeJsonFile(OracleReliabilityPath,
                buildOracleReliability(Snapshot.AuditRecords));
  writeJsonFile(EvidenceBundlePath,
                buildPublicationEvidenceBundle(ResolvedRoot, ReportDir, Summary,
                                               Snapshot, ReportBasePath));

  CampaignReportArtifacts Output;
  Output.Root = ResolvedRoot;
  Output.ReportDir = ReportDir;
  Output.SummaryPath = SummaryPath;
  Output.AblationMatrixPath = AblationMatrixPath;
  Output.ClusterCountsPath = ClusterCountsPath;
  Output.FailureTaxonomyPath = FailureTaxonomyPath;
  Output.ExclusionSummaryPath = ExclusionSummaryPath;
  Output.ReproRatePath = ReproRatePath;
  Output.OracleAuditPath = OracleAuditPath;
  Output.OracleReliabilityPath = OracleReliabilityPath;
  Output.EvidenceBundlePath = EvidenceBundlePath;
  Output.SampleCount = Snapshot.TotalSamples;
  Output.ClusterCount = Snapshot.ClusterCounter.size();
  Output.OracleAuditCandidateCount = Snapshot.OracleAuditCandidateCount;
  Output.SemanticDiffCount = Snapshot.SemanticDiffCount;
  return Output;
}

json::Value::Object
buildCampaignSummaryPayload(const std::filesystem::path &Root,
                            const std::optional<std::filesystem::path>
                                &AssociatedWorkDir) {
  const auto Snapshot =
      collectCampaignReportSnapshot(normalizePath(Root), AssociatedWorkDir);
  json::Value::Object AblationStatus;
  AblationStatus["mutator"] =
      (std::getenv("ENABLE_DST1_MUTATOR") &&
       std::string(std::getenv("ENABLE_DST1_MUTATOR")) == "1")
          ? "on"
          : "off";
  AblationStatus["cache-delta"] =
      (!std::getenv("ENABLE_CACHE_DELTA") ||
       std::string(std::getenv("ENABLE_CACHE_DELTA")) == "1")
          ? "on"
          : "off";
  AblationStatus["triage"] =
      (!std::getenv("ENABLE_TRIAGE") ||
       std::string(std::getenv("ENABLE_TRIAGE")) == "1")
          ? "on"
          : "off";
  AblationStatus["symcc"] =
      (!std::getenv("ENABLE_SYMCC") ||
       std::string(std::getenv("ENABLE_SYMCC")) == "1")
          ? "on"
          : "off";

  const auto ManifestSize = static_cast<std::int64_t>(
      std::count_if(Snapshot.SemanticFrontierEntries.begin(),
                    Snapshot.SemanticFrontierEntries.end(),
                    [](const SemanticFrontierEntry &Entry) {
                      return Entry.PriorityTier > 0;
                    }));

  std::map<std::string, std::int64_t> ExecutedResolverCounts;
  std::map<std::string, std::int64_t> SkippedResolverCounts;
  std::map<std::string, std::int64_t> ResolverPairDiffCounts;
  size_t DiffDetectedCount = 0;
  for (const auto &Record : Snapshot.AuditRecords) {
    if (Record.DiffDetected) {
      ++DiffDetectedCount;
    }
    for (const auto &ResolverName : Record.ExecutedResolvers) {
      ++ExecutedResolverCounts[ResolverName];
    }
    for (const auto &[ResolverName, Reason] : Record.SkippedResolvers) {
      (void)Reason;
      ++SkippedResolverCounts[ResolverName];
    }
    for (const auto &DifferenceValue : Record.ResolverDiffs) {
      const auto Difference = coerceObjectOrEmpty(&DifferenceValue);
      const auto Left =
          coerceText(findObjectValue(Difference, "left_resolver"), "");
      const auto Right =
          coerceText(findObjectValue(Difference, "right_resolver"), "");
      if (!Left.empty() && !Right.empty()) {
        ++ResolverPairDiffCounts[Left + "_vs_" + Right];
      }
    }
  }

  json::Value::Object Summary;
  Summary["campaign_id"] = compactTimestampNow();
  Summary["total_samples"] = static_cast<std::int64_t>(Snapshot.TotalSamples);
  Summary["needs_review_count"] =
      static_cast<std::int64_t>(Snapshot.NeedsReviewCount);
  Summary["cluster_count"] =
      static_cast<std::int64_t>(Snapshot.ClusterCounter.size());
  Summary["contract_version"] = static_cast<std::int64_t>(kContractVersion);
  Summary["metric_denominators"] = buildMetricDenominators(
      Snapshot.TotalSamples, Snapshot.AnalysisStateCounter,
      *Snapshot.Comparability);
  json::Value::Object SemanticCounts;
  for (const auto &[Outcome, Count] : Snapshot.SemanticCounts) {
    SemanticCounts[Outcome] = static_cast<std::int64_t>(Count);
  }
  Summary["semantic_counts"] = SemanticCounts;
  Summary["semantic_diff_count"] =
      static_cast<std::int64_t>(Snapshot.SemanticDiffCount);
  Summary["oracle_audit_candidate_count"] =
      static_cast<std::int64_t>(Snapshot.OracleAuditCandidateCount);
  Summary["diff_detected_sample_count"] =
      static_cast<std::int64_t>(DiffDetectedCount);
  json::Value::Array ExecutedResolvers;
  for (const auto &[ResolverName, Count] : ExecutedResolverCounts) {
    (void)Count;
    ExecutedResolvers.emplace_back(ResolverName);
  }
  Summary["executed_resolvers"] = ExecutedResolvers;
  json::Value::Object ExecutedResolverCountsPayload;
  for (const auto &[ResolverName, Count] : ExecutedResolverCounts) {
    ExecutedResolverCountsPayload[ResolverName] = Count;
  }
  Summary["executed_resolver_sample_counts"] =
      ExecutedResolverCountsPayload;
  json::Value::Object SkippedResolverCountsPayload;
  for (const auto &[ResolverName, Count] : SkippedResolverCounts) {
    SkippedResolverCountsPayload[ResolverName] = Count;
  }
  Summary["skipped_resolver_sample_counts"] =
      SkippedResolverCountsPayload;
  json::Value::Object ResolverPairDiffCountsPayload;
  for (const auto &[ResolverPair, Count] : ResolverPairDiffCounts) {
    ResolverPairDiffCountsPayload[ResolverPair] = Count;
  }
  Summary["resolver_pair_diff_counts"] = ResolverPairDiffCountsPayload;
  Summary["comparability"] = *Snapshot.Comparability;
  json::setOptional(Summary, "run_id", Snapshot.RunId);
  Summary["ablation_status"] = AblationStatus;
  if (Snapshot.SeedProvenance.has_value()) {
    Summary["seed_provenance"] = *Snapshot.SeedProvenance;
  } else {
    Summary["seed_provenance"] = json::Value();
  }
  Summary["manifest_size"] = ManifestSize;
  Summary["reproduced_count"] = ManifestSize;
  Summary["repro_rate"] = ManifestSize == 0 ? json::Value(0.0) : json::Value(1.0);
  return Summary;
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

json::Value toJson(const SemanticFrontierEntry &Input) {
  json::Value::Object Output;
  Output["sample_path"] = Input.SamplePath;
  Output["sample_id"] = Input.SampleId;
  Output["analysis_state"] = Input.AnalysisState;
  Output["semantic_outcome"] = Input.SemanticOutcome;
  Output["oracle_audit_candidate"] = Input.OracleAuditCandidate;
  Output["needs_manual_review"] = Input.NeedsManualReview;
  Output["priority_tier"] = Input.PriorityTier;
  return Output;
}

json::Value toJson(const TriageReportArtifacts &Input) {
  json::Value::Object Output;
  Output["root"] = Input.Root.string();
  Output["cluster_summary"] = Input.ClusterSummaryPath.string();
  Output["status_summary"] = Input.StatusSummaryPath.string();
  Output["high_value_manifest"] = Input.HighValueManifestPath.string();
  Output["semantic_frontier_manifest"] =
      Input.SemanticFrontierManifestPath.string();
  Output["triage_report_markdown"] = Input.TriageReportMarkdownPath.string();
  Output["sample_count"] = static_cast<std::int64_t>(Input.SampleCount);
  Output["semantic_frontier_entry_count"] =
      static_cast<std::int64_t>(Input.SemanticFrontierEntryCount);
  return Output;
}

json::Value toJson(const CaseStudyExportArtifacts &Input) {
  json::Value::Object Output;
  Output["root"] = Input.Root.string();
  Output["report_dir"] = Input.ReportDir.string();
  Output["output_dir"] = Input.OutputDir.string();
  Output["index"] = Input.IndexPath.string();
  Output["selected_count"] = static_cast<std::int64_t>(Input.SelectedCount);
  return Output;
}

json::Value toJson(const CampaignReportArtifacts &Input) {
  json::Value::Object Output;
  Output["root"] = Input.Root.string();
  Output["report_dir"] = Input.ReportDir.string();
  Output["summary"] = Input.SummaryPath.string();
  Output["ablation_matrix"] = Input.AblationMatrixPath.string();
  Output["cluster_counts"] = Input.ClusterCountsPath.string();
  Output["failure_taxonomy"] = Input.FailureTaxonomyPath.string();
  Output["exclusion_summary"] = Input.ExclusionSummaryPath.string();
  Output["repro_rate"] = Input.ReproRatePath.string();
  Output["oracle_audit"] = Input.OracleAuditPath.string();
  Output["oracle_reliability"] = Input.OracleReliabilityPath.string();
  Output["evidence_bundle"] = Input.EvidenceBundlePath.string();
  Output["sample_count"] = static_cast<std::int64_t>(Input.SampleCount);
  Output["cluster_count"] = static_cast<std::int64_t>(Input.ClusterCount);
  Output["oracle_audit_candidate_count"] =
      static_cast<std::int64_t>(Input.OracleAuditCandidateCount);
  Output["semantic_diff_count"] =
      static_cast<std::int64_t>(Input.SemanticDiffCount);
  return Output;
}

} // namespace dnslab
