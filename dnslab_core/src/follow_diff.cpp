#include "dnslab_core/follow_diff.hpp"

#include "dnslab_core/cache_analysis.hpp"
#include "dnslab_core/evidence_contract.hpp"
#include "dnslab_core/experiment_config.hpp"
#include "dnslab_core/process.hpp"
#include "dnslab_core/reporting.hpp"
#include "dnslab_core/transcript.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace dnslab {

namespace {

constexpr const char *kFollowDiffStateFileName = "follow_diff.state.json";
constexpr const char *kFollowDiffWindowSummaryFileName =
    "follow_diff.window.summary.json";
constexpr const char *kCampaignCloseSummaryFileName =
    "campaign_close.summary.json";
constexpr const char *kFollowDiffOutputDirName = "follow_diff";
constexpr int kExitDeadlineExceeded = 6;

struct ProcessFailure : std::runtime_error {
  ProcessFailure(std::string Message, int Code)
      : std::runtime_error(std::move(Message)), ExitCode(Code) {}

  int ExitCode = 1;
};

struct FollowDiffConfig {
  std::filesystem::path RootDir;
  std::filesystem::path WorkDir;
  std::filesystem::path SourceDir;
  std::filesystem::path OutputRoot;
  std::filesystem::path StatePath;
  std::filesystem::path WindowSummaryPath;
  std::filesystem::path CampaignCloseSummaryPath;
  std::filesystem::path SeedProvenancePath;
  std::filesystem::path SelfExecutable;
  std::filesystem::path Bind9BuildRoot;
  std::filesystem::path Bind9SourceRoot;
  std::filesystem::path SecondaryBuildRoot;
  std::filesystem::path SecondarySourceRoot;
  std::string SecondaryResolver = "unbound";
  double IntervalSec = 1.0;
  int IdleRounds = 1;
  int SeedTimeoutSec = 5;
};

struct BatchSummary {
  size_t Scanned = 0;
  size_t Attempted = 0;
  size_t Completed = 0;
  size_t Failed = 0;
  size_t Skipped = 0;
  std::optional<std::string> LastQueueEventId;
};

struct RecoveryAudit {
  std::string Status = "none";
  std::optional<std::string> SampleId;
  std::optional<std::string> Detail;
};

struct FollowDiffStateData {
  std::optional<std::string> RunId;
  std::optional<std::string> LastExitReason;
  std::optional<std::string> LastAttemptTs;
  std::optional<std::string> LastScanTs;
  std::optional<std::string> LastQueueEventId;
  std::optional<std::string> RunningSampleId;
  std::optional<json::Value::Object> AggregationKey;
  std::optional<json::Value::Object> BaselineCompareKey;
  size_t RetryCount = 0;
  size_t CompletedCount = 0;
  size_t FailedCount = 0;
  size_t ScannedCount = 0;
};

struct PhaseRecord {
  std::string Status = "not_started";
  std::string StartedAt;
  std::string FinishedAt;
  double DurationSec = 0.0;
  std::string ExitReason = "not_started";
  int ExitCode = 0;
  std::optional<std::string> Message;
};

std::filesystem::path normalizePath(const std::filesystem::path &Input) {
  std::error_code Error;
  const auto Absolute = std::filesystem::absolute(Input, Error);
  if (Error) {
    return Input.lexically_normal();
  }
  return Absolute.lexically_normal();
}

std::vector<std::uint8_t> readBinaryFile(const std::filesystem::path &InputPath) {
  std::ifstream Input(InputPath, std::ios::binary);
  if (!Input) {
    throw std::runtime_error("无法读取文件: " + InputPath.string());
  }
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(Input)),
                                   std::istreambuf_iterator<char>());
}

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
    if (CodePoint <= 0x7FU) {
      Output.push_back(static_cast<char>(CodePoint));
      return;
    }
    if (CodePoint <= 0x7FFU) {
      Output.push_back(static_cast<char>(0xC0U | ((CodePoint >> 6) & 0x1FU)));
      Output.push_back(static_cast<char>(0x80U | (CodePoint & 0x3FU)));
      return;
    }
    if (CodePoint <= 0xFFFFU) {
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
      while (Position_ < Input_.size() &&
             std::isdigit(static_cast<unsigned char>(Input_[Position_]))) {
        ++Position_;
      }
    }
    const auto Text = Input_.substr(Begin, Position_ - Begin);
    if (IsDouble) {
      return json::Value(std::stod(Text));
    }
    return json::Value(static_cast<std::int64_t>(std::stoll(Text)));
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

const json::Value *findObjectValue(const json::Value::Object &Object,
                                   const std::string &Key) {
  const auto Found = Object.find(Key);
  if (Found == Object.end()) {
    return nullptr;
  }
  return &Found->second;
}

std::optional<json::Value::Object>
loadObjectIfPresent(const std::filesystem::path &InputPath) {
  if (!std::filesystem::is_regular_file(InputPath)) {
    return std::nullopt;
  }
  const auto Parsed = JsonParser(readTextFile(InputPath)).parse();
  if (const auto *Object = std::get_if<json::Value::Object>(&Parsed.storage())) {
    return *Object;
  }
  throw std::runtime_error("JSON 顶层必须是对象: " + InputPath.string());
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

json::Value budgetJsonValue(double BudgetSec) {
  const auto Rounded = std::llround(BudgetSec);
  if (std::fabs(BudgetSec - static_cast<double>(Rounded)) < 1e-9) {
    return json::Value(static_cast<std::int64_t>(Rounded));
  }
  return json::Value(BudgetSec);
}

std::filesystem::path resolvePathEnv(const char *Name,
                                     const std::filesystem::path &Fallback) {
  const char *Value = std::getenv(Name);
  if (Value == nullptr || *Value == '\0') {
    return normalizePath(Fallback);
  }
  return normalizePath(std::filesystem::path(Value));
}

std::string resolveTextEnv(const char *Name, const std::string &Fallback) {
  const char *Value = std::getenv(Name);
  if (Value == nullptr || *Value == '\0') {
    return Fallback;
  }
  return Value;
}

double resolvePositiveDoubleEnv(const char *Name, double Fallback) {
  const char *Value = std::getenv(Name);
  if (Value == nullptr || *Value == '\0') {
    return Fallback;
  }
  const double Parsed = std::stod(Value);
  return Parsed > 0 ? Parsed : Fallback;
}

int resolvePositiveIntEnv(const char *Name, int Fallback) {
  const char *Value = std::getenv(Name);
  if (Value == nullptr || *Value == '\0') {
    return Fallback;
  }
  const int Parsed = std::stoi(Value);
  return Parsed > 0 ? Parsed : Fallback;
}

std::filesystem::path resolveSelfExecutable() {
  if (const char *SelfExecutable = std::getenv("DNSLAB_SELF_EXECUTABLE");
      SelfExecutable != nullptr && *SelfExecutable != '\0') {
    return normalizePath(SelfExecutable);
  }
  std::error_code Error;
  const auto SelfPath = std::filesystem::read_symlink("/proc/self/exe", Error);
  if (!Error && !SelfPath.empty()) {
    return normalizePath(SelfPath);
  }
  return normalizePath(std::filesystem::current_path() /
                       "build/linux/x86_64/release/dnslabctl");
}

std::filesystem::path resolveRootDir() {
  return resolvePathEnv("ROOT_DIR", std::filesystem::current_path());
}

std::filesystem::path resolveWorkDir(const std::filesystem::path &RootDir) {
  return resolvePathEnv("WORK_DIR", RootDir / "work");
}

std::filesystem::path resolveBind9WorkDir(const std::filesystem::path &RootDir) {
  const char *Bind9WorkDir = std::getenv("BIND9_WORK_DIR");
  if (Bind9WorkDir != nullptr && *Bind9WorkDir != '\0') {
    return normalizePath(Bind9WorkDir);
  }
  const char *WorkDir = std::getenv("WORK_DIR");
  if (WorkDir != nullptr && *WorkDir != '\0') {
    return normalizePath(WorkDir);
  }
  return resolvePathEnv("BIND9_WORK_DIR", RootDir / "bind9-work");
}

std::filesystem::path
resolveSourceDir(const std::filesystem::path &Bind9WorkDir) {
  return resolvePathEnv("FOLLOW_DIFF_SOURCE_DIR",
                        Bind9WorkDir / "afl_out/master/queue");
}

std::filesystem::path
resolveOutputRoot(const std::filesystem::path &WorkDir) {
  return normalizePath(WorkDir / kFollowDiffOutputDirName);
}

std::string resolveSecondaryResolver() {
  return resolveTextEnv("DNS_DIFF_SECONDARY_RESOLVER", "unbound");
}

std::filesystem::path resolveBind9BuildRoot(const std::filesystem::path &RootDir) {
  return resolvePathEnv("BIND9_AFL_TREE", RootDir / "bind-9.18.46-afl");
}

std::filesystem::path
resolveBind9SourceRoot(const std::filesystem::path &BuildRoot) {
  return resolvePathEnv("BIND9_SRC_TREE", BuildRoot);
}

std::filesystem::path
resolveSecondaryBuildRoot(const std::filesystem::path &RootDir,
                          const std::string &Resolver) {
  if (Resolver == "unbound") {
    return resolvePathEnv("AFL_TREE", RootDir / "unbound-1.24.2-afl");
  }
  if (Resolver == "dnsmasq") {
    return resolvePathEnv("DNSMASQ_BUILD_TREE",
                          RootDir / "experiments/subjects/dnsmasq/v2.92-build");
  }
  if (Resolver == "smartdns") {
    return resolvePathEnv(
        "SMARTDNS_BUILD_TREE",
        RootDir / "experiments/subjects/smartdns/Release47.1-build");
  }
  if (Resolver == "maradns") {
    return resolvePathEnv(
        "MARADNS_BUILD_TREE",
        RootDir / "experiments/subjects/maradns/deadwood-3.3.02-build");
  }
  if (Resolver == "knot-resolver") {
    return resolvePathEnv(
        "KNOT_RESOLVER_BUILD_TREE",
        RootDir / "experiments/subjects/knot-resolver/v6.2.0-build");
  }
  throw std::runtime_error("不支持的 secondary resolver: " + Resolver);
}

std::filesystem::path
resolveSecondarySourceRoot(const std::string &Resolver,
                           const std::filesystem::path &BuildRoot) {
  if (Resolver == "unbound") {
    const char *UnboundSrc = std::getenv("UNBOUND_SRC_TREE");
    if (UnboundSrc != nullptr && *UnboundSrc != '\0') {
      return normalizePath(UnboundSrc);
    }
    const char *GenericSrc = std::getenv("SRC_TREE");
    if (GenericSrc != nullptr && *GenericSrc != '\0') {
      return normalizePath(GenericSrc);
    }
    return normalizePath(BuildRoot);
  }
  if (Resolver == "dnsmasq") {
    return resolvePathEnv("DNSMASQ_SRC_TREE", BuildRoot);
  }
  if (Resolver == "smartdns") {
    return resolvePathEnv("SMARTDNS_SRC_TREE", BuildRoot);
  }
  if (Resolver == "maradns") {
    return resolvePathEnv("MARADNS_SRC_TREE", BuildRoot);
  }
  if (Resolver == "knot-resolver") {
    return resolvePathEnv("KNOT_RESOLVER_SRC_TREE", BuildRoot);
  }
  return normalizePath(BuildRoot);
}

FollowDiffConfig collectConfig() {
  FollowDiffConfig Config;
  Config.RootDir = resolveRootDir();
  Config.WorkDir = resolveWorkDir(Config.RootDir);
  const auto Bind9WorkDir = resolveBind9WorkDir(Config.RootDir);
  Config.SourceDir = resolveSourceDir(Bind9WorkDir);
  Config.OutputRoot = resolveOutputRoot(Config.WorkDir);
  Config.StatePath = Config.WorkDir / kFollowDiffStateFileName;
  Config.WindowSummaryPath = Config.WorkDir / kFollowDiffWindowSummaryFileName;
  Config.CampaignCloseSummaryPath =
      Config.WorkDir / kCampaignCloseSummaryFileName;
  Config.SeedProvenancePath = Config.WorkDir / "producer_seed_provenance.json";
  Config.SelfExecutable = resolveSelfExecutable();
  Config.SecondaryResolver = resolveSecondaryResolver();
  Config.Bind9BuildRoot = resolveBind9BuildRoot(Config.RootDir);
  Config.Bind9SourceRoot = resolveBind9SourceRoot(Config.Bind9BuildRoot);
  Config.SecondaryBuildRoot =
      resolveSecondaryBuildRoot(Config.RootDir, Config.SecondaryResolver);
  Config.SecondarySourceRoot =
      resolveSecondarySourceRoot(Config.SecondaryResolver,
                                 Config.SecondaryBuildRoot);
  Config.IntervalSec =
      resolvePositiveDoubleEnv("FOLLOW_DIFF_INTERVAL_SEC", 1.0);
  Config.IdleRounds =
      resolvePositiveIntEnv("FOLLOW_DIFF_WINDOW_IDLE_ROUNDS", 1);
  Config.SeedTimeoutSec = resolveSeedTimeoutSec();
  return Config;
}

std::vector<std::filesystem::path>
listQueueEntries(const std::filesystem::path &SourceDir) {
  std::vector<std::filesystem::path> Output;
  if (!std::filesystem::is_directory(SourceDir)) {
    return Output;
  }
  for (const auto &Entry : std::filesystem::directory_iterator(SourceDir)) {
    if (!Entry.is_regular_file()) {
      continue;
    }
    const auto Name = Entry.path().filename().string();
    if (Name.rfind("id:", 0) == 0) {
      Output.push_back(Entry.path());
    }
  }
  std::sort(Output.begin(), Output.end());
  return Output;
}

std::string buildResolverPair(const std::string &SecondaryResolver) {
  return "bind9_vs_" + SecondaryResolver;
}

AggregationKey buildAggregationKey(const FollowDiffConfig &Config,
                                   double BudgetSec) {
  AggregationKey Output;
  Output.ResolverPair = buildResolverPair(Config.SecondaryResolver);
  Output.ProducerProfile = "poison-stateful";
  Output.InputModel = "DST1 transcript";
  Output.SourceQueueDir = Config.SourceDir.string();
  Output.BudgetSec = static_cast<int>(std::max(1.0, std::floor(BudgetSec)));
  Output.SeedTimeoutSec = Config.SeedTimeoutSec;
  const auto Ablation = resolveAblationConfig();
  Output.VariantName = Ablation.variantName();
  Output.AblationStatus = Ablation.status();
  Output.ContractVersion = kContractVersion;
  return Output;
}

BaselineCompareKey buildBaselineCompareKey(const FollowDiffConfig &Config,
                                           double BudgetSec) {
  BaselineCompareKey Output;
  Output.ResolverPair = buildResolverPair(Config.SecondaryResolver);
  Output.ProducerProfile = "poison-stateful";
  Output.InputModel = "DST1 transcript";
  Output.SourceQueueDir = Config.SourceDir.string();
  Output.BudgetSec = static_cast<int>(std::max(1.0, std::floor(BudgetSec)));
  Output.SeedTimeoutSec = Config.SeedTimeoutSec;
  Output.RepeatCount = 1;
  Output.ContractVersion = kContractVersion;
  return Output;
}

json::Value::Object buildAblationStatusPayload() {
  json::Value::Object Output;
  for (const auto &[Name, Status] : resolveAblationConfig().status()) {
    Output[Name] = Status;
  }
  return Output;
}

json::Value::Object buildAggregationKeyPayload(const FollowDiffConfig &Config,
                                               double BudgetSec) {
  json::Value::Object Output;
  Output["resolver_pair"] = buildResolverPair(Config.SecondaryResolver);
  Output["producer_profile"] = "poison-stateful";
  Output["input_model"] = "DST1 transcript";
  Output["source_queue_dir"] = Config.SourceDir.string();
  Output["budget_sec"] = budgetJsonValue(BudgetSec);
  Output["seed_timeout_sec"] =
      static_cast<std::int64_t>(Config.SeedTimeoutSec);
  Output["variant_name"] = resolveAblationConfig().variantName();
  Output["ablation_status"] = buildAblationStatusPayload();
  Output["contract_version"] = static_cast<std::int64_t>(kContractVersion);
  return Output;
}

json::Value::Object buildBaselineCompareKeyPayload(const FollowDiffConfig &Config,
                                                   double BudgetSec) {
  json::Value::Object Output;
  Output["resolver_pair"] = buildResolverPair(Config.SecondaryResolver);
  Output["producer_profile"] = "poison-stateful";
  Output["input_model"] = "DST1 transcript";
  Output["source_queue_dir"] = Config.SourceDir.string();
  Output["budget_sec"] = budgetJsonValue(BudgetSec);
  Output["seed_timeout_sec"] =
      static_cast<std::int64_t>(Config.SeedTimeoutSec);
  Output["repeat_count"] = static_cast<std::int64_t>(1);
  Output["contract_version"] = static_cast<std::int64_t>(kContractVersion);
  return Output;
}

std::optional<json::Value::Object>
loadSeedProvenancePayload(const FollowDiffConfig &Config) {
  return loadObjectIfPresent(Config.SeedProvenancePath);
}

void enrichSampleMetaContract(const FollowDiffConfig &Config,
                              const std::filesystem::path &QueueFile,
                              const std::filesystem::path &SampleDir,
                              const SampleIdentity &Identity,
                              double BudgetSec) {
  auto Payload = loadObjectIfPresent(SampleDir / "sample.meta.json");
  if (!Payload.has_value()) {
    return;
  }
  (*Payload)["sample_id"] = Identity.SampleId;
  (*Payload)["queue_event_id"] = Identity.QueueEventId;
  (*Payload)["source_queue_file"] = QueueFile.string();
  (*Payload)["sample_sha1"] = Identity.SampleSha1;
  (*Payload)["sample_size"] =
      static_cast<std::int64_t>(Identity.SampleSize);
  (*Payload)["aggregation_key"] =
      buildAggregationKeyPayload(Config, BudgetSec);
  (*Payload)["baseline_compare_key"] =
      buildBaselineCompareKeyPayload(Config, BudgetSec);
  if (const auto SeedProvenance = loadSeedProvenancePayload(Config);
      SeedProvenance.has_value()) {
    (*Payload)["seed_provenance"] = *SeedProvenance;
  }
  writeJsonFile(SampleDir / "sample.meta.json", *Payload);
}

void setObjectDefault(json::Value::Object &Object, const std::string &Name,
                      json::Value Value) {
  if (Object.find(Name) == Object.end()) {
    Object.emplace(Name, std::move(Value));
  }
}

void backfillExistingSampleContracts(const FollowDiffConfig &Config,
                                     double BudgetSec) {
  if (!std::filesystem::is_directory(Config.OutputRoot)) {
    return;
  }

  for (const auto &Entry :
       std::filesystem::directory_iterator(Config.OutputRoot)) {
    if (!Entry.is_directory()) {
      continue;
    }
    const auto SampleDir = Entry.path();
    const auto SamplePath = SampleDir / "sample.bin";
    if (!std::filesystem::is_regular_file(SamplePath)) {
      continue;
    }

    const auto SampleId = SampleDir.filename().string();
    const auto SampleBytes = readBinaryFile(SamplePath);
    const auto SampleSha1 = sha1Hex(SampleBytes);
    auto Meta = loadObjectIfPresent(SampleDir / "sample.meta.json")
                    .value_or(json::Value::Object{});
    const auto ExistingTriage =
        loadObjectIfPresent(SampleDir / "triage.json")
            .value_or(json::Value::Object{});

    std::string Status = "pending";
    if (const auto ExistingStatus =
            coerceOptionalText(findObjectValue(Meta, "status"));
        ExistingStatus.has_value()) {
      Status = *ExistingStatus;
    } else if (const auto TriageStatus =
                   coerceOptionalText(findObjectValue(ExistingTriage, "status"));
               TriageStatus.has_value()) {
      if (TriageStatus->rfind("completed", 0) == 0) {
        Status = "completed";
      } else if (TriageStatus->rfind("failed", 0) == 0) {
        Status = "failed";
      }
    }

    setObjectDefault(Meta, "schema_version",
                     static_cast<std::int64_t>(kSchemaVersion));
    setObjectDefault(Meta, "contract_version",
                     static_cast<std::int64_t>(kContractVersion));
    setObjectDefault(Meta, "generated_at", utcTimestampNow());
    setObjectDefault(Meta, "first_seen_ts", utcTimestampNow());
    Meta["sample_id"] = SampleId;
    if (!coerceOptionalText(findObjectValue(Meta, "queue_event_id"))
             .has_value()) {
      const auto Delimiter = SampleId.find("__");
      Meta["queue_event_id"] =
          Delimiter == std::string::npos
              ? json::Value()
              : json::Value(SampleId.substr(0, Delimiter));
    }
    if (!coerceOptionalText(findObjectValue(Meta, "source_queue_file"))
             .has_value()) {
      Meta["source_queue_file"] = json::Value();
    }
    Meta["sample_sha1"] = SampleSha1;
    Meta["sample_size"] = static_cast<std::int64_t>(SampleBytes.size());
    Meta["is_stateful"] = parseTranscript(SampleBytes).has_value();
    Meta["status"] = Status;
    setObjectDefault(Meta, "source_resolver", "bind9");
    setObjectDefault(Meta, "afl_tags", json::Value::Array{});
    setObjectDefault(Meta, "analysis_state", "unknown");
    setObjectDefault(Meta, "exclude_reason", json::Value());
    setObjectDefault(Meta, "aggregation_key",
                     buildAggregationKeyPayload(Config, BudgetSec));
    setObjectDefault(Meta, "baseline_compare_key",
                     buildBaselineCompareKeyPayload(Config, BudgetSec));
    Meta["output_dir"] = SampleDir.string();
    if (const auto SeedProvenance = loadSeedProvenancePayload(Config);
        SeedProvenance.has_value() &&
        Meta.find("seed_provenance") == Meta.end()) {
      Meta["seed_provenance"] = *SeedProvenance;
    }
    writeJsonFile(SampleDir / "sample.meta.json", Meta);

    if (!std::filesystem::is_regular_file(SampleDir / "oracle.json")) {
      writeJsonFile(SampleDir / "oracle.json", json::Value::Object{});
    }

    if (!std::filesystem::is_regular_file(SampleDir /
                                          "state_fingerprint.json")) {
      json::Value::Object Fingerprint;
      Fingerprint["schema_version"] =
          static_cast<std::int64_t>(kSchemaVersion);
      Fingerprint["generated_at"] = utcTimestampNow();
      Fingerprint["sample_id"] = SampleId;
      for (const auto *Name : {
               "bind9.forwarding_path", "bind9.retry_seen",
               "bind9.msg_cache_seen", "bind9.rrset_cache_seen",
               "bind9.negative_cache_seen", "unbound.forwarding_path",
               "unbound.retry_seen", "unbound.msg_cache_seen",
               "unbound.rrset_cache_seen", "unbound.negative_cache_seen"}) {
        Fingerprint[Name] = json::Value();
      }
      writeJsonFile(SampleDir / "state_fingerprint.json", Fingerprint);
    }

    CacheDiffResult CacheDiff;
    if (!std::filesystem::is_regular_file(SampleDir / "cache_diff.json")) {
      std::map<std::string, std::vector<CacheRecord>> BeforeByResolver = {
          {"bind9", {}}, {Config.SecondaryResolver, {}}};
      const auto AfterByResolver = BeforeByResolver;
      CacheDiff = buildCacheDiff(SampleId, BeforeByResolver, AfterByResolver,
                                 false, Config.SecondaryResolver);
      writeJsonFile(SampleDir / "cache_diff.json", toJson(CacheDiff));
    }

    if (!std::filesystem::is_regular_file(SampleDir / "triage.json")) {
      if (CacheDiff.SampleId.empty()) {
        std::map<std::string, std::vector<CacheRecord>> EmptyByResolver = {
            {"bind9", {}}, {Config.SecondaryResolver, {}}};
        CacheDiff = buildCacheDiff(SampleId, EmptyByResolver, EmptyByResolver,
                                   false, Config.SecondaryResolver);
      }
      StateFingerprint Fingerprint;
      Fingerprint.GeneratedAt = utcTimestampNow();
      Fingerprint.SampleId = SampleId;
      const std::map<std::string, json::Value::Object> EmptyOracle;
      const auto Triage = buildTriageRecord(
          SampleId, EmptyOracle, CacheDiff, Fingerprint, std::nullopt);
      writeJsonFile(SampleDir / "triage.json", toJson(Triage));
    }
  }
}

std::optional<std::string>
readSampleStatus(const std::filesystem::path &SampleDir) {
  const auto Payload = loadObjectIfPresent(SampleDir / "sample.meta.json");
  if (!Payload.has_value()) {
    return std::nullopt;
  }
  return coerceOptionalText(findObjectValue(*Payload, "status"));
}

FollowDiffStateData loadState(const std::filesystem::path &StatePath) {
  FollowDiffStateData State;
  const auto Payload = loadObjectIfPresent(StatePath);
  if (!Payload.has_value()) {
    return State;
  }
  State.RunId = coerceOptionalText(findObjectValue(*Payload, "run_id"));
  State.LastExitReason =
      coerceOptionalText(findObjectValue(*Payload, "last_exit_reason"));
  State.LastAttemptTs =
      coerceOptionalText(findObjectValue(*Payload, "last_attempt_ts"));
  State.LastScanTs =
      coerceOptionalText(findObjectValue(*Payload, "last_scan_ts"));
  State.LastQueueEventId =
      coerceOptionalText(findObjectValue(*Payload, "last_queue_event_id"));
  State.RunningSampleId =
      coerceOptionalText(findObjectValue(*Payload, "running_sample_id"));
  if (const auto *AggregationValue =
          findObjectValue(*Payload, "aggregation_key")) {
    if (const auto *Object =
            std::get_if<json::Value::Object>(&AggregationValue->storage())) {
      State.AggregationKey = *Object;
    }
  }
  if (const auto *BaselineValue =
          findObjectValue(*Payload, "baseline_compare_key")) {
    if (const auto *Object =
            std::get_if<json::Value::Object>(&BaselineValue->storage())) {
      State.BaselineCompareKey = *Object;
    }
  }
  State.RetryCount = static_cast<size_t>(
      coerceInt64(findObjectValue(*Payload, "retry_count"), 0));
  State.CompletedCount = static_cast<size_t>(
      coerceInt64(findObjectValue(*Payload, "completed_count"), 0));
  State.FailedCount = static_cast<size_t>(
      coerceInt64(findObjectValue(*Payload, "failed_count"), 0));
  State.ScannedCount = static_cast<size_t>(
      coerceInt64(findObjectValue(*Payload, "scanned_count"), 0));
  return State;
}

void saveState(const std::filesystem::path &StatePath,
               const FollowDiffStateData &State) {
  json::Value::Object Payload;
  Payload["schema_version"] = static_cast<std::int64_t>(kSchemaVersion);
  Payload["generated_at"] = utcTimestampNow();
  json::setOptional(Payload, "run_id", State.RunId);
  json::setOptional(Payload, "last_scan_ts", State.LastScanTs);
  json::setOptional(Payload, "last_exit_reason", State.LastExitReason);
  json::setOptional(Payload, "last_attempt_ts", State.LastAttemptTs);
  json::setOptional(Payload, "last_queue_event_id", State.LastQueueEventId);
  json::setOptional(Payload, "running_sample_id", State.RunningSampleId);
  if (State.AggregationKey.has_value()) {
    Payload["aggregation_key"] = *State.AggregationKey;
  } else {
    Payload["aggregation_key"] = json::Value();
  }
  if (State.BaselineCompareKey.has_value()) {
    Payload["baseline_compare_key"] = *State.BaselineCompareKey;
  } else {
    Payload["baseline_compare_key"] = json::Value();
  }
  Payload["retry_count"] = static_cast<std::int64_t>(State.RetryCount);
  Payload["completed_count"] = static_cast<std::int64_t>(State.CompletedCount);
  Payload["failed_count"] = static_cast<std::int64_t>(State.FailedCount);
  Payload["scanned_count"] = static_cast<std::int64_t>(State.ScannedCount);
  writeJsonFile(StatePath, json::Value(Payload));
}

std::string newRunId() {
  const auto Now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
  return "follow-diff-window-" + std::to_string(Now);
}

void writeFailureMeta(const FollowDiffConfig &Config,
                      const std::filesystem::path &QueueFile,
                      const std::filesystem::path &SampleDir,
                      const SampleIdentity &Identity,
                      const std::vector<std::uint8_t> &SampleBytes,
                      const std::string &Message, int ExitCode,
                      double BudgetSec) {
  auto Meta = buildSampleMeta(Identity.SampleId);
  Meta.QueueEventId = Identity.QueueEventId;
  Meta.SourceQueueFile = QueueFile.string();
  Meta.SourceResolver = "bind9";
  Meta.SampleSha1 = Identity.SampleSha1;
  Meta.SampleSize = static_cast<int>(Identity.SampleSize);
  Meta.IsStateful = parseTranscript(SampleBytes).has_value();
  Meta.Status = "failed";
  Meta.State = AnalysisState::Unknown;
  Meta.Aggregation = buildAggregationKey(Config, BudgetSec);
  Meta.BaselineCompare = buildBaselineCompareKey(Config, BudgetSec);
  FailureEvidence Failure;
  Failure.Kind = "replay_error";
  Failure.Reason = "subprocess_failed";
  Failure.Message = Message;
  Failure.ExitCode = ExitCode;
  Failure.Stage = "sync-replay";
  Failure.Resolver = Config.SecondaryResolver;
  Failure.ProcessStarted = true;
  Failure.ExecutablePath = Config.SelfExecutable.string();
  Meta.Failure = Failure;
  writeJsonFile(SampleDir / "sample.meta.json", toJson(Meta));
}

enum class SampleProcessStatus {
  Skipped,
  Completed,
  Failed,
};

SampleProcessStatus parseSyncReplayEnvelope(
    const CommandResult &Result, const SampleIdentity &ExpectedIdentity) {
  const auto Parsed = JsonParser(Result.StdoutText).parse();
  const auto *Envelope =
      std::get_if<json::Value::Object>(&Parsed.storage());
  if (Envelope == nullptr) {
    throw std::runtime_error("sync-replay 输出顶层不是 JSON 对象");
  }

  const auto Status = coerceOptionalText(findObjectValue(*Envelope, "status"));
  const auto SampleId =
      coerceOptionalText(findObjectValue(*Envelope, "sample_id"));
  const auto QueueEventId =
      coerceOptionalText(findObjectValue(*Envelope, "queue_event_id"));
  const auto ExitCode = coerceInt64(findObjectValue(*Envelope, "exit_code"), -1);
  if (!Status.has_value() || !SampleId.has_value() ||
      !QueueEventId.has_value() || *SampleId != ExpectedIdentity.SampleId ||
      *QueueEventId != ExpectedIdentity.QueueEventId || ExitCode < 0 ||
      ExitCode != Result.ExitCode) {
    throw std::runtime_error("sync-replay 输出身份或退出码不匹配");
  }

  if (*Status == "completed") {
    if (ExitCode != 0) {
      throw std::runtime_error("sync-replay completed envelope 使用非零退出码");
    }
    return SampleProcessStatus::Completed;
  }
  if (*Status != "failed") {
    throw std::runtime_error("sync-replay 输出 status 非法: " + *Status);
  }

  const auto *FailureValue = findObjectValue(*Envelope, "failure");
  const auto *Failure =
      FailureValue == nullptr
          ? nullptr
          : std::get_if<json::Value::Object>(&FailureValue->storage());
  const auto *ProcessStarted =
      Failure == nullptr ? nullptr
                         : findObjectValue(*Failure, "process_started");
  if (Failure == nullptr ||
      !coerceOptionalText(findObjectValue(*Failure, "kind")).has_value() ||
      !coerceOptionalText(findObjectValue(*Failure, "reason")).has_value() ||
      !coerceOptionalText(findObjectValue(*Failure, "stage")).has_value() ||
      !coerceOptionalText(findObjectValue(*Failure, "resolver")).has_value() ||
      coerceInt64(findObjectValue(*Failure, "exit_code"), -1) != ExitCode ||
      ProcessStarted == nullptr ||
      std::get_if<bool>(&ProcessStarted->storage()) == nullptr) {
    throw std::runtime_error("sync-replay failed envelope 缺少完整 failure");
  }
  return SampleProcessStatus::Failed;
}

SampleProcessStatus runSyncReplay(const FollowDiffConfig &Config,
                                  const std::filesystem::path &QueueFile,
                                  const std::filesystem::path &SampleDir,
                                  const SampleIdentity &Identity,
                                  double BudgetSec) {
  std::string RequestedResolvers = "bind9";
  if (Config.SecondaryResolver != "bind9") {
    RequestedResolvers += "," + Config.SecondaryResolver;
  }
  ProcessRequest Request;
  Request.WorkingDirectory = Config.RootDir;
  Request.Environment = {
      {"DNSLAB_SYNC_REPLAY_BUDGET_SEC", std::to_string(BudgetSec)},
  };
  Request.Arguments = {
      Config.SelfExecutable.string(),
      "sync-replay",
      "--sample",
      QueueFile.string(),
      "--queue-event-id",
      QueueFile.filename().string(),
      "--run-root",
      SampleDir.string(),
      "--bind9-build-root",
      Config.Bind9BuildRoot.string(),
      "--bind9-source-root",
      Config.Bind9SourceRoot.string(),
      "--secondary-resolver",
      Config.SecondaryResolver,
      "--secondary-build-root",
      Config.SecondaryBuildRoot.string(),
      "--secondary-source-root",
      Config.SecondarySourceRoot.string(),
      "--resolvers",
      RequestedResolvers,
      "--unbound-build-root",
      Config.SecondaryBuildRoot.string(),
  };
  const auto Result = runProcess(Request);
  try {
    return parseSyncReplayEnvelope(Result, Identity);
  } catch (const std::exception &EnvelopeError) {
    const auto Message = !Result.StderrText.empty()
                             ? Result.StderrText
                             : (!Result.StdoutText.empty()
                                    ? Result.StdoutText
                                    : ("dnslabctl sync-replay 返回 " +
                                       std::to_string(Result.ExitCode)));
    throw ProcessFailure("sync-replay 协议错误: " +
                             std::string(EnvelopeError.what()) + ": " + Message,
                         Result.ExitCode == 0 ? 1 : Result.ExitCode);
  }
}

SampleProcessStatus processOneSample(const FollowDiffConfig &Config,
                                     const std::filesystem::path &QueueFile,
                                     bool ReplayFailedSample,
                                     bool CountAsRetry, double BudgetSec,
                                     FollowDiffStateData &State) {
  const auto SampleBytes = readBinaryFile(QueueFile);
  const auto Identity = buildSampleIdentity(QueueFile.filename().string(),
                                            SampleBytes);
  const auto SampleDir = Config.OutputRoot / Identity.SampleId;
  const auto ExistingStatus = readSampleStatus(SampleDir);
  if (ExistingStatus.has_value() && *ExistingStatus == "completed") {
    if (State.RunningSampleId ==
        std::optional<std::string>(Identity.SampleId)) {
      State.RunningSampleId.reset();
      saveState(Config.StatePath, State);
    }
    return SampleProcessStatus::Skipped;
  }
  if (ExistingStatus.has_value() && *ExistingStatus == "failed" &&
      !ReplayFailedSample) {
    return SampleProcessStatus::Skipped;
  }

  std::filesystem::create_directories(SampleDir);
  std::filesystem::copy_file(QueueFile, SampleDir / "sample.bin",
                             std::filesystem::copy_options::overwrite_existing);

  State.RunningSampleId = Identity.SampleId;
  State.LastQueueEventId = Identity.QueueEventId;
  State.LastAttemptTs = utcTimestampNow();
  if (CountAsRetry &&
      ExistingStatus == std::optional<std::string>("failed")) {
    ++State.RetryCount;
  }
  saveState(Config.StatePath, State);

  SampleProcessStatus Status = SampleProcessStatus::Failed;
  try {
    Status = runSyncReplay(Config, QueueFile, SampleDir, Identity, BudgetSec);
    enrichSampleMetaContract(Config, QueueFile, SampleDir, Identity, BudgetSec);
  } catch (const ProcessFailure &Error) {
    writeFailureMeta(Config, QueueFile, SampleDir, Identity, SampleBytes,
                     Error.what(), Error.ExitCode, BudgetSec);
    enrichSampleMetaContract(Config, QueueFile, SampleDir, Identity, BudgetSec);
  } catch (const std::exception &Error) {
    writeFailureMeta(Config, QueueFile, SampleDir, Identity, SampleBytes,
                     Error.what(), 1, BudgetSec);
    enrichSampleMetaContract(Config, QueueFile, SampleDir, Identity, BudgetSec);
  }

  if (Status == SampleProcessStatus::Completed) {
    ++State.CompletedCount;
  } else if (Status == SampleProcessStatus::Failed) {
    ++State.FailedCount;
  }
  State.RunningSampleId.reset();
  saveState(Config.StatePath, State);
  return Status;
}

BatchSummary processQueueEntries(const FollowDiffConfig &Config,
                                 bool RetryFailed,
                                 const std::optional<std::string> &QueueTailId,
                                 double BudgetSec,
                                 FollowDiffStateData &State) {
  BatchSummary Summary;
  auto QueueEntries = listQueueEntries(Config.SourceDir);
  if (QueueTailId.has_value()) {
    QueueEntries.erase(
        std::remove_if(QueueEntries.begin(), QueueEntries.end(),
                       [&](const std::filesystem::path &Entry) {
                         return Entry.filename().string() > *QueueTailId;
                       }),
        QueueEntries.end());
  }
  Summary.Scanned = QueueEntries.size();
  if (!QueueEntries.empty()) {
    Summary.LastQueueEventId = QueueEntries.back().filename().string();
  }

  for (const auto &QueueFile : QueueEntries) {
    const auto Status = processOneSample(Config, QueueFile, RetryFailed,
                                         RetryFailed, BudgetSec, State);
    if (Status == SampleProcessStatus::Skipped) {
      ++Summary.Skipped;
      continue;
    }
    ++Summary.Attempted;
    if (Status == SampleProcessStatus::Completed) {
      ++Summary.Completed;
    } else {
      ++Summary.Failed;
    }
  }
  return Summary;
}

json::Value buildWindowSummaryPayload(const FollowDiffConfig &Config,
                                      double BudgetSec,
                                      const std::optional<std::string> &QueueTailId,
                                      const std::string &ExitReason,
                                      int ExitCode,
                                      const BatchSummary &Summary,
                                      const std::string &RunId,
                                      bool RetryFailed,
                                      const RecoveryAudit &Recovery) {
  FollowDiffWindowSummary WindowSummary;
  WindowSummary.BudgetSec = BudgetSec;
  WindowSummary.DeadlineTs = utcTimestampNow();
  WindowSummary.QueueTailId = QueueTailId;
  WindowSummary.ExitReason = ExitReason;
  WindowSummary.ExitCode = ExitCode;
  WindowSummary.CompletedCount = static_cast<int>(Summary.Completed);
  WindowSummary.FailedCount = static_cast<int>(Summary.Failed);
  WindowSummary.LastQueueEventId = Summary.LastQueueEventId;
  WindowSummary.Aggregation = buildAggregationKey(Config, BudgetSec);
  WindowSummary.BaselineCompare = buildBaselineCompareKey(Config, BudgetSec);

  auto Payload = std::get<json::Value::Object>(toJson(WindowSummary).storage());
  Payload["generated_at"] = utcTimestampNow();
  Payload["run_id"] = RunId;
  Payload["retry_failed"] = RetryFailed;
  Payload["scanned_count"] = static_cast<std::int64_t>(Summary.Scanned);
  Payload["attempted_count"] = static_cast<std::int64_t>(Summary.Attempted);
  Payload["skipped_count"] = static_cast<std::int64_t>(Summary.Skipped);
  Payload["aggregation_key"] = buildAggregationKeyPayload(Config, BudgetSec);
  Payload["baseline_compare_key"] =
      buildBaselineCompareKeyPayload(Config, BudgetSec);
  if (Recovery.Status != "none") {
    Payload["recovery_status"] = Recovery.Status;
    json::setOptional(Payload, "recovery_sample_id", Recovery.SampleId);
    json::setOptional(Payload, "recovery_detail", Recovery.Detail);
  }
  if (const auto SeedProvenance = loadSeedProvenancePayload(Config);
      SeedProvenance.has_value()) {
    Payload["seed_provenance"] = *SeedProvenance;
  }
  return json::Value(std::move(Payload));
}

void saveWindowSummary(const FollowDiffConfig &Config, double BudgetSec,
                       const std::optional<std::string> &QueueTailId,
                       const std::string &ExitReason, int ExitCode,
                       const BatchSummary &Summary, const std::string &RunId,
                       bool RetryFailed, const RecoveryAudit &Recovery) {
  writeJsonFile(
      Config.WindowSummaryPath,
      buildWindowSummaryPayload(Config, BudgetSec, QueueTailId, ExitReason,
                                ExitCode, Summary, RunId, RetryFailed,
                                Recovery));
}

RecoveryAudit recoverRunningSample(
    const FollowDiffConfig &Config, FollowDiffStateData &State,
    const std::optional<std::string> &QueueTailId, double BudgetSec) {
  RecoveryAudit Audit;
  if (!State.RunningSampleId.has_value()) {
    return Audit;
  }

  const auto RunningSampleId = *State.RunningSampleId;
  const auto ExistingStatus =
      readSampleStatus(Config.OutputRoot / RunningSampleId);
  if (ExistingStatus == std::optional<std::string>("completed")) {
    std::cerr << "dns-diff: 检测到上次运行中的样本已完成，清理状态后继续: "
              << RunningSampleId << '\n';
    State.RunningSampleId.reset();
    saveState(Config.StatePath, State);
    Audit.Status = "cleared";
    Audit.SampleId = RunningSampleId;
    Audit.Detail = "already_completed";
    return Audit;
  }

  std::optional<std::filesystem::path> QueueFileForSample;
  for (const auto &QueueFile : listQueueEntries(Config.SourceDir)) {
    if (QueueTailId.has_value() &&
        QueueFile.filename().string() > *QueueTailId) {
      continue;
    }
    const auto Bytes = readBinaryFile(QueueFile);
    const auto Identity =
        buildSampleIdentity(QueueFile.filename().string(), Bytes);
    if (Identity.SampleId == RunningSampleId) {
      QueueFileForSample = QueueFile;
      break;
    }
  }
  if (!QueueFileForSample.has_value()) {
    std::cerr << "dns-diff: queue 中未找到待恢复样本，已清理运行中状态: "
              << RunningSampleId << '\n';
    State.RunningSampleId.reset();
    saveState(Config.StatePath, State);
    Audit.Status = "cleared";
    Audit.SampleId = RunningSampleId;
    Audit.Detail = "stale_missing";
    return Audit;
  }

  std::cerr << "dns-diff: 检测到未完成样本，启动时先恢复一次: "
            << RunningSampleId << '\n';
  const auto Status = processOneSample(Config, *QueueFileForSample, true, false,
                                       BudgetSec, State);
  Audit.SampleId = RunningSampleId;
  if (Status == SampleProcessStatus::Failed) {
    std::cerr << "dns-diff: running_sample 恢复失败，保留失败证据并继续流程: "
              << RunningSampleId << '\n';
    Audit.Status = "recovery_failed";
    Audit.Detail = "sample_failed";
    return Audit;
  }

  std::cerr << "dns-diff: running_sample 恢复成功，后续本轮不重复处理: "
            << RunningSampleId << '\n';
  Audit.Status = "recovered";
  Audit.Detail = "sample_processed";
  return Audit;
}

void markPhaseStarted(PhaseRecord &Phase) {
  Phase.Status = "running";
  Phase.StartedAt = utcTimestampNow();
}

void markPhaseFinished(PhaseRecord &Phase, double StartedEpochSec,
                       const std::string &Status,
                       const std::string &ExitReason, int ExitCode,
                       const std::optional<std::string> &Message =
                           std::nullopt) {
  const auto Now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
  Phase.Status = Status;
  Phase.FinishedAt = utcTimestampNow();
  Phase.DurationSec =
      std::max(0.0, (static_cast<double>(Now) / 1000.0) - StartedEpochSec);
  Phase.ExitReason = ExitReason;
  Phase.ExitCode = ExitCode;
  Phase.Message = Message;
}

double nowEpochSec() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
             .count() /
         1000.0;
}

json::Value toJson(const PhaseRecord &Input) {
  json::Value::Object Output;
  Output["status"] = Input.Status;
  Output["started_at"] = Input.StartedAt;
  Output["finished_at"] = Input.FinishedAt;
  Output["duration_sec"] = Input.DurationSec;
  Output["exit_reason"] = Input.ExitReason;
  Output["exit_code"] = Input.ExitCode;
  json::setOptional(Output, "message", Input.Message);
  return json::Value(Output);
}

json::Value buildPhasesPayload(const std::map<std::string, PhaseRecord> &Phases) {
  json::Value::Object Output;
  for (const auto &[Name, Phase] : Phases) {
    Output[Name] = toJson(Phase);
  }
  return json::Value(Output);
}

std::optional<std::string>
readWindowRunId(const std::filesystem::path &WindowSummaryPath) {
  const auto Payload = loadObjectIfPresent(WindowSummaryPath);
  if (!Payload.has_value()) {
    return std::nullopt;
  }
  return coerceOptionalText(findObjectValue(*Payload, "run_id"));
}

void rewriteWindowSummaryExitCode(const std::filesystem::path &WindowSummaryPath,
                                  int ExitCode) {
  const auto Payload = loadObjectIfPresent(WindowSummaryPath);
  if (!Payload.has_value()) {
    return;
  }
  auto Object = *Payload;
  Object["exit_code"] = static_cast<std::int64_t>(ExitCode);
  writeJsonFile(WindowSummaryPath, json::Value(Object));
}

} // namespace

FollowDiffRunArtifacts runFollowDiffOnce() {
  const auto Config = collectConfig();
  std::filesystem::create_directories(Config.WorkDir);
  std::filesystem::create_directories(Config.OutputRoot);
  const auto DeadlineTs = utcTimestampNow();

  auto State = loadState(Config.StatePath);
  State.LastScanTs = utcTimestampNow();
  recoverRunningSample(Config, State, std::nullopt, 1.0);

  const auto Summary =
      processQueueEntries(Config, false, std::nullopt, 1.0, State);
  backfillExistingSampleContracts(Config, 1.0);
  State.LastQueueEventId = Summary.LastQueueEventId;
  State.ScannedCount = Summary.Scanned;
  saveState(Config.StatePath, State);

  FollowDiffRunArtifacts Output;
  Output.WorkDir = Config.WorkDir;
  Output.FollowRoot = Config.OutputRoot;
  Output.StatePath = Config.StatePath;
  Output.WindowSummaryPath = Config.WindowSummaryPath;
  Output.RunId = "follow-diff-once";
  Output.ExitReason = "completed";
  Output.ExitCode = 0;
  Output.CompletedCount = Summary.Completed;
  Output.FailedCount = Summary.Failed;
  Output.ScannedCount = Summary.Scanned;
  Output.LastQueueEventId = Summary.LastQueueEventId;
  return Output;
}

FollowDiffRunArtifacts
runFollowDiffWindow(double BudgetSec, bool RetryFailed,
                    std::optional<std::string> QueueTailId) {
  if (BudgetSec <= 0) {
    throw std::runtime_error("--budget-sec 必须大于 0");
  }

  const auto Config = collectConfig();
  std::filesystem::create_directories(Config.WorkDir);
  std::filesystem::create_directories(Config.OutputRoot);
  backfillExistingSampleContracts(Config, BudgetSec);

  if (!QueueTailId.has_value()) {
    const auto QueueEntries = listQueueEntries(Config.SourceDir);
    if (!QueueEntries.empty()) {
      QueueTailId = QueueEntries.back().filename().string();
    }
  }

  const auto Deadline = std::chrono::steady_clock::now() +
                        std::chrono::duration<double>(BudgetSec);
  const auto RunId = newRunId();
  auto State = loadState(Config.StatePath);
  State.RunId = RunId;
  State.RetryCount = 0;
  State.LastExitReason.reset();
  State.LastAttemptTs = utcTimestampNow();
  State.LastScanTs = utcTimestampNow();
  State.AggregationKey = buildAggregationKeyPayload(Config, BudgetSec);
  State.BaselineCompareKey = buildBaselineCompareKeyPayload(Config, BudgetSec);
  const auto Recovery =
      recoverRunningSample(Config, State, QueueTailId, BudgetSec);
  saveState(Config.StatePath, State);

  int IdleRounds = 0;
  BatchSummary LastSummary;
  while (true) {
    if (std::chrono::steady_clock::now() >= Deadline) {
      State.LastExitReason = "deadline_exceeded";
      saveState(Config.StatePath, State);
      auto SummaryForOutput = LastSummary;
      SummaryForOutput.Completed = State.CompletedCount;
      SummaryForOutput.Failed = State.FailedCount;
      SummaryForOutput.Scanned = State.ScannedCount;
      saveWindowSummary(Config, BudgetSec, QueueTailId, "deadline_exceeded",
                        kExitDeadlineExceeded, SummaryForOutput, RunId,
                        RetryFailed, Recovery);

      FollowDiffRunArtifacts Output;
      Output.WorkDir = Config.WorkDir;
      Output.FollowRoot = Config.OutputRoot;
      Output.StatePath = Config.StatePath;
      Output.WindowSummaryPath = Config.WindowSummaryPath;
      Output.RunId = RunId;
      Output.ExitReason = "deadline_exceeded";
      Output.ExitCode = kExitDeadlineExceeded;
      Output.CompletedCount = State.CompletedCount;
      Output.FailedCount = State.FailedCount;
      Output.ScannedCount = State.ScannedCount;
      Output.LastQueueEventId = State.LastQueueEventId;
      return Output;
    }

    const auto Summary =
        processQueueEntries(Config, RetryFailed, QueueTailId, BudgetSec, State);
    backfillExistingSampleContracts(Config, BudgetSec);
    LastSummary = Summary;
    State.LastAttemptTs = utcTimestampNow();
    State.LastScanTs = utcTimestampNow();
    State.LastQueueEventId = Summary.LastQueueEventId;
    State.RunningSampleId.reset();
    State.ScannedCount = Summary.Scanned;
    saveState(Config.StatePath, State);

    if (Summary.Attempted == 0) {
      ++IdleRounds;
    } else {
      IdleRounds = 0;
    }

    const bool ReachedFrozenTail =
        !QueueTailId.has_value() || Summary.LastQueueEventId == QueueTailId;
    if (ReachedFrozenTail && IdleRounds >= Config.IdleRounds) {
      State.LastExitReason = "quiescent";
      saveState(Config.StatePath, State);
      auto SummaryForOutput = Summary;
      SummaryForOutput.Completed = State.CompletedCount;
      SummaryForOutput.Failed = State.FailedCount;
      SummaryForOutput.Scanned = State.ScannedCount;
      saveWindowSummary(Config, BudgetSec, QueueTailId, "quiescent", 0,
                        SummaryForOutput, RunId, RetryFailed, Recovery);

      FollowDiffRunArtifacts Output;
      Output.WorkDir = Config.WorkDir;
      Output.FollowRoot = Config.OutputRoot;
      Output.StatePath = Config.StatePath;
      Output.WindowSummaryPath = Config.WindowSummaryPath;
      Output.RunId = RunId;
      Output.ExitReason = "quiescent";
      Output.ExitCode = 0;
      Output.CompletedCount = State.CompletedCount;
      Output.FailedCount = State.FailedCount;
      Output.ScannedCount = State.ScannedCount;
      Output.LastQueueEventId = State.LastQueueEventId;
      return Output;
    }

    const auto Remaining = Deadline - std::chrono::steady_clock::now();
    if (Remaining <= std::chrono::steady_clock::duration::zero()) {
      continue;
    }
    const double SleepSec = std::min(
        Config.IntervalSec,
        std::chrono::duration_cast<std::chrono::duration<double>>(Remaining)
            .count());
    std::this_thread::sleep_for(std::chrono::duration<double>(SleepSec));
  }
}

CampaignCloseArtifacts runCampaignClose(double BudgetSec) {
  if (BudgetSec <= 0) {
    throw std::runtime_error("--budget-sec 必须大于 0");
  }

  const auto Config = collectConfig();
  std::filesystem::create_directories(Config.WorkDir);
  std::filesystem::create_directories(Config.OutputRoot);
  const auto DeadlineTs = utcTimestampNow();

  std::optional<std::string> QueueTailId;
  const auto QueueEntries = listQueueEntries(Config.SourceDir);
  if (!QueueEntries.empty()) {
    QueueTailId = QueueEntries.back().filename().string();
  }

  std::map<std::string, PhaseRecord> Phases = {
      {"follow-diff-window", PhaseRecord{}},
      {"triage-report", PhaseRecord{}},
      {"campaign-report", PhaseRecord{}},
  };

  TriageReportArtifacts ReportArtifacts;
  ReportArtifacts.Root = Config.OutputRoot;
  CampaignReportArtifacts CampaignArtifacts;
  CampaignArtifacts.Root = Config.OutputRoot;
  std::string Status = "failed";
  std::string ExitReason = "phase_failed";
  int ExitCode = 1;
  std::optional<std::string> FailedPhase;

  {
    auto &Phase = Phases["follow-diff-window"];
    const auto StartedAt = nowEpochSec();
    markPhaseStarted(Phase);
    const auto RemainingBudget = BudgetSec;
    FollowDiffRunArtifacts WindowArtifacts;
    try {
      WindowArtifacts =
          runFollowDiffWindow(RemainingBudget, false, QueueTailId);
    } catch (const std::exception &Error) {
      markPhaseFinished(Phase, StartedAt, "failed", "phase_failed", 1,
                        Error.what());
      FailedPhase = "follow-diff-window";
      ExitReason = "phase_failed";
      ExitCode = 1;
      goto write_summary;
    }
    if (WindowArtifacts.ExitCode != 0) {
      const auto PhaseExitReason =
          WindowArtifacts.ExitCode == kExitDeadlineExceeded
              ? "deadline_exceeded"
              : "phase_failed";
      const int NormalizedExitCode =
          WindowArtifacts.ExitCode == kExitDeadlineExceeded ? 1
                                                           : WindowArtifacts.ExitCode;
      markPhaseFinished(Phase, StartedAt, "failed", PhaseExitReason,
                        NormalizedExitCode);
      FailedPhase = "follow-diff-window";
      ExitReason = PhaseExitReason;
      ExitCode = NormalizedExitCode;
      if (WindowArtifacts.ExitCode == kExitDeadlineExceeded) {
        rewriteWindowSummaryExitCode(Config.WindowSummaryPath, ExitCode);
      }
      goto write_summary;
    }
    markPhaseFinished(Phase, StartedAt, "success", "quiescent", 0);
  }

  {
    auto &Phase = Phases["triage-report"];
    const auto StartedAt = nowEpochSec();
    markPhaseStarted(Phase);
    std::optional<std::filesystem::path> HighValueManifestPath;
    if (const char *EnvManifest = std::getenv("SYMCC_HIGH_VALUE_MANIFEST")) {
      if (*EnvManifest != '\0') {
        HighValueManifestPath = std::filesystem::path(EnvManifest);
      }
    }
    try {
      ReportArtifacts = generateTriageReportArtifacts(Config.OutputRoot,
                                                     HighValueManifestPath);
    } catch (const std::exception &Error) {
      markPhaseFinished(Phase, StartedAt, "failed", "phase_failed", 1,
                        Error.what());
      FailedPhase = "triage-report";
      ExitReason = "phase_failed";
      ExitCode = 1;
      goto write_summary;
    }
    markPhaseFinished(Phase, StartedAt, "success", "generated", 0);
  }

  {
    auto &Phase = Phases["campaign-report"];
    const auto StartedAt = nowEpochSec();
    markPhaseStarted(Phase);
    try {
      CampaignArtifacts = generateCampaignReportArtifacts(
          Config.OutputRoot, Config.WorkDir / "campaign_reports", Config.WorkDir);
    } catch (const std::exception &Error) {
      markPhaseFinished(Phase, StartedAt, "failed", "phase_failed", 1,
                        Error.what());
      FailedPhase = "campaign-report";
      ExitReason = "phase_failed";
      ExitCode = 1;
      goto write_summary;
    }
    markPhaseFinished(Phase, StartedAt, "success", "summary_written", 0);
    Status = "success";
    ExitReason = "success";
    ExitCode = 0;
  }

write_summary:
  {
    const auto CampaignSummaryPayload =
        loadObjectIfPresent(CampaignArtifacts.SummaryPath);
    const auto WindowSummaryPayload =
        loadObjectIfPresent(Config.WindowSummaryPath);
    const auto StatePayload = loadObjectIfPresent(Config.StatePath);
    json::Value::Object Summary;
    Summary["budget_sec"] = BudgetSec;
    Summary["deadline_ts"] = DeadlineTs;
    Summary["generated_at"] = utcTimestampNow();
    json::setOptional(Summary, "queue_tail_id", QueueTailId);
    Summary["status"] = Status;
    Summary["exit_reason"] = ExitReason;
    Summary["exit_code"] = ExitCode;
    if (FailedPhase.has_value()) {
      Summary["failed_phase"] = *FailedPhase;
    } else {
      Summary["failed_phase"] = json::Value();
    }
    Summary["run_id"] = readWindowRunId(Config.WindowSummaryPath).has_value()
                            ? json::Value(*readWindowRunId(Config.WindowSummaryPath))
                            : json::Value();
    Summary["phases"] = buildPhasesPayload(Phases);
    if (CampaignSummaryPayload.has_value()) {
      if (const auto *Value =
              findObjectValue(*CampaignSummaryPayload, "metric_denominators")) {
        Summary["metric_denominators"] = *Value;
      }
      if (const auto *Value =
              findObjectValue(*CampaignSummaryPayload, "comparability")) {
        Summary["comparability"] = *Value;
      }
      if (const auto *Value =
              findObjectValue(*CampaignSummaryPayload, "seed_provenance")) {
        Summary["seed_provenance"] = *Value;
      }
      if (const auto *Value = findObjectValue(*CampaignSummaryPayload, "run_id")) {
        Summary["run_id"] = *Value;
      }
    } else {
      const auto FallbackSummary =
          dnslab::buildCampaignSummaryPayload(Config.OutputRoot, Config.WorkDir);
      Summary["metric_denominators"] =
          *findObjectValue(FallbackSummary, "metric_denominators");
      Summary["comparability"] =
          *findObjectValue(FallbackSummary, "comparability");
      Summary["seed_provenance"] =
          *findObjectValue(FallbackSummary, "seed_provenance");
      Summary["run_id"] = *findObjectValue(FallbackSummary, "run_id");
      if (WindowSummaryPayload.has_value()) {
        if (const auto *Value =
                findObjectValue(*WindowSummaryPayload, "seed_provenance")) {
          Summary["seed_provenance"] = *Value;
        }
      }
    }

    json::Value::Object PhaseContext;
    PhaseContext["follow_diff_state"] =
        StatePayload.has_value() ? json::Value(*StatePayload) : json::Value::Object{};
    PhaseContext["follow_diff_window_summary"] = WindowSummaryPayload.has_value()
                                                     ? json::Value(*WindowSummaryPayload)
                                                     : json::Value::Object{};
    PhaseContext["triage_report"] = toJson(ReportArtifacts);
    PhaseContext["campaign_report"] = toJson(CampaignArtifacts);
    Summary["phase_context"] = PhaseContext;
    writeJsonFile(Config.CampaignCloseSummaryPath, json::Value(Summary));
  }

  CampaignCloseArtifacts Output;
  Output.WorkDir = Config.WorkDir;
  Output.FollowRoot = Config.OutputRoot;
  Output.SummaryPath = Config.CampaignCloseSummaryPath;
  Output.WindowSummaryPath = Config.WindowSummaryPath;
  Output.ExitReason = ExitReason;
  Output.ExitCode = ExitCode;
  Output.RunId = readWindowRunId(Config.WindowSummaryPath);
  Output.SampleCount = CampaignArtifacts.SampleCount;
  Output.SemanticFrontierEntryCount = ReportArtifacts.SemanticFrontierEntryCount;
  return Output;
}

json::Value toJson(const FollowDiffRunArtifacts &Input) {
  json::Value::Object Output;
  Output["work_dir"] = Input.WorkDir.string();
  Output["follow_root"] = Input.FollowRoot.string();
  Output["state_path"] = Input.StatePath.string();
  Output["window_summary_path"] = Input.WindowSummaryPath.string();
  Output["run_id"] = Input.RunId;
  Output["exit_reason"] = Input.ExitReason;
  Output["exit_code"] = Input.ExitCode;
  Output["completed_count"] = static_cast<std::int64_t>(Input.CompletedCount);
  Output["failed_count"] = static_cast<std::int64_t>(Input.FailedCount);
  Output["scanned_count"] = static_cast<std::int64_t>(Input.ScannedCount);
  json::setOptional(Output, "last_queue_event_id", Input.LastQueueEventId);
  return json::Value(Output);
}

json::Value toJson(const CampaignCloseArtifacts &Input) {
  json::Value::Object Output;
  Output["work_dir"] = Input.WorkDir.string();
  Output["follow_root"] = Input.FollowRoot.string();
  Output["summary_path"] = Input.SummaryPath.string();
  Output["window_summary_path"] = Input.WindowSummaryPath.string();
  Output["exit_reason"] = Input.ExitReason;
  Output["exit_code"] = Input.ExitCode;
  json::setOptional(Output, "run_id", Input.RunId);
  Output["sample_count"] = static_cast<std::int64_t>(Input.SampleCount);
  Output["semantic_frontier_entry_count"] =
      static_cast<std::int64_t>(Input.SemanticFrontierEntryCount);
  return json::Value(Output);
}

} // namespace dnslab
