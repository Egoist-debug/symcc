#include "dnslab_core/concrete_adapters.hpp"
#include "dnslab_core/cache_analysis.hpp"
#include "dnslab_core/evidence_contract.hpp"
#include "dnslab_core/experiment_config.hpp"
#include "dnslab_core/follow_diff.hpp"
#include "dnslab_core/oracle.hpp"
#include "dnslab_core/replay_failure.hpp"
#include "dnslab_core/reporting.hpp"
#include "dnslab_core/resolver_lock.hpp"
#include "dnslab_core/transcript.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <vector>

namespace {

std::vector<uint8_t> readBinaryFile(const std::filesystem::path &InputPath) {
  std::ifstream Input(InputPath, std::ios::binary);
  if (!Input) {
    throw std::runtime_error("无法读取文件: " + InputPath.string());
  }
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(Input)),
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

void writeJsonFile(const std::filesystem::path &OutputPath,
                   const dnslab::json::Value &Payload) {
  std::filesystem::create_directories(OutputPath.parent_path());
  std::ofstream Output(OutputPath);
  if (!Output) {
    throw std::runtime_error("无法写入文件: " + OutputPath.string());
  }
  Output << Payload.dump(2) << '\n';
}

std::filesystem::path normalizePath(const std::filesystem::path &InputPath) {
  std::error_code Error;
  const auto Absolute = std::filesystem::absolute(InputPath, Error);
  if (Error) {
    return InputPath.lexically_normal();
  }
  return Absolute.lexically_normal();
}

std::optional<std::filesystem::path>
resolveSelfExecutableFromArgv0(const char *Argv0) {
  if (Argv0 == nullptr || *Argv0 == '\0') {
    return std::nullopt;
  }
  const std::filesystem::path Candidate(Argv0);
  if (Candidate.is_absolute()) {
    return normalizePath(Candidate);
  }
  if (Candidate.has_parent_path()) {
    return normalizePath(std::filesystem::current_path() / Candidate);
  }
  if (const char *PathEnv = std::getenv("PATH")) {
    std::stringstream Stream(PathEnv);
    std::string Entry;
    while (std::getline(Stream, Entry, ':')) {
      if (Entry.empty()) {
        continue;
      }
      const auto Resolved = std::filesystem::path(Entry) / Candidate;
      if (std::filesystem::exists(Resolved)) {
        return normalizePath(Resolved);
      }
    }
  }
  return std::nullopt;
}

std::filesystem::path resolveSelfExecutablePath(const char *Argv0 = nullptr) {
  if (const char *SelfExecutable = std::getenv("DNSLAB_SELF_EXECUTABLE");
      SelfExecutable != nullptr && *SelfExecutable != '\0') {
    return normalizePath(SelfExecutable);
  }
  std::error_code Error;
  const auto SelfPath = std::filesystem::read_symlink("/proc/self/exe", Error);
  if (!Error && !SelfPath.empty()) {
    return normalizePath(SelfPath);
  }
  if (const auto Argv0Path = resolveSelfExecutableFromArgv0(Argv0);
      Argv0Path.has_value()) {
    return *Argv0Path;
  }
  return normalizePath(std::filesystem::current_path() /
                       "build/linux/x86_64/release/dnslabctl");
}

std::string requireOption(const std::vector<std::string> &Args,
                          const std::string &Name) {
  for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
    if (Args[Index] == Name) {
      return Args[Index + 1];
    }
  }
  throw std::runtime_error("缺少参数: " + Name);
}

std::optional<std::string> optionalOption(const std::vector<std::string> &Args,
                                          const std::string &Name) {
  for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
    if (Args[Index] == Name) {
      return Args[Index + 1];
    }
  }
  return std::nullopt;
}

std::filesystem::path requireCommandPath(const std::vector<std::string> &Args,
                                         const std::string &Name) {
  return normalizePath(requireOption(Args, Name));
}

void printJsonValue(const dnslab::json::Value &Value) {
  std::cout << Value.dump(2) << '\n';
}

std::vector<std::string> splitCsv(const std::string &Input) {
  std::vector<std::string> Output;
  std::stringstream Stream(Input);
  std::string Token;
  while (std::getline(Stream, Token, ',')) {
    Token.erase(Token.begin(),
                std::find_if(Token.begin(), Token.end(),
                             [](unsigned char Ch) { return !std::isspace(Ch); }));
    Token.erase(
        std::find_if(Token.rbegin(), Token.rend(),
                     [](unsigned char Ch) { return !std::isspace(Ch); })
            .base(),
        Token.end());
    if (!Token.empty()) {
      Output.push_back(Token);
    }
  }
  return Output;
}

std::optional<dnslab::ResolverLockFile>
loadDefaultResolverLockIfPresent(const std::filesystem::path &WorkspaceRoot) {
  const auto LockPath = dnslab::defaultResolverLockFilePath(WorkspaceRoot);
  if (!std::filesystem::is_regular_file(LockPath)) {
    return std::nullopt;
  }
  try {
    return dnslab::loadResolverLockFileJson(LockPath);
  } catch (const std::exception &) {
    return std::nullopt;
  }
}

std::filesystem::path resolveDefaultSourceRootForWorkspace(
    const std::filesystem::path &WorkspaceRoot,
    const std::optional<dnslab::ResolverLockFile> &DefaultResolverLock,
    const std::string &ResolverName,
    const std::filesystem::path &FallbackRoot) {
  if (DefaultResolverLock.has_value()) {
    if (const auto Tag =
            dnslab::resolveLockedTag(*DefaultResolverLock, ResolverName)) {
      const auto LockedSourceRoot =
          dnslab::defaultSubjectRoot(WorkspaceRoot, ResolverName, *Tag);
      if (std::filesystem::exists(LockedSourceRoot)) {
        return LockedSourceRoot;
      }
    }
  }
  return FallbackRoot;
}

struct ResolverPathSpec {
  const char *Name;
  const char *BuildEnvName;
  const char *PrimarySourceEnvName;
  const char *SecondarySourceEnvName;
  const char *DefaultBuildRelative;
  const char *RuntimeBuildRootEnvName;
};

const ResolverPathSpec *findResolverPathSpec(const std::string &ResolverName) {
  static const ResolverPathSpec Specs[] = {
      {"bind9", "BIND9_AFL_TREE", "BIND9_SRC_TREE", nullptr,
       "bind-9.18.46-afl", "DNSLAB_BIND9_BUILD_ROOT"},
      {"unbound", "AFL_TREE", "UNBOUND_SRC_TREE", "SRC_TREE",
       "unbound-1.24.2-afl", "DNSLAB_UNBOUND_BUILD_ROOT"},
      {"dnsmasq", "DNSMASQ_BUILD_TREE", "DNSMASQ_SRC_TREE", nullptr,
       "experiments/subjects/dnsmasq/v2.92-build",
       "DNSLAB_DNSMASQ_BUILD_ROOT"},
      {"smartdns", "SMARTDNS_BUILD_TREE", "SMARTDNS_SRC_TREE", nullptr,
       "experiments/subjects/smartdns/Release47.1-build",
       "DNSLAB_SMARTDNS_BUILD_ROOT"},
      {"maradns", "MARADNS_BUILD_TREE", "MARADNS_SRC_TREE", nullptr,
       "experiments/subjects/maradns/deadwood-3.3.02-build",
       "DNSLAB_MARADNS_BUILD_ROOT"},
      {"knot-resolver", "KNOT_RESOLVER_BUILD_TREE", "KNOT_RESOLVER_SRC_TREE",
       nullptr, "experiments/subjects/knot-resolver/v6.2.0-build",
       "DNSLAB_KNOT_RESOLVER_BUILD_ROOT"},
  };
  for (const auto &Spec : Specs) {
    if (ResolverName == Spec.Name) {
      return &Spec;
    }
  }
  return nullptr;
}

std::filesystem::path defaultBuildRootForResolver(
    const std::filesystem::path &WorkspaceRoot, const std::string &ResolverName) {
  if (const auto *Spec = findResolverPathSpec(ResolverName)) {
    if (const char *Env = std::getenv(Spec->BuildEnvName);
        Env != nullptr && *Env != '\0') {
      return normalizePath(Env);
    }
    return WorkspaceRoot / Spec->DefaultBuildRelative;
  }
  throw std::runtime_error("不支持的 resolver: " + ResolverName);
}

std::filesystem::path defaultSourceRootForResolver(
    const std::filesystem::path &BuildRoot, const std::string &ResolverName) {
  if (const auto *Spec = findResolverPathSpec(ResolverName)) {
    for (const char *EnvName :
         {Spec->PrimarySourceEnvName, Spec->SecondarySourceEnvName}) {
      if (EnvName == nullptr || *EnvName == '\0') {
        continue;
      }
      if (const char *Env = std::getenv(EnvName);
          Env != nullptr && *Env != '\0') {
        return normalizePath(Env);
      }
    }
  }
  return BuildRoot;
}

std::optional<std::string>
buildRootEnvNameForResolver(const std::string &ResolverName) {
  if (const auto *Spec = findResolverPathSpec(ResolverName)) {
    return std::string(Spec->BuildEnvName);
  }
  return std::nullopt;
}

std::optional<std::string>
sourceRootEnvNameForResolver(const std::string &ResolverName) {
  if (const auto *Spec = findResolverPathSpec(ResolverName);
      Spec != nullptr && Spec->PrimarySourceEnvName != nullptr &&
      *Spec->PrimarySourceEnvName != '\0') {
    return std::string(Spec->PrimarySourceEnvName);
  }
  return std::nullopt;
}

void setResolverBuildEnvForResolver(const std::string &ResolverName,
                                    const std::filesystem::path &BuildRoot) {
  if (const auto *Spec = findResolverPathSpec(ResolverName);
      Spec != nullptr && Spec->RuntimeBuildRootEnvName != nullptr &&
      *Spec->RuntimeBuildRootEnvName != '\0') {
    ::setenv(Spec->RuntimeBuildRootEnvName, BuildRoot.c_str(), 1);
  }
}

std::vector<std::string> orderedResolversForReplay(
    const std::vector<std::string> &AvailableResolvers,
    const std::string &CompatibilitySecondaryResolver,
    const std::optional<std::string> &RequestedResolversCsv) {
  std::vector<std::string> Requested =
      RequestedResolversCsv.has_value() ? splitCsv(*RequestedResolversCsv)
                                        : AvailableResolvers;
  if (std::find(Requested.begin(), Requested.end(), "bind9") == Requested.end()) {
    Requested.push_back("bind9");
  }
  if (std::find(Requested.begin(), Requested.end(), CompatibilitySecondaryResolver) ==
      Requested.end()) {
    Requested.push_back(CompatibilitySecondaryResolver);
  }
  std::sort(Requested.begin(), Requested.end());
  Requested.erase(std::unique(Requested.begin(), Requested.end()),
                  Requested.end());
  auto MoveToFront = [&](const std::string &Resolver) {
    const auto Found = std::find(Requested.begin(), Requested.end(), Resolver);
    if (Found == Requested.end()) {
      return;
    }
    std::rotate(Requested.begin(), Found, Found + 1);
  };
  MoveToFront(CompatibilitySecondaryResolver);
  MoveToFront("bind9");
  return Requested;
}

std::filesystem::path resolveSourceRootOverride(
    const std::vector<std::string> &Args, const std::string &OptionName,
    const std::filesystem::path &DefaultValue) {
  for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
    if (Args[Index] == OptionName) {
      return normalizePath(Args[Index + 1]);
    }
  }
  return DefaultValue;
}

void applySyncReplaySourceRootOverrides(
    const std::vector<std::string> &Args, std::filesystem::path &Bind9SourceRoot,
    std::filesystem::path &SecondarySourceRoot) {
  Bind9SourceRoot =
      resolveSourceRootOverride(Args, "--bind9-source-root", Bind9SourceRoot);
  SecondarySourceRoot =
      resolveSourceRootOverride(Args, "--unbound-source-root", SecondarySourceRoot);
  SecondarySourceRoot = resolveSourceRootOverride(Args, "--secondary-source-root",
                                                  SecondarySourceRoot);
}

std::string buildReplayCommandEnvPrefix(
    const std::vector<std::string> &ExecutedResolvers,
    const std::string &SecondaryResolver,
    const std::map<std::string, std::filesystem::path> &ResolverBuildRoots,
    const std::map<std::string, std::filesystem::path> &ResolverSourceRoots) {
  std::string Output;
  for (const auto &ResolverName : ExecutedResolvers) {
    if (ResolverName == "bind9" || ResolverName == SecondaryResolver ||
        ResolverName == "unbound") {
      continue;
    }
    if (const auto EnvName = buildRootEnvNameForResolver(ResolverName);
        EnvName.has_value()) {
      Output += *EnvName + "=" + ResolverBuildRoots.at(ResolverName).string() +
                " ";
    }
    if (const auto EnvName = sourceRootEnvNameForResolver(ResolverName);
        EnvName.has_value()) {
      Output += *EnvName + "=" + ResolverSourceRoots.at(ResolverName).string() +
                " ";
    }
  }
  return Output;
}

std::string buildSyncReplayReplayCommand(
    const std::string &SelfExecutableCommand,
    const std::string &SourceQueueFile,
    const std::filesystem::path &ArtifactDir,
    const std::filesystem::path &Bind9BuildRoot,
    const std::filesystem::path &SecondaryBuildRoot,
    const std::string &SecondaryResolver,
    const std::map<std::string, std::filesystem::path> &ResolverBuildRoots,
    const std::map<std::string, std::filesystem::path> &ResolverSourceRoots,
    const std::vector<std::string> &ExecutedResolvers) {
  auto Output = buildReplayCommandEnvPrefix(ExecutedResolvers, SecondaryResolver,
                                            ResolverBuildRoots,
                                            ResolverSourceRoots);
  Output += SelfExecutableCommand + " sync-replay --sample " + SourceQueueFile +
            " --run-root " + ArtifactDir.string() + " --bind9-build-root " +
            Bind9BuildRoot.string() + " --bind9-source-root " +
            ResolverSourceRoots.at("bind9").string();
  if (ResolverBuildRoots.count("unbound")) {
    Output += " --unbound-build-root " +
              ResolverBuildRoots.at("unbound").string();
  } else {
    Output += " --unbound-build-root " + SecondaryBuildRoot.string();
  }
  if (SecondaryResolver != "unbound") {
    Output += " --secondary-resolver " + SecondaryResolver +
              " --secondary-build-root " +
              ResolverBuildRoots.at(SecondaryResolver).string() +
              " --secondary-source-root " +
              ResolverSourceRoots.at(SecondaryResolver).string();
  }
  Output += " --resolvers ";
  for (size_t Index = 0; Index < ExecutedResolvers.size(); ++Index) {
    if (Index != 0) {
      Output.push_back(',');
    }
    Output += ExecutedResolvers[Index];
  }
  return Output;
}

struct ResolverRunResult {
  dnslab::CommandResult DumpResult;
  dnslab::CommandResult RunResult;
  dnslab::OracleArtifact Oracle;
  std::filesystem::path BeforeCache;
  std::filesystem::path AfterCache;
  std::filesystem::path StderrPath;
  std::vector<std::filesystem::path> Logs;
  std::optional<dnslab::FailureEvidence> Failure;
};

struct SyncReplayResult {
  dnslab::SampleIdentity Identity;
  dnslab::SampleMeta Meta;
  dnslab::StateFingerprint Fingerprint;
  dnslab::CacheDiffResult CacheDiff;
  dnslab::TriageRecord Triage;
  dnslab::json::Value::Object OraclePayload;
  std::map<std::string, dnslab::json::Value::Object> OracleByResolver;
  std::map<std::string, ResolverRunResult> ResolverRuns;
  std::map<std::string, std::string> SkippedResolvers;
  std::map<std::string, std::filesystem::path> ResolverBuildRoots;
  std::map<std::string, std::filesystem::path> ResolverSourceRoots;
  std::vector<std::string> ExecutedResolvers;
  ResolverRunResult Bind9;
  ResolverRunResult Secondary;
  std::string SecondaryResolver = "unbound";
  std::filesystem::path ArtifactDir;
  std::optional<dnslab::FailureEvidence> Failure;
  int ExitCode = 0;
  bool Failed = false;
};

struct ResolverExecution {
  ResolverRunResult Run;
  std::vector<dnslab::CacheRecord> BeforeRows;
  std::vector<dnslab::CacheRecord> AfterRows;
  dnslab::json::Value::Object OracleFields;
};

struct SyncReplayResolverRoots {
  std::vector<std::string> RequestedResolvers;
  std::map<std::string, std::filesystem::path> BuildRoots;
  std::map<std::string, std::filesystem::path> SourceRoots;
};

struct SyncReplayCommandContext {
  std::filesystem::path Bind9BuildRoot;
  std::string SecondaryResolverName = "unbound";
  std::filesystem::path SecondaryBuildRoot;
  std::filesystem::path Bind9SourceRoot;
  std::filesystem::path SecondarySourceRoot;
  std::optional<std::string> RequestedResolversCsv;
};

struct AdapterCommandContext {
  std::string ResolverName;
  std::filesystem::path BuildRoot;
  std::filesystem::path SourceRoot;
  const dnslab::ResolverAdapter *Adapter = nullptr;
};

struct MainCommandContext {
  std::filesystem::path WorkspaceRoot;
  std::string SelfExecutableCommand;
  std::optional<dnslab::ResolverLockFile> DefaultResolverLock;
  dnslab::ResolverRegistry RuntimeRegistry;
};

struct ResolverExecutionMaps {
  std::map<std::string, std::vector<dnslab::CacheRecord>> BeforeByResolver;
  std::map<std::string, std::vector<dnslab::CacheRecord>> AfterByResolver;
  std::map<std::string, dnslab::json::Value::Object> OracleByResolver;
};

struct SyncReplayResolverExecutions {
  std::map<std::string, ResolverExecution> ExecutedResolvers;
  std::map<std::string, std::string> SkippedResolvers;
  std::optional<dnslab::FailureEvidence> Failure;
};

ResolverRunResult runSyncReplayResolver(
    const std::string &ResolverName, const dnslab::ResolverAdapter &Adapter,
    const std::filesystem::path &ArtifactRoot,
    const std::filesystem::path &SamplePath, const std::string &SampleId,
    const std::filesystem::path &SourceRoot,
    const std::filesystem::path &BuildRoot);
ResolverExecutionMaps buildResolverExecutionMaps(
    const std::map<std::string, ResolverExecution> &ExecutedResolvers);
dnslab::json::Value::Object buildSyncReplayOraclePayload(
    const std::map<std::string, dnslab::json::Value::Object> &OracleByResolver,
    const std::string &SecondaryResolverName);
dnslab::StateFingerprint buildSyncReplayFingerprint(
    const dnslab::SampleIdentity &SampleIdentity,
    const ResolverExecutionMaps &ExecutionMaps);
void copySyncReplaySampleArtifact(const std::filesystem::path &SamplePath,
                                  const std::filesystem::path &ArtifactRoot);
double readSyncReplayBudgetSec();
dnslab::SampleMeta buildSyncReplayMeta(
    const dnslab::SampleIdentity &SampleIdentity,
    const std::filesystem::path &SamplePath,
    const std::vector<uint8_t> &SampleBytes,
    const std::string &SecondaryResolverName, double ReplayBudgetSec,
    const dnslab::TriageRecord &Triage,
    const std::optional<dnslab::FailureEvidence> &Failure);
SyncReplayResult buildSyncReplayResult(
    const dnslab::SampleIdentity &SampleIdentity,
    const dnslab::StateFingerprint &Fingerprint,
    const dnslab::json::Value::Object &OraclePayload,
    const ResolverExecutionMaps &ExecutionMaps,
    const std::map<std::string, ResolverExecution> &ExecutedResolvers,
    const std::map<std::string, std::string> &SkippedResolvers,
    const SyncReplayResolverRoots &ResolverRoots,
    const dnslab::CacheDiffResult &CacheDiff, const dnslab::TriageRecord &Triage,
    const std::optional<dnslab::FailureEvidence> &Failure,
    const std::string &SecondaryResolverName,
    const std::filesystem::path &ArtifactRoot);
void writeSyncReplayArtifacts(
    const std::filesystem::path &ArtifactRoot,
    const std::string &SecondaryResolverName,
    const dnslab::CacheDiffResult &CacheDiff,
    const std::map<std::string, std::string> &SkippedResolvers,
    const ResolverExecutionMaps &ExecutionMaps,
    const std::map<std::string, ResolverExecution> &ExecutedResolvers,
    const dnslab::json::Value::Object &OraclePayload,
    const dnslab::TriageRecord &Triage, const dnslab::SampleMeta &Meta,
    const dnslab::StateFingerprint &Fingerprint);

std::string compactJson(const dnslab::json::Value &Value) {
  return Value.dump(0);
}

dnslab::json::Value buildSkippedResolversJson(
    const std::map<std::string, std::string> &SkippedResolvers) {
  dnslab::json::Value::Object Output;
  for (const auto &[ResolverName, Reason] : SkippedResolvers) {
    Output[ResolverName] = Reason;
  }
  return dnslab::json::Value(Output);
}

dnslab::json::Value
buildResolverDiffsJson(const dnslab::TriageRecord &Triage) {
  dnslab::json::Value::Array Output;
  for (const auto &Difference : Triage.ResolverDifferences) {
    Output.emplace_back(dnslab::toJson(Difference));
  }
  return dnslab::json::Value(Output);
}

std::string joinNotes(const std::vector<std::string> &Notes) {
  if (Notes.empty()) {
    return "_";
  }
  std::ostringstream Stream;
  for (size_t Index = 0; Index < Notes.size(); ++Index) {
    if (Index != 0) {
      Stream << " | ";
    }
    Stream << Notes[Index];
  }
  return Stream.str();
}

std::string joinValues(const std::vector<std::string> &Values,
                       const std::string &Separator) {
  std::ostringstream Stream;
  for (size_t Index = 0; Index < Values.size(); ++Index) {
    if (Index != 0) {
      Stream << Separator;
    }
    Stream << Values[Index];
  }
  return Stream.str();
}

dnslab::json::Value::Object
buildResolverRunJson(const ResolverRunResult &Result) {
  dnslab::json::Value::Object Output;
  Output["dump_cache_exit_code"] = Result.DumpResult.ExitCode;
  Output["run_sample_exit_code"] = Result.RunResult.ExitCode;
  Output["before_cache"] = normalizePath(Result.BeforeCache).string();
  Output["after_cache"] = normalizePath(Result.AfterCache).string();
  Output["stderr"] = normalizePath(Result.StderrPath).string();
  Output["oracle"] = dnslab::json::Value(Result.Oracle.Fields);
  dnslab::json::Value::Array Logs;
  for (const auto &Path : Result.Logs) {
    Logs.emplace_back(normalizePath(Path).string());
  }
  Output["logs"] = Logs;
  return Output;
}

dnslab::json::Value::Object buildAdapterCommandOutput(
    const std::string &ResolverName, const std::filesystem::path &SourceRoot,
    const std::filesystem::path &BuildRoot,
    const dnslab::CommandResult &CommandResult,
    const std::optional<std::filesystem::path> &RunRoot = std::nullopt,
    const std::optional<std::filesystem::path> &SamplePath = std::nullopt,
    const std::optional<std::filesystem::path> &OutputFile = std::nullopt) {
  dnslab::json::Value::Object Output;
  Output["resolver"] = ResolverName;
  Output["source_root"] = normalizePath(SourceRoot).string();
  Output["build_root"] = normalizePath(BuildRoot).string();
  if (RunRoot.has_value()) {
    Output["run_root"] = normalizePath(*RunRoot).string();
  }
  if (SamplePath.has_value()) {
    Output["sample"] = normalizePath(*SamplePath).string();
  }
  if (OutputFile.has_value()) {
    Output["output_file"] = normalizePath(*OutputFile).string();
  }
  Output["exit_code"] = CommandResult.ExitCode;
  Output["stdout"] = CommandResult.StdoutText;
  Output["stderr"] = CommandResult.StderrText;
  return Output;
}

dnslab::json::Value::Object
buildAdapterReplayOutput(const std::string &ResolverName,
                         const ResolverRunResult &ReplayResult) {
  auto Output = buildResolverRunJson(ReplayResult);
  Output["resolver"] = ResolverName;
  return Output;
}

dnslab::json::Value::Array
buildExecutedResolversJson(const std::vector<std::string> &Resolvers) {
  dnslab::json::Value::Array Output;
  for (const auto &ResolverName : Resolvers) {
    Output.emplace_back(ResolverName);
  }
  return Output;
}

dnslab::json::Value::Object
buildSyncReplayCliOutput(const SyncReplayResult &ReplayResult) {
  dnslab::json::Value::Object Output;
  Output["status"] = ReplayResult.Failed ? "failed" : "completed";
  Output["exit_code"] = ReplayResult.ExitCode;
  Output["sample_id"] = ReplayResult.Identity.SampleId;
  Output["queue_event_id"] = ReplayResult.Identity.QueueEventId;
  Output["sample_sha1"] = ReplayResult.Identity.SampleSha1;
  Output["sample_size"] =
      static_cast<std::int64_t>(ReplayResult.Identity.SampleSize);
  Output["bind9"] = buildResolverRunJson(ReplayResult.Bind9);
  Output["secondary_resolver"] = ReplayResult.SecondaryResolver;
  Output[ReplayResult.SecondaryResolver] =
      buildResolverRunJson(ReplayResult.Secondary);
  dnslab::json::Value::Object Resolvers;
  for (const auto &[ResolverName, ResolverResult] : ReplayResult.ResolverRuns) {
    Resolvers[ResolverName] = buildResolverRunJson(ResolverResult);
  }
  Output["resolvers"] = dnslab::json::Value(Resolvers);
  Output["executed_resolvers"] =
      buildExecutedResolversJson(ReplayResult.ExecutedResolvers);
  Output["skipped_resolvers"] =
      buildSkippedResolversJson(ReplayResult.SkippedResolvers);
  Output["diff_detected"] = ReplayResult.Triage.DiffDetected;
  Output["resolver_diffs"] = buildResolverDiffsJson(ReplayResult.Triage);
  Output["artifact_dir"] = normalizePath(ReplayResult.ArtifactDir).string();
  if (ReplayResult.Failure.has_value()) {
    Output["failure"] = dnslab::toJson(*ReplayResult.Failure);
  }
  return Output;
}

std::vector<dnslab::CacheRecord>
parseCacheRowsIfPresent(const std::string &ResolverName,
                        const std::filesystem::path &DumpPath) {
  if (!std::filesystem::is_regular_file(DumpPath)) {
    return {};
  }
  return dnslab::parseCacheDump(ResolverName, DumpPath);
}

ResolverExecution buildResolverExecution(const std::string &ResolverName,
                                         ResolverRunResult Run) {
  ResolverExecution Execution;
  Execution.BeforeRows = parseCacheRowsIfPresent(ResolverName, Run.BeforeCache);
  Execution.AfterRows = parseCacheRowsIfPresent(ResolverName, Run.AfterCache);
  Execution.OracleFields = Run.Oracle.Fields;
  Execution.Run = std::move(Run);
  return Execution;
}

SyncReplayResolverRoots prepareSyncReplayResolverRoots(
    const std::filesystem::path &WorkspaceRoot,
    const std::optional<dnslab::ResolverLockFile> &DefaultResolverLock,
    const dnslab::ResolverRegistry &RuntimeRegistry,
    const std::string &SecondaryResolverName,
    const std::optional<std::string> &RequestedResolversCsv,
    const std::filesystem::path &Bind9BuildRoot,
    const std::filesystem::path &SecondaryBuildRoot,
    const std::filesystem::path &Bind9SourceRoot,
    const std::filesystem::path &SecondarySourceRoot) {
  SyncReplayResolverRoots Output;
  Output.RequestedResolvers = orderedResolversForReplay(
      RuntimeRegistry.names(), SecondaryResolverName, RequestedResolversCsv);
  for (const auto &ResolverName : Output.RequestedResolvers) {
    auto BuildRoot = defaultBuildRootForResolver(WorkspaceRoot, ResolverName);
    if (ResolverName == "bind9") {
      BuildRoot = Bind9BuildRoot;
    } else if (ResolverName == SecondaryResolverName) {
      BuildRoot = SecondaryBuildRoot;
    }
    Output.BuildRoots[ResolverName] = BuildRoot;
    auto SourceRoot = resolveDefaultSourceRootForWorkspace(
        WorkspaceRoot, DefaultResolverLock, ResolverName,
        defaultSourceRootForResolver(BuildRoot, ResolverName));
    if (ResolverName == "bind9") {
      SourceRoot = Bind9SourceRoot;
    } else if (ResolverName == SecondaryResolverName) {
      SourceRoot = SecondarySourceRoot;
    }
    Output.SourceRoots[ResolverName] = SourceRoot;
  }
  return Output;
}

SyncReplayCommandContext
resolveSyncReplayCommandContext(
    const std::vector<std::string> &Args,
    const std::filesystem::path &WorkspaceRoot,
    const std::optional<dnslab::ResolverLockFile> &DefaultResolverLock) {
  SyncReplayCommandContext Output;
  Output.Bind9BuildRoot = requireCommandPath(Args, "--bind9-build-root");
  Output.SecondaryResolverName =
      optionalOption(Args, "--secondary-resolver").value_or("unbound");
  const auto SecondaryBuildRootArg = optionalOption(Args, "--secondary-build-root");
  const auto LegacyUnboundBuildRootArg = optionalOption(Args, "--unbound-build-root");
  if (!SecondaryBuildRootArg.has_value() &&
      !LegacyUnboundBuildRootArg.has_value()) {
    throw std::runtime_error(
        "缺少参数: --secondary-build-root 或 --unbound-build-root");
  }
  Output.SecondaryBuildRoot =
      normalizePath(SecondaryBuildRootArg.value_or(*LegacyUnboundBuildRootArg));
  Output.Bind9SourceRoot = resolveDefaultSourceRootForWorkspace(
      WorkspaceRoot, DefaultResolverLock, "bind9", Output.Bind9BuildRoot);
  Output.SecondarySourceRoot = resolveDefaultSourceRootForWorkspace(
      WorkspaceRoot, DefaultResolverLock, Output.SecondaryResolverName,
      Output.SecondaryBuildRoot);
  Output.RequestedResolversCsv = optionalOption(Args, "--resolvers");
  applySyncReplaySourceRootOverrides(Args, Output.Bind9SourceRoot,
                                     Output.SecondarySourceRoot);
  return Output;
}

SyncReplayResolverExecutions executeSyncReplayResolvers(
    const dnslab::ResolverRegistry &RuntimeRegistry,
    const std::vector<std::string> &RequestedResolvers,
    const std::string &SecondaryResolverName,
    const std::map<std::string, std::filesystem::path> &BuildRoots,
    const std::map<std::string, std::filesystem::path> &SourceRoots,
    const std::filesystem::path &ArtifactRoot,
    const std::filesystem::path &SamplePath,
    const dnslab::SampleIdentity &SampleIdentity) {
  SyncReplayResolverExecutions Output;
  for (const auto &ResolverName : RequestedResolvers) {
    const bool RequiredResolver =
        ResolverName == "bind9" || ResolverName == SecondaryResolverName;
    try {
      setResolverBuildEnvForResolver(ResolverName, BuildRoots.at(ResolverName));
      const auto &Adapter = RuntimeRegistry.require(ResolverName);
      auto Run = runSyncReplayResolver(ResolverName, Adapter, ArtifactRoot,
                                       SamplePath, SampleIdentity.SampleId,
                                       SourceRoots.at(ResolverName),
                                       BuildRoots.at(ResolverName));
      const auto Failure = Run.Failure;
      if (Failure.has_value() && !RequiredResolver) {
        Output.SkippedResolvers[ResolverName] =
            Failure->Message.value_or("resolver replay 失败");
        continue;
      }
      Output.ExecutedResolvers.emplace(
          ResolverName, buildResolverExecution(ResolverName, std::move(Run)));
      if (Failure.has_value()) {
        Output.Failure = Failure;
        break;
      }
    } catch (const dnslab::ResolverExecutableError &Error) {
      if (RequiredResolver) {
        Output.Failure = dnslab::buildMissingExecutableFailure(
            ResolverName, Error.executablePath(), Error.what());
        break;
      }
      Output.SkippedResolvers[ResolverName] = Error.what();
    } catch (const std::exception &Error) {
      if (RequiredResolver) {
        dnslab::ReplayStageContext Context;
        Context.Resolver = ResolverName;
        Context.Stage = ResolverName + ".preflight";
        Output.Failure = dnslab::buildReplayLaunchFailure(Context, Error.what());
        break;
      }
      Output.SkippedResolvers[ResolverName] = Error.what();
    }
  }
  return Output;
}

SyncReplayResult executeSyncReplay(
    const std::filesystem::path &WorkspaceRoot,
    const std::optional<dnslab::ResolverLockFile> &DefaultResolverLock,
    const dnslab::ResolverRegistry &RuntimeRegistry,
    const std::filesystem::path &SamplePath,
    const std::filesystem::path &RunRoot, bool NestBySampleId,
    const std::filesystem::path &Bind9BuildRoot,
    const std::filesystem::path &SecondaryBuildRoot,
    const std::filesystem::path &Bind9SourceRoot,
    const std::filesystem::path &SecondarySourceRoot,
    const std::string &SecondaryResolverName,
    const std::optional<std::string> &RequestedResolversCsv = std::nullopt,
    const std::optional<std::string> &QueueEventId = std::nullopt) {
  const auto SampleBytes = readBinaryFile(SamplePath);
  const auto SampleIdentity = dnslab::buildSampleIdentity(
      QueueEventId.value_or("manual"), SampleBytes);
  const auto ArtifactRoot =
      NestBySampleId ? (RunRoot / SampleIdentity.SampleId) : RunRoot;

  const auto ResolverRoots = prepareSyncReplayResolverRoots(
      WorkspaceRoot, DefaultResolverLock, RuntimeRegistry,
      SecondaryResolverName, RequestedResolversCsv, Bind9BuildRoot,
      SecondaryBuildRoot, Bind9SourceRoot, SecondarySourceRoot);

  auto ResolverExecutions = executeSyncReplayResolvers(
      RuntimeRegistry, ResolverRoots.RequestedResolvers, SecondaryResolverName,
      ResolverRoots.BuildRoots, ResolverRoots.SourceRoots, ArtifactRoot,
      SamplePath, SampleIdentity);
  auto &ExecutedResolvers = ResolverExecutions.ExecutedResolvers;
  auto &SkippedResolvers = ResolverExecutions.SkippedResolvers;
  auto Failure = ResolverExecutions.Failure;

  const auto Bind9Found = ExecutedResolvers.find("bind9");
  const auto SecondaryFound = ExecutedResolvers.find(SecondaryResolverName);
  if (!Failure.has_value() &&
      (Bind9Found == ExecutedResolvers.end() ||
       SecondaryFound == ExecutedResolvers.end())) {
    const std::string MissingResolver =
        Bind9Found == ExecutedResolvers.end() ? "bind9" : SecondaryResolverName;
    dnslab::ReplayStageContext Context;
    Context.Resolver = MissingResolver;
    Context.Stage = MissingResolver + ".preflight";
    Failure = dnslab::buildReplayLaunchFailure(
        Context, "缺少必要 resolver 执行结果: " + MissingResolver);
  }

  const auto ExecutionMaps = buildResolverExecutionMaps(ExecutedResolvers);

  const auto PreliminaryCacheDiff = dnslab::buildCacheDiff(
      SampleIdentity.SampleId, ExecutionMaps.BeforeByResolver,
      ExecutionMaps.AfterByResolver, false, SecondaryResolverName);
  bool Triggered = false;
  for (const auto &[ResolverName, Diff] : PreliminaryCacheDiff.Resolvers) {
    (void)ResolverName;
    if (Diff.HasCacheDiff) {
      Triggered = true;
      break;
    }
  }
  const auto CacheDiff = dnslab::buildCacheDiff(
      SampleIdentity.SampleId, ExecutionMaps.BeforeByResolver,
      ExecutionMaps.AfterByResolver, Triggered, SecondaryResolverName);

  dnslab::json::Value::Object OraclePayload;
  if (!Failure.has_value()) {
    OraclePayload = buildSyncReplayOraclePayload(
        ExecutionMaps.OracleByResolver, SecondaryResolverName);
  }

  const auto Fingerprint =
      buildSyncReplayFingerprint(SampleIdentity, ExecutionMaps);
  copySyncReplaySampleArtifact(SamplePath, ArtifactRoot);

  const auto Triage = dnslab::buildTriageRecord(
      SampleIdentity.SampleId, ExecutionMaps.OracleByResolver, CacheDiff,
      Fingerprint, Failure);

  const auto ReplayBudgetSec = readSyncReplayBudgetSec();

  auto Meta = buildSyncReplayMeta(SampleIdentity, SamplePath, SampleBytes,
                                  SecondaryResolverName, ReplayBudgetSec, Triage,
                                  Failure);
  writeSyncReplayArtifacts(ArtifactRoot, SecondaryResolverName, CacheDiff,
                           SkippedResolvers, ExecutionMaps, ExecutedResolvers,
                           OraclePayload, Triage, Meta, Fingerprint);
  auto Result = buildSyncReplayResult(
      SampleIdentity, Fingerprint, OraclePayload, ExecutionMaps,
      ExecutedResolvers, SkippedResolvers, ResolverRoots, CacheDiff, Triage,
      Failure, SecondaryResolverName, ArtifactRoot);
  Result.Meta = Meta;
  return Result;
}

ResolverExecutionMaps buildResolverExecutionMaps(
    const std::map<std::string, ResolverExecution> &ExecutedResolvers) {
  ResolverExecutionMaps Output;
  for (const auto &[ResolverName, Execution] : ExecutedResolvers) {
    Output.BeforeByResolver[ResolverName] = Execution.BeforeRows;
    Output.AfterByResolver[ResolverName] = Execution.AfterRows;
    Output.OracleByResolver[ResolverName] = Execution.OracleFields;
  }
  return Output;
}

dnslab::json::Value::Object buildSyncReplayOraclePayload(
    const std::map<std::string, dnslab::json::Value::Object> &OracleByResolver,
    const std::string &SecondaryResolverName) {
  auto Output = OracleByResolver.at("bind9");
  const auto &SecondaryOracle = OracleByResolver.at(SecondaryResolverName);
  for (const auto &[Key, Value] : SecondaryOracle) {
    Output[Key] = Value;
    const std::string Prefix = SecondaryResolverName + ".";
    if (SecondaryResolverName != "unbound" && Key.rfind(Prefix, 0) == 0) {
      Output["unbound." + Key.substr(Prefix.size())] = Value;
    }
  }
  return Output;
}

dnslab::json::Value::Object buildSyncReplayArtifactsPayload(
    const std::map<std::string, ResolverExecution> &ExecutedResolvers,
    bool ReplayFailed) {
  dnslab::json::Value::Object Artifacts;
  Artifacts["sample_bin"] = "sample.bin";
  if (!ReplayFailed) {
    Artifacts["oracle"] = "oracle.json";
  }
  for (const auto &[ResolverName, Execution] : ExecutedResolvers) {
    const auto ResolverPrefix = ResolverName + "/";
    Artifacts[ResolverName + "_stderr"] =
        ResolverPrefix + Execution.Run.StderrPath.filename().string();
    Artifacts[ResolverName + "_before_cache"] =
        ResolverPrefix + Execution.Run.BeforeCache.filename().string();
    Artifacts[ResolverName + "_after_cache"] =
        ResolverPrefix + Execution.Run.AfterCache.filename().string();
  }
  return Artifacts;
}

dnslab::json::Value::Object buildSyncReplayOracleProvenancePayload(
    const std::map<std::string, ResolverExecution> &ExecutedResolvers) {
  dnslab::json::Value::Object Provenance;
  Provenance["mode"] = "same_replay_after_cache";
  for (const auto &[ResolverName, Execution] : ExecutedResolvers) {
    dnslab::json::Value::Object ResolverProvenance;
    const auto ResolverPrefix = ResolverName + "/";
    ResolverProvenance["stderr"] =
        ResolverPrefix + Execution.Run.StderrPath.filename().string();
    ResolverProvenance["after_cache"] =
        ResolverPrefix + Execution.Run.AfterCache.filename().string();
    ResolverProvenance["stage_marker"] =
        "===== " + ResolverName + ".after =====";
    Provenance[ResolverName] = dnslab::json::Value(ResolverProvenance);
  }
  return Provenance;
}

void appendSyncReplayContractFields(
    dnslab::json::Value::Object &Payload,
    const std::string &SecondaryResolverName,
    const std::vector<std::string> &ExecutedResolvers,
    const std::map<std::string, std::string> &SkippedResolvers,
    const dnslab::TriageRecord &Triage,
    const std::optional<std::map<std::string, dnslab::json::Value::Object>>
        &ResolverPayloads = std::nullopt) {
  Payload["secondary_resolver"] = SecondaryResolverName;
  Payload["executed_resolvers"] = buildExecutedResolversJson(ExecutedResolvers);
  Payload["skipped_resolvers"] = buildSkippedResolversJson(SkippedResolvers);
  Payload["diff_detected"] = Triage.DiffDetected;
  Payload["resolver_diffs"] = buildResolverDiffsJson(Triage);
  if (ResolverPayloads.has_value()) {
    dnslab::json::Value::Object ResolverObjects;
    for (const auto &[ResolverName, ResolverPayload] : *ResolverPayloads) {
      ResolverObjects[ResolverName] = dnslab::json::Value(ResolverPayload);
    }
    Payload["resolvers"] = dnslab::json::Value(ResolverObjects);
  }
}

dnslab::SampleMeta buildSyncReplayMeta(
    const dnslab::SampleIdentity &SampleIdentity,
    const std::filesystem::path &SamplePath,
    const std::vector<uint8_t> &SampleBytes,
    const std::string &SecondaryResolverName, double ReplayBudgetSec,
    const dnslab::TriageRecord &Triage,
    const std::optional<dnslab::FailureEvidence> &Failure) {
  auto Meta = dnslab::buildSampleMeta(SampleIdentity.SampleId);
  Meta.QueueEventId = SampleIdentity.QueueEventId;
  Meta.SourceQueueFile = SamplePath.string();
  Meta.SourceResolver = "bind9";
  Meta.SampleSha1 = SampleIdentity.SampleSha1;
  Meta.SampleSize = static_cast<int>(SampleIdentity.SampleSize);
  Meta.IsStateful = dnslab::parseTranscript(SampleBytes).has_value();
  Meta.Status = Failure.has_value() ? "failed" : "completed";
  Meta.State = dnslab::analysisStateFromString(Triage.AnalysisState);
  Meta.ExcludeReason = Triage.ExcludeReason;
  Meta.Aggregation.ResolverPair = "bind9_vs_" + SecondaryResolverName;
  Meta.Aggregation.ProducerProfile = "poison-stateful";
  Meta.Aggregation.InputModel = "DST1 transcript";
  Meta.Aggregation.SourceQueueDir = SamplePath.parent_path().string();
  Meta.Aggregation.BudgetSec = ReplayBudgetSec;
  const auto Ablation = dnslab::resolveAblationConfig();
  Meta.Aggregation.SeedTimeoutSec = dnslab::resolveSeedTimeoutSec();
  Meta.Aggregation.VariantName = Ablation.variantName();
  Meta.Aggregation.AblationStatus = Ablation.status();
  Meta.BaselineCompare.ResolverPair = "bind9_vs_" + SecondaryResolverName;
  Meta.BaselineCompare.ProducerProfile = "poison-stateful";
  Meta.BaselineCompare.InputModel = "DST1 transcript";
  Meta.BaselineCompare.SourceQueueDir = SamplePath.parent_path().string();
  Meta.BaselineCompare.BudgetSec = ReplayBudgetSec;
  Meta.BaselineCompare.SeedTimeoutSec = dnslab::resolveSeedTimeoutSec();
  Meta.BaselineCompare.RepeatCount = 1;
  Meta.Failure = Failure;
  return Meta;
}

double readSyncReplayBudgetSec() {
  if (const char *BudgetEnv = std::getenv("DNSLAB_SYNC_REPLAY_BUDGET_SEC")) {
    try {
      return std::stod(BudgetEnv);
    } catch (const std::exception &) {
      return 0.0;
    }
  }
  return 0.0;
}

SyncReplayResult buildSyncReplayResult(
    const dnslab::SampleIdentity &SampleIdentity,
    const dnslab::StateFingerprint &Fingerprint,
    const dnslab::json::Value::Object &OraclePayload,
    const ResolverExecutionMaps &ExecutionMaps,
    const std::map<std::string, ResolverExecution> &ExecutedResolvers,
    const std::map<std::string, std::string> &SkippedResolvers,
    const SyncReplayResolverRoots &ResolverRoots,
    const dnslab::CacheDiffResult &CacheDiff, const dnslab::TriageRecord &Triage,
    const std::optional<dnslab::FailureEvidence> &Failure,
    const std::string &SecondaryResolverName,
    const std::filesystem::path &ArtifactRoot) {
  SyncReplayResult Result;
  Result.Identity = SampleIdentity;
  Result.Fingerprint = Fingerprint;
  Result.OraclePayload = OraclePayload;
  Result.OracleByResolver = ExecutionMaps.OracleByResolver;
  for (const auto &[ResolverName, Execution] : ExecutedResolvers) {
    Result.ResolverRuns.emplace(ResolverName, Execution.Run);
  }
  Result.SkippedResolvers = SkippedResolvers;
  Result.ResolverBuildRoots = ResolverRoots.BuildRoots;
  Result.ResolverSourceRoots = ResolverRoots.SourceRoots;
  Result.ExecutedResolvers = CacheDiff.ExecutedResolvers;
  if (const auto Found = ExecutedResolvers.find("bind9");
      Found != ExecutedResolvers.end()) {
    Result.Bind9 = Found->second.Run;
  }
  if (const auto Found = ExecutedResolvers.find(SecondaryResolverName);
      Found != ExecutedResolvers.end()) {
    Result.Secondary = Found->second.Run;
  }
  Result.SecondaryResolver = SecondaryResolverName;
  Result.ArtifactDir = ArtifactRoot;
  Result.Failure = Failure;
  Result.ExitCode =
      Failure.has_value() ? Failure->ExitCode.value_or(
                                dnslab::kReplayExitRuntimeFailure)
                          : 0;
  Result.Failed = Failure.has_value();
  Result.CacheDiff = CacheDiff;
  Result.Triage = Triage;
  return Result;
}

ResolverRunResult runSyncReplayResolver(
    const std::string &ResolverName, const dnslab::ResolverAdapter &Adapter,
    const std::filesystem::path &ArtifactRoot,
    const std::filesystem::path &SamplePath, const std::string &SampleId,
    const std::filesystem::path &SourceRoot,
    const std::filesystem::path &BuildRoot) {
  const auto ResolverRunRoot = ArtifactRoot / ResolverName;
  std::filesystem::create_directories(ResolverRunRoot);
  ResolverRunResult Result;
  Result.BeforeCache =
      ResolverRunRoot / (ResolverName + ".before.cache.txt");
  Result.AfterCache = ResolverRunRoot / (ResolverName + ".after.cache.txt");
  Result.StderrPath = ResolverRunRoot / (ResolverName + ".stderr");
  const auto RootStderrPath = ArtifactRoot / (ResolverName + ".stderr");

  std::error_code Error;
  std::filesystem::remove(Result.BeforeCache, Error);
  std::filesystem::remove(Result.AfterCache, Error);
  std::filesystem::remove(Result.StderrPath, Error);
  std::filesystem::remove(RootStderrPath, Error);

  const auto MirrorStderr = [&]() {
    std::error_code CopyError;
    if (std::filesystem::is_regular_file(Result.StderrPath, CopyError)) {
      std::filesystem::copy_file(
          Result.StderrPath, RootStderrPath,
          std::filesystem::copy_options::overwrite_existing, CopyError);
    }
  };
  const auto BuildStageContext = [&](const std::string &Stage,
                                     const std::filesystem::path &Artifact) {
    dnslab::ReplayStageContext Context;
    Context.Resolver = ResolverName;
    Context.Stage = ResolverName + "." + Stage;
    Context.StderrPath = RootStderrPath.filename();
    Context.ArtifactPath = Artifact;
    Context.TimeoutSec = dnslab::resolveSeedTimeoutSec();
    Context.OkReturnCodes = ResolverName == "unbound"
                                ? std::vector<int>{0, 1}
                                : std::vector<int>{0};
    return Context;
  };

  try {
    Result.DumpResult = Adapter.dumpCache(ResolverRunRoot, Result.BeforeCache);
  } catch (const dnslab::ResolverExecutableError &ExecutableError) {
    Result.Failure = dnslab::buildMissingExecutableFailure(
        ResolverName, ExecutableError.executablePath(), ExecutableError.what());
    return Result;
  } catch (const std::exception &Exception) {
    auto Context = BuildStageContext("preflight", {});
    Context.ArtifactPath.reset();
    Result.Failure =
        dnslab::buildReplayLaunchFailure(Context, Exception.what());
    return Result;
  }
  MirrorStderr();
  const auto BeforeContext = BuildStageContext("before", Result.BeforeCache);
  Result.Failure =
      dnslab::classifyReplayCommandResult(BeforeContext, Result.DumpResult);
  if (!Result.Failure.has_value()) {
    Result.Failure = dnslab::classifyMissingReplayArtifact(
        BeforeContext, Result.DumpResult.ProcessStarted);
  }
  if (Result.Failure.has_value()) {
    Result.Logs = Adapter.collectLogs(ResolverRunRoot);
    return Result;
  }

  try {
    Result.RunResult = Adapter.runSample(
        {SourceRoot, BuildRoot, ResolverRunRoot, SamplePath, SampleId, {}});
  } catch (const dnslab::ResolverExecutableError &ExecutableError) {
    Result.Failure = dnslab::buildMissingExecutableFailure(
        ResolverName, ExecutableError.executablePath(), ExecutableError.what());
    return Result;
  } catch (const std::exception &Exception) {
    auto Context = BuildStageContext("after", Result.AfterCache);
    Result.Failure =
        dnslab::buildReplayLaunchFailure(Context, Exception.what());
    return Result;
  }
  MirrorStderr();
  const auto AfterContext = BuildStageContext("after", Result.AfterCache);
  Result.Failure =
      dnslab::classifyReplayCommandResult(AfterContext, Result.RunResult);
  if (!Result.Failure.has_value()) {
    Result.Failure = dnslab::classifyMissingReplayArtifact(
        AfterContext, Result.RunResult.ProcessStarted);
  }
  if (Result.Failure.has_value()) {
    Result.Logs = Adapter.collectLogs(ResolverRunRoot);
    return Result;
  }

  Result.Oracle = Adapter.parseOracle(Result.StderrPath);
  Result.Logs = Adapter.collectLogs(ResolverRunRoot);
  return Result;
}

dnslab::StateFingerprint buildSyncReplayFingerprint(
    const dnslab::SampleIdentity &SampleIdentity,
    const ResolverExecutionMaps &ExecutionMaps) {
  dnslab::StateFingerprint Fingerprint;
  Fingerprint.SchemaVersion = dnslab::kSchemaVersion;
  Fingerprint.GeneratedAt = dnslab::utcTimestampNow();
  Fingerprint.SampleId = SampleIdentity.SampleId;

  // 从 replay 后的 cache 记录提取可观测缓存状态信号。
  const auto FillSignals =
      [](const std::vector<dnslab::CacheRecord> &Rows, bool &MsgSeen,
         bool &RrsetSeen, bool &NegativeSeen) {
        for (const auto &Row : Rows) {
          if (Row.Section == "MSG") {
            MsgSeen = true;
          }
          if (Row.CacheType == "rrset") {
            RrsetSeen = true;
          }
          if (Row.CacheType == "negative" || Row.Section == "SERVFAIL" ||
              Row.CacheType == "servfail" || Row.CacheType == "badcache") {
            NegativeSeen = true;
          }
        }
      };

  bool Bind9Msg = false;
  bool Bind9Rrset = false;
  bool Bind9Neg = false;
  if (const auto It = ExecutionMaps.AfterByResolver.find("bind9");
      It != ExecutionMaps.AfterByResolver.end()) {
    FillSignals(It->second, Bind9Msg, Bind9Rrset, Bind9Neg);
    Fingerprint.Bind9MsgCacheSeen = Bind9Msg;
    Fingerprint.Bind9RrsetCacheSeen = Bind9Rrset;
    Fingerprint.Bind9NegativeCacheSeen = Bind9Neg;
  }
  bool UnboundMsg = false;
  bool UnboundRrset = false;
  bool UnboundNeg = false;
  if (const auto It = ExecutionMaps.AfterByResolver.find("unbound");
      It != ExecutionMaps.AfterByResolver.end()) {
    FillSignals(It->second, UnboundMsg, UnboundRrset, UnboundNeg);
    Fingerprint.UnboundMsgCacheSeen = UnboundMsg;
    Fingerprint.UnboundRrsetCacheSeen = UnboundRrset;
    Fingerprint.UnboundNegativeCacheSeen = UnboundNeg;
  }
  // forwarding_path / retry_seen：当前 resolver stderr 无稳定信号源，
  // 保持未设置（null），由上层 triage 的 partial_fingerprint 标签显式区分。
  return Fingerprint;
}

void copySyncReplaySampleArtifact(const std::filesystem::path &SamplePath,
                                  const std::filesystem::path &ArtifactRoot) {
  std::filesystem::create_directories(ArtifactRoot);
  std::filesystem::copy_file(
      SamplePath, ArtifactRoot / "sample.bin",
      std::filesystem::copy_options::overwrite_existing);
}

void writeSyncReplayArtifacts(
    const std::filesystem::path &ArtifactRoot,
    const std::string &SecondaryResolverName,
    const dnslab::CacheDiffResult &CacheDiff,
    const std::map<std::string, std::string> &SkippedResolvers,
    const ResolverExecutionMaps &ExecutionMaps,
    const std::map<std::string, ResolverExecution> &ExecutedResolvers,
    const dnslab::json::Value::Object &OraclePayload, const dnslab::TriageRecord &Triage,
    const dnslab::SampleMeta &Meta, const dnslab::StateFingerprint &Fingerprint) {
  std::error_code CopyError;
  for (const auto &[ResolverName, Execution] : ExecutedResolvers) {
    // case study / audit 契约期望 <resolver>.before/after.cache.txt 位于
    // 样本顶层；同时保留 resolver 子目录原始布局以兼容既有消费方。
    if (std::filesystem::is_regular_file(Execution.Run.BeforeCache)) {
      std::filesystem::copy_file(
          Execution.Run.BeforeCache,
          ArtifactRoot / (ResolverName + ".before.cache.txt"),
          std::filesystem::copy_options::overwrite_existing, CopyError);
    }
    if (std::filesystem::is_regular_file(Execution.Run.AfterCache)) {
      std::filesystem::copy_file(
          Execution.Run.AfterCache,
          ArtifactRoot / (ResolverName + ".after.cache.txt"),
          std::filesystem::copy_options::overwrite_existing, CopyError);
    }
  }

  if (!Meta.Failure.has_value()) {
    dnslab::json::Value::Object OracleDocument = OraclePayload;
    appendSyncReplayContractFields(
        OracleDocument, SecondaryResolverName, CacheDiff.ExecutedResolvers,
        SkippedResolvers, Triage, ExecutionMaps.OracleByResolver);
    writeJsonFile(ArtifactRoot / "oracle.json",
                  dnslab::json::Value(OracleDocument));
  } else {
    std::error_code Error;
    std::filesystem::remove(ArtifactRoot / "oracle.json", Error);
  }

  auto MetaPayload =
      std::get<dnslab::json::Value::Object>(dnslab::toJson(Meta).storage());
  MetaPayload["artifacts"] = dnslab::json::Value(
      buildSyncReplayArtifactsPayload(ExecutedResolvers,
                                      Meta.Failure.has_value()));
  MetaPayload["oracle_provenance"] =
      dnslab::json::Value(buildSyncReplayOracleProvenancePayload(ExecutedResolvers));
  MetaPayload["output_dir"] = ArtifactRoot.string();
  appendSyncReplayContractFields(MetaPayload, SecondaryResolverName,
                                 CacheDiff.ExecutedResolvers, SkippedResolvers,
                                 Triage);
  writeJsonFile(ArtifactRoot / "sample.meta.json", dnslab::json::Value(MetaPayload));
  writeJsonFile(ArtifactRoot / "cache_diff.json", dnslab::toJson(CacheDiff));
  writeJsonFile(ArtifactRoot / "state_fingerprint.json", dnslab::toJson(Fingerprint));
  writeJsonFile(ArtifactRoot / "triage.json", dnslab::toJson(Triage));
}

void writeCaseStudyMarkdown(const std::filesystem::path &CaseStudyPath,
                            const SyncReplayResult &Result,
                            const std::string &ReplayCommand) {
  const auto ExecutedResolversText =
      joinValues(Result.ExecutedResolvers, ",");
  const auto SkippedResolversJson =
      buildSkippedResolversJson(Result.SkippedResolvers);
  const auto ResolverDiffsJson = buildResolverDiffsJson(Result.Triage);
  std::ofstream CaseStudyFile(CaseStudyPath);
  CaseStudyFile << "# " << Result.Identity.SampleId << "\n\n";
  CaseStudyFile << "- semantic_outcome: " << Result.Triage.SemanticOutcome
                << "\n";
  CaseStudyFile << "- manual_truth_status: "
                << Result.Triage.ManualTruthStatus << "\n";
  CaseStudyFile << "- executed_resolvers: " << ExecutedResolversText << "\n";
  CaseStudyFile << "- skipped_resolvers_json: "
                << compactJson(SkippedResolversJson) << "\n";
  CaseStudyFile << "- diff_detected: "
                << (Result.Triage.DiffDetected ? "true" : "false") << "\n";
  CaseStudyFile << "- resolver_diffs_json: "
                << compactJson(ResolverDiffsJson) << "\n";
  CaseStudyFile << "- notes: " << joinNotes(Result.Triage.Notes) << "\n";
  CaseStudyFile << "- transcript: "
                << (Result.ArtifactDir / "sample.bin").string() << "\n";
  CaseStudyFile << "- oracle: "
                << (Result.ArtifactDir / "oracle.json").string() << "\n";
  for (const auto &ResolverName : Result.ExecutedResolvers) {
    const auto ResolverFound = Result.ResolverRuns.find(ResolverName);
    if (ResolverFound == Result.ResolverRuns.end()) {
      continue;
    }
    CaseStudyFile << "- " << ResolverName
                  << "_before_cache: "
                  << ResolverFound->second.BeforeCache.string() << "\n";
    CaseStudyFile << "- " << ResolverName
                  << "_after_cache: "
                  << ResolverFound->second.AfterCache.string() << "\n";
  }
  for (const auto &ResolverName : Result.ExecutedResolvers) {
    const auto ResolverFound = Result.ResolverRuns.find(ResolverName);
    if (ResolverFound == Result.ResolverRuns.end()) {
      continue;
    }
    CaseStudyFile << "- " << ResolverName << "_logs:\n";
    for (const auto &Path : ResolverFound->second.Logs) {
      CaseStudyFile << "  - " << Path.string() << "\n";
    }
  }
  CaseStudyFile << "- replay_command: `" << ReplayCommand << "`\n";
}

void appendCaseStudyIndexRow(std::ostream &CaseStudyIndex,
                             const SyncReplayResult &Result,
                             const std::filesystem::path &CaseStudyPath,
                             const std::string &ReplayCommand) {
  CaseStudyIndex << Result.Identity.SampleId << '\t'
                 << Result.Triage.SemanticOutcome << '\t'
                 << "oracle_audit_candidate" << '\t'
                 << CaseStudyPath.string() << '\t' << ReplayCommand << '\t'
                 << joinValues(Result.ExecutedResolvers, ",") << '\t'
                 << (Result.Triage.DiffDetected ? "true" : "false")
                 << '\t'
                 << compactJson(buildResolverDiffsJson(Result.Triage))
                 << '\n';
}

std::optional<bool> objectBoolValue(const dnslab::json::Value::Object &Object,
                                    const std::string &Key) {
  const auto Found = Object.find(Key);
  if (Found == Object.end()) {
    return std::nullopt;
  }
  if (const auto *BoolValue = std::get_if<bool>(&Found->second.storage())) {
    return *BoolValue;
  }
  return std::nullopt;
}

bool anyResolverTrue(const dnslab::json::Value::Object &Object) {
  for (const auto &[ResolverName, Value] : Object) {
    (void)ResolverName;
    if (const auto *BoolValue = std::get_if<bool>(&Value.storage())) {
      if (*BoolValue) {
        return true;
      }
    }
  }
  return false;
}

struct BatchReplayRowData {
  dnslab::json::Value::Object ResponseAcceptedByResolver;
  dnslab::json::Value::Object SecondQueryHitByResolver;
  dnslab::json::Value::Object CacheEntryCreatedByResolver;
  std::string ExecutedResolversText;
  dnslab::json::Value SkippedResolversJson;
  dnslab::json::Value ResolverDiffsJson;
  bool ResponseAcceptedAny = false;
  bool SecondQueryHitAny = false;
  bool CacheEntryCreatedAny = false;
  bool OracleDiffAny = false;
  bool CacheDiffAny = false;
  bool OracleEligible = false;
};

BatchReplayRowData buildBatchReplayRowData(const SyncReplayResult &Result) {
  const auto buildResolverBoolMap =
      [&](const std::string &FieldSuffix) {
        dnslab::json::Value::Object Output;
        for (const auto &ResolverName : Result.ExecutedResolvers) {
          const auto OracleFound = Result.OracleByResolver.find(ResolverName);
          const auto Value =
              OracleFound == Result.OracleByResolver.end()
                  ? std::optional<bool>()
                  : objectBoolValue(OracleFound->second,
                                    ResolverName + "." + FieldSuffix);
          if (Value.has_value()) {
            Output[ResolverName] = *Value;
          } else {
            Output[ResolverName] = dnslab::json::Value();
          }
        }
        return Output;
      };

  BatchReplayRowData Output;
  Output.ResponseAcceptedByResolver =
      buildResolverBoolMap("response_accepted");
  Output.SecondQueryHitByResolver = buildResolverBoolMap("second_query_hit");
  Output.CacheEntryCreatedByResolver =
      buildResolverBoolMap("cache_entry_created");
  Output.ExecutedResolversText = joinValues(Result.ExecutedResolvers, ",");
  Output.SkippedResolversJson =
      buildSkippedResolversJson(Result.SkippedResolvers);
  Output.ResolverDiffsJson = buildResolverDiffsJson(Result.Triage);
  Output.ResponseAcceptedAny =
      anyResolverTrue(Output.ResponseAcceptedByResolver);
  Output.SecondQueryHitAny =
      anyResolverTrue(Output.SecondQueryHitByResolver);
  Output.CacheEntryCreatedAny =
      anyResolverTrue(Output.CacheEntryCreatedByResolver);
  Output.OracleEligible =
      Result.Triage.AnalysisState == "included" &&
      Result.Triage.OracleAuditCandidate;
  Output.OracleDiffAny = std::any_of(
      Result.Triage.ResolverDifferences.begin(),
      Result.Triage.ResolverDifferences.end(),
      [](const dnslab::ResolverPairDifference &Difference) {
        return !Difference.OracleDiffFields.empty();
      });
  Output.CacheDiffAny = Result.CacheDiff.DiffDetected;
  return Output;
}

struct BatchReplayAccumulator {
  std::vector<dnslab::SampleMeta> MetaRecords;
  std::vector<dnslab::ClusterRecord> ClusterRecords;
  size_t CompletedCount = 0;
  size_t FailedCount = 0;
  size_t IncludedCount = 0;
  size_t ExcludedCount = 0;
  size_t UnknownCount = 0;
  size_t OracleAuditCount = 0;
  size_t CaseStudyCount = 0;
  size_t DiffDetectedCount = 0;
  std::map<std::string, int> FailurePrimaryCounts;
  std::map<std::string, int> SignalEligibleCounts;
  std::map<std::string, int> SignalPendingCounts;
  std::map<std::string, int> ExecutedResolverSampleCounts;
  std::map<std::string, int> SkippedResolverSampleCounts;
  std::map<std::string, int> ResolverPairDiffCounts;
};

void updateBatchReplaySignal(BatchReplayAccumulator &Accumulator,
                             const std::string &Name,
                             bool EligibleCondition) {
  if (!EligibleCondition) {
    return;
  }
  ++Accumulator.SignalEligibleCounts[Name];
  ++Accumulator.SignalPendingCounts[Name];
}

void accumulateBatchReplayResult(BatchReplayAccumulator &Accumulator,
                                 const SyncReplayResult &Result) {
  Accumulator.MetaRecords.push_back(Result.Meta);
  Accumulator.ClusterRecords.push_back({Result.Meta, Result.Fingerprint});
  if (Result.Failed) {
    ++Accumulator.FailedCount;
  } else {
    ++Accumulator.CompletedCount;
  }

  if (Result.Triage.AnalysisState == "included") {
    ++Accumulator.IncludedCount;
  } else if (Result.Triage.AnalysisState == "excluded") {
    ++Accumulator.ExcludedCount;
  } else {
    ++Accumulator.UnknownCount;
  }
  ++Accumulator.FailurePrimaryCounts[Result.Triage.FailureBucketPrimary];
  if (Result.Triage.OracleAuditCandidate) {
    ++Accumulator.OracleAuditCount;
  }
  if (Result.Triage.DiffDetected) {
    ++Accumulator.DiffDetectedCount;
  }
  for (const auto &ResolverName : Result.ExecutedResolvers) {
    ++Accumulator.ExecutedResolverSampleCounts[ResolverName];
  }
  for (const auto &[ResolverName, Reason] : Result.SkippedResolvers) {
    (void)Reason;
    ++Accumulator.SkippedResolverSampleCounts[ResolverName];
  }
  for (const auto &Difference : Result.Triage.ResolverDifferences) {
    const std::string PairName =
        Difference.LeftResolver + "_vs_" + Difference.RightResolver;
    ++Accumulator.ResolverPairDiffCounts[PairName];
  }
}

void writeOracleAuditRow(std::ostream &OracleAudit,
                         const SyncReplayResult &Result,
                         const BatchReplayRowData &RowData) {
  OracleAudit << Result.Identity.SampleId << '\t'
              << Result.Triage.AnalysisState << '\t'
              << Result.Triage.Status << '\t'
              << Result.Triage.SemanticOutcome << '\t'
              << (Result.Triage.OracleAuditCandidate ? "true" : "false")
              << '\t'
              << (Result.Triage.CaseStudyCandidate ? "true" : "false")
              << '\t' << RowData.ExecutedResolversText << '\t'
              << compactJson(RowData.SkippedResolversJson) << '\t'
              << (Result.Triage.DiffDetected ? "true" : "false") << '\t'
              << compactJson(RowData.ResolverDiffsJson) << '\t'
              << (RowData.ResponseAcceptedAny ? "true" : "false") << '\t'
              << (RowData.SecondQueryHitAny ? "true" : "false") << '\t'
              << (RowData.CacheEntryCreatedAny ? "true" : "false") << '\t'
              << compactJson(dnslab::json::Value(RowData.ResponseAcceptedByResolver))
              << '\t'
              << compactJson(dnslab::json::Value(RowData.SecondQueryHitByResolver))
              << '\t'
              << compactJson(dnslab::json::Value(RowData.CacheEntryCreatedByResolver))
              << '\n';
}

void writeFailureTaxonomyRow(std::ostream &FailureTaxonomy,
                             const SyncReplayResult &Result) {
  FailureTaxonomy << Result.Identity.SampleId << '\t'
                  << Result.Triage.FailureBucketPrimary << '\t'
                  << Result.Triage.FailureBucketDetail << '\t'
                  << Result.Triage.AnalysisState << '\t'
                  << Result.Triage.ExcludeReason.value_or("_") << '\t'
                  << Result.Triage.SemanticOutcome << '\n';
}

dnslab::json::Value::Object
buildBatchOracleReliabilityPayload(const BatchReplayAccumulator &Accumulator) {
  const auto signalCount =
      [](const std::map<std::string, int> &Counts, const std::string &Name) {
        const auto Found = Counts.find(Name);
        return static_cast<std::int64_t>(Found == Counts.end() ? 0 : Found->second);
      };
  dnslab::json::Value::Object OracleReliability;
  dnslab::json::Value::Object Signals;
  for (const auto &SignalName : {"response_accepted_any", "second_query_hit_any",
                                 "cache_entry_created_any", "oracle_diff_any"}) {
    dnslab::json::Value::Object Bucket;
    Bucket["eligible_count"] =
        signalCount(Accumulator.SignalEligibleCounts, SignalName);
    Bucket["pending_manual_count"] =
        signalCount(Accumulator.SignalPendingCounts, SignalName);
    Bucket["judged_count"] = static_cast<std::int64_t>(0);
    Bucket["confirmed_relevant_count"] = static_cast<std::int64_t>(0);
    Bucket["false_positive_count"] = static_cast<std::int64_t>(0);
    Bucket["inconclusive_count"] = static_cast<std::int64_t>(0);
    Signals[SignalName] = Bucket;
  }
  dnslab::json::Value::Object SignalCombos;
  dnslab::json::Value::Object ComboBucket;
  ComboBucket["eligible_count"] =
      signalCount(Accumulator.SignalEligibleCounts,
                  "oracle_diff_plus_cache_diff");
  ComboBucket["pending_manual_count"] =
      signalCount(Accumulator.SignalPendingCounts,
                  "oracle_diff_plus_cache_diff");
  ComboBucket["judged_count"] = static_cast<std::int64_t>(0);
  ComboBucket["confirmed_relevant_count"] = static_cast<std::int64_t>(0);
  ComboBucket["false_positive_count"] = static_cast<std::int64_t>(0);
  ComboBucket["inconclusive_count"] = static_cast<std::int64_t>(0);
  SignalCombos["oracle_diff_plus_cache_diff"] = ComboBucket;
  OracleReliability["signals"] = Signals;
  OracleReliability["signal_combos"] = SignalCombos;
  return OracleReliability;
}

dnslab::json::Value::Object buildBatchSummaryPayload(
    const BatchReplayAccumulator &Accumulator, const std::string &SecondaryResolver,
    size_t SampleCount, size_t ClusterCount, size_t ManifestSize,
    size_t ReproducedCount, double ReproRate,
    const dnslab::RunComparabilityPayload &Comparability) {
  dnslab::json::Value::Object Summary;
  Summary["generated_at"] = dnslab::utcTimestampNow();
  Summary["status"] =
      Accumulator.FailedCount == 0 ? "success" : "partial_failure";
  Summary["compatibility_secondary_resolver"] = SecondaryResolver;
  Summary["sample_count"] = static_cast<std::int64_t>(SampleCount);
  Summary["completed_count"] =
      static_cast<std::int64_t>(Accumulator.CompletedCount);
  Summary["failed_count"] = static_cast<std::int64_t>(Accumulator.FailedCount);
  Summary["diff_detected_sample_count"] =
      static_cast<std::int64_t>(Accumulator.DiffDetectedCount);
  dnslab::json::Value::Object AnalysisStateCounts;
  AnalysisStateCounts["included"] =
      static_cast<std::int64_t>(Accumulator.IncludedCount);
  AnalysisStateCounts["excluded"] =
      static_cast<std::int64_t>(Accumulator.ExcludedCount);
  AnalysisStateCounts["unknown"] =
      static_cast<std::int64_t>(Accumulator.UnknownCount);
  Summary["analysis_state"] = AnalysisStateCounts;
  dnslab::json::Value::Array ExecutedResolversSummary;
  for (const auto &[ResolverName, Count] :
       Accumulator.ExecutedResolverSampleCounts) {
    (void)Count;
    ExecutedResolversSummary.emplace_back(ResolverName);
  }
  Summary["executed_resolvers"] = ExecutedResolversSummary;
  dnslab::json::Value::Object ExecutedResolverCounts;
  for (const auto &[ResolverName, Count] :
       Accumulator.ExecutedResolverSampleCounts) {
    ExecutedResolverCounts[ResolverName] = static_cast<std::int64_t>(Count);
  }
  Summary["executed_resolver_sample_counts"] =
      dnslab::json::Value(ExecutedResolverCounts);
  dnslab::json::Value::Object SkippedResolverCounts;
  for (const auto &[ResolverName, Count] :
       Accumulator.SkippedResolverSampleCounts) {
    SkippedResolverCounts[ResolverName] = static_cast<std::int64_t>(Count);
  }
  Summary["skipped_resolver_sample_counts"] =
      dnslab::json::Value(SkippedResolverCounts);
  dnslab::json::Value::Object ResolverDiffCounts;
  for (const auto &[ResolverPair, Count] :
       Accumulator.ResolverPairDiffCounts) {
    ResolverDiffCounts[ResolverPair] = static_cast<std::int64_t>(Count);
  }
  Summary["resolver_pair_diff_counts"] =
      dnslab::json::Value(ResolverDiffCounts);
  Summary["oracle_audit_candidate_count"] =
      static_cast<std::int64_t>(Accumulator.OracleAuditCount);
  Summary["case_study_candidate_count"] =
      static_cast<std::int64_t>(Accumulator.CaseStudyCount);
  Summary["cluster_count"] = static_cast<std::int64_t>(ClusterCount);
  Summary["contract_version"] = dnslab::kContractVersion;
  Summary["manifest_size"] = static_cast<std::int64_t>(ManifestSize);
  Summary["reproduced_count"] = static_cast<std::int64_t>(ReproducedCount);
  Summary["repro_rate"] = ReproRate;
  Summary["comparability"] = dnslab::toJson(Comparability);
  return Summary;
}

void writeBatchAblationMatrix(const std::filesystem::path &RunRoot) {
  std::ofstream AblationMatrix(RunRoot / "ablation_matrix.tsv");
  AblationMatrix << "module\tstatus\n";
  AblationMatrix << "mutator\ton\n";
  AblationMatrix << "cache-delta\ton\n";
  AblationMatrix << "triage\ton\n";
  AblationMatrix << "symcc\ton\n";
}

void writeBatchClusterCounts(
    const std::filesystem::path &RunRoot,
    const std::vector<dnslab::ClusterSummary> &Clusters) {
  std::ofstream ClusterCounts(RunRoot / "cluster_counts.tsv");
  ClusterCounts << "cluster_key\tcount\n";
  if (Clusters.empty()) {
    ClusterCounts << "_\t0\n";
    return;
  }
  for (const auto &Cluster : Clusters) {
    ClusterCounts << Cluster.ClusterKey << '\t' << Cluster.SampleCount << '\n';
  }
}

void writeBatchExclusionSummary(const std::filesystem::path &RunRoot,
                                const BatchReplayAccumulator &Accumulator,
                                size_t SampleCount) {
  std::ofstream ExclusionSummary(RunRoot / "exclusion_summary.tsv");
  ExclusionSummary << "failure_bucket_primary\tanalysis_state\tcount\n";
  const auto failureCount =
      [&](const std::string &Primary) {
        const auto Found = Accumulator.FailurePrimaryCounts.find(Primary);
        return Found == Accumulator.FailurePrimaryCounts.end() ? 0
                                                               : Found->second;
      };
  const std::vector<std::pair<std::string, std::string>> FailureOrder = {
      {"semantic_diff", "included"},
      {"valid_negative", "included"},
      {"input_parse_failure", "unknown"},
      {"infra_artifact_failure", "excluded"},
      {"orchestrator_compat_failure", "excluded"},
      {"target_runtime_failure", "unknown"},
  };
  for (const auto &[Primary, AnalysisState] : FailureOrder) {
    ExclusionSummary << Primary << '\t' << AnalysisState << '\t'
                     << failureCount(Primary) << '\n';
  }
  ExclusionSummary << "__total__\t-\t" << SampleCount << '\n';
}

void writeBatchReproRate(const std::filesystem::path &RunRoot,
                         size_t ManifestSize, size_t ReproducedCount,
                         double ReproRate) {
  std::ofstream ReproRateFile(RunRoot / "repro_rate.tsv");
  ReproRateFile << "metric\tvalue\n";
  ReproRateFile << "manifest_size\t" << ManifestSize << '\n';
  ReproRateFile << "reproduced_count\t" << ReproducedCount << '\n';
  ReproRateFile << "repro_rate\t" << ReproRate << '\n';
}

std::vector<dnslab::ReportArtifact>
buildBatchReportArtifacts(const std::filesystem::path &RunRoot,
                          const std::string &BatchSyncReplayCommand) {
  return {
      {"summary", (RunRoot / "summary.json").string(), BatchSyncReplayCommand},
      {"ablation_matrix", (RunRoot / "ablation_matrix.tsv").string(),
       BatchSyncReplayCommand},
      {"cluster_counts", (RunRoot / "cluster_counts.tsv").string(),
       BatchSyncReplayCommand},
      {"repro_rate", (RunRoot / "repro_rate.tsv").string(),
       BatchSyncReplayCommand},
      {"oracle_audit", (RunRoot / "oracle_audit.tsv").string(),
       BatchSyncReplayCommand},
      {"oracle_reliability", (RunRoot / "oracle_reliability.json").string(),
       BatchSyncReplayCommand},
      {"failure_taxonomy", (RunRoot / "failure_taxonomy.tsv").string(),
       BatchSyncReplayCommand},
      {"exclusion_summary", (RunRoot / "exclusion_summary.tsv").string(),
       BatchSyncReplayCommand},
      {"cluster", (RunRoot / "cluster.tsv").string(), BatchSyncReplayCommand},
      {"case_studies_index", (RunRoot / "case_studies/index.tsv").string(),
       BatchSyncReplayCommand},
  };
}

std::filesystem::path resolveCommandWorkspaceRoot(
    const std::vector<std::string> &Args,
    const std::filesystem::path &DefaultWorkspaceRoot);
std::filesystem::path resolveCommandLockFilePath(
    const std::vector<std::string> &Args,
    const std::filesystem::path &DefaultLockPath);
std::optional<std::string> resolveCommandOptionalText(
    const std::vector<std::string> &Args, const std::string &OptionName);
std::optional<std::filesystem::path> resolveCommandOptionalPath(
    const std::vector<std::string> &Args, const std::string &OptionName);
std::filesystem::path resolveAdapterSourceRootForWorkspace(
    const std::vector<std::string> &CommandArgs,
    const std::filesystem::path &WorkspaceRoot,
    const std::optional<dnslab::ResolverLockFile> &DefaultResolverLock,
    const std::string &ResolverName,
    const std::filesystem::path &BuildRoot);
AdapterCommandContext buildAdapterCommandContext(
    const std::vector<std::string> &CommandArgs,
    const std::filesystem::path &WorkspaceRoot,
    const std::optional<dnslab::ResolverLockFile> &DefaultResolverLock,
    const dnslab::ResolverRegistry &RuntimeRegistry);

int runAdapterBuildCommand(const AdapterCommandContext &Context) {
  const auto BuildResult =
      Context.Adapter->build(Context.SourceRoot, Context.BuildRoot);
  const auto Output = buildAdapterCommandOutput(
      Context.ResolverName, Context.SourceRoot, Context.BuildRoot, BuildResult);
  printJsonValue(dnslab::json::Value(Output));
  return BuildResult.ExitCode;
}

template <typename SetResolverBuildEnvFn>
int runAdapterDumpCacheCommand(const std::vector<std::string> &Args,
                               const AdapterCommandContext &Context,
                               SetResolverBuildEnvFn SetResolverBuildEnv) {
  const auto RunRoot = requireCommandPath(Args, "--run-root");
  std::optional<std::filesystem::path> SamplePath;
  std::optional<std::filesystem::path> OutputFile;
  for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
    if (Args[Index] == "--sample") {
      SamplePath = normalizePath(Args[Index + 1]);
    } else if (Args[Index] == "--output-file") {
      OutputFile = normalizePath(Args[Index + 1]);
    }
  }

  std::filesystem::create_directories(RunRoot);
  SetResolverBuildEnv(Context.ResolverName, Context.BuildRoot);

  dnslab::CommandResult DumpResult;
  std::filesystem::path EffectiveOutput;
  if (SamplePath.has_value()) {
    const auto SampleBytes = readBinaryFile(*SamplePath);
    const auto SampleIdentity = dnslab::buildSampleIdentity(
        SamplePath->filename().string(), SampleBytes);
    DumpResult = Context.Adapter->runSample(
        {Context.SourceRoot, Context.BuildRoot, RunRoot, *SamplePath,
         SampleIdentity.SampleId, {}});
    EffectiveOutput = RunRoot / (Context.ResolverName + ".after.cache.txt");
  } else {
    EffectiveOutput = OutputFile.value_or(
        RunRoot / (Context.ResolverName + ".before.cache.txt"));
    DumpResult = Context.Adapter->dumpCache(RunRoot, EffectiveOutput);
  }

  if (OutputFile.has_value() && EffectiveOutput != *OutputFile &&
      std::filesystem::is_regular_file(EffectiveOutput)) {
    std::filesystem::create_directories(OutputFile->parent_path());
    std::filesystem::copy_file(EffectiveOutput, *OutputFile,
                               std::filesystem::copy_options::overwrite_existing);
    EffectiveOutput = *OutputFile;
  }

  const auto Output = buildAdapterCommandOutput(
      Context.ResolverName, Context.SourceRoot, Context.BuildRoot, DumpResult,
      RunRoot, SamplePath, EffectiveOutput);
  printJsonValue(dnslab::json::Value(Output));
  return DumpResult.ExitCode;
}

template <typename SetResolverBuildEnvFn>
int runAdapterReplayCommand(const std::vector<std::string> &Args,
                            const AdapterCommandContext &Context,
                            SetResolverBuildEnvFn SetResolverBuildEnv) {
  const auto RunRoot = requireCommandPath(Args, "--run-root");
  const auto SamplePath = requireCommandPath(Args, "--sample");
  std::filesystem::create_directories(RunRoot);
  SetResolverBuildEnv(Context.ResolverName, Context.BuildRoot);

  const auto BeforeCache = RunRoot / (Context.ResolverName + ".before.cache.txt");
  const auto DumpResult = Context.Adapter->dumpCache(RunRoot, BeforeCache);
  if (DumpResult.ExitCode != 0) {
    std::cerr << "adapter dump-cache 失败\n";
    return DumpResult.ExitCode;
  }

  const auto RunResult = Context.Adapter->runSample(
      {Context.SourceRoot, Context.BuildRoot, RunRoot, SamplePath,
       SamplePath.filename().string(), {}});
  const auto Oracle =
      Context.Adapter->parseOracle(RunRoot / (Context.ResolverName + ".stderr"));

  ResolverRunResult ReplayResultRow;
  ReplayResultRow.DumpResult = DumpResult;
  ReplayResultRow.RunResult = RunResult;
  ReplayResultRow.Oracle = Oracle;
  ReplayResultRow.BeforeCache = BeforeCache;
  ReplayResultRow.AfterCache = RunRoot / (Context.ResolverName + ".after.cache.txt");
  ReplayResultRow.StderrPath = RunRoot / (Context.ResolverName + ".stderr");
  ReplayResultRow.Logs = Context.Adapter->collectLogs(RunRoot);
  const auto Output =
      buildAdapterReplayOutput(Context.ResolverName, ReplayResultRow);
  printJsonValue(dnslab::json::Value(Output));
  return RunResult.ExitCode;
}

int runSyncReplayCliCommand(
    const std::vector<std::string> &Args,
    const std::filesystem::path &WorkspaceRoot,
    const std::optional<dnslab::ResolverLockFile> &DefaultResolverLock,
    const dnslab::ResolverRegistry &RuntimeRegistry) {
  const auto SamplePath = requireCommandPath(Args, "--sample");
  const auto RunRoot = requireCommandPath(Args, "--run-root");
  const auto QueueEventId = optionalOption(Args, "--queue-event-id");
  const auto Context =
      resolveSyncReplayCommandContext(Args, WorkspaceRoot, DefaultResolverLock);

  const auto ReplayResult = executeSyncReplay(
      WorkspaceRoot, DefaultResolverLock, RuntimeRegistry, SamplePath, RunRoot,
      false, Context.Bind9BuildRoot, Context.SecondaryBuildRoot,
      Context.Bind9SourceRoot, Context.SecondarySourceRoot,
      Context.SecondaryResolverName, Context.RequestedResolversCsv,
      QueueEventId);

  const auto Output = buildSyncReplayCliOutput(ReplayResult);
  printJsonValue(dnslab::json::Value(Output));
  return ReplayResult.ExitCode;
}

int runBatchSyncReplayCommand(
    const std::vector<std::string> &Args,
    const std::string &SelfExecutableCommand,
    const std::filesystem::path &WorkspaceRoot,
    const std::optional<dnslab::ResolverLockFile> &DefaultResolverLock,
    const dnslab::ResolverRegistry &RuntimeRegistry) {
  const auto SampleDir = requireCommandPath(Args, "--sample-dir");
  const auto RunRoot = requireCommandPath(Args, "--run-root");
  const auto Context =
      resolveSyncReplayCommandContext(Args, WorkspaceRoot, DefaultResolverLock);
  std::optional<size_t> Limit;
  for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
    if (Args[Index] == "--limit") {
      Limit = static_cast<size_t>(std::stoul(Args[Index + 1]));
    }
  }

  if (!std::filesystem::is_directory(SampleDir)) {
    throw std::runtime_error("sample-dir 不是目录: " + SampleDir.string());
  }

  std::vector<std::filesystem::path> Samples;
  for (const auto &Entry : std::filesystem::directory_iterator(SampleDir)) {
    if (Entry.is_regular_file()) {
      Samples.push_back(Entry.path());
    }
  }
  std::sort(Samples.begin(), Samples.end());
  if (Limit.has_value() && *Limit < Samples.size()) {
    Samples.resize(*Limit);
  }

  std::filesystem::create_directories(RunRoot / "samples");
  std::filesystem::create_directories(RunRoot / "case_studies");

  std::vector<SyncReplayResult> Results;
  Results.reserve(Samples.size());
  for (const auto &SamplePath : Samples) {
    Results.push_back(executeSyncReplay(
        WorkspaceRoot, DefaultResolverLock, RuntimeRegistry, SamplePath,
        RunRoot / "samples", true, Context.Bind9BuildRoot,
        Context.SecondaryBuildRoot, Context.Bind9SourceRoot,
        Context.SecondarySourceRoot, Context.SecondaryResolverName,
        Context.RequestedResolversCsv));
  }

  std::ofstream OracleAudit(RunRoot / "oracle_audit.tsv");
  OracleAudit
      << "sample_id\tanalysis_state\tstatus\tsemantic_outcome\toracle_audit_candidate\tcase_study_candidate\texecuted_resolvers\tskipped_resolvers_json\tdiff_detected\tresolver_diffs_json\tresponse_accepted_any\tsecond_query_hit_any\tcache_entry_created_any\tresponse_accepted_by_resolver_json\tsecond_query_hit_by_resolver_json\tcache_entry_created_by_resolver_json\n";

  std::ofstream FailureTaxonomy(RunRoot / "failure_taxonomy.tsv");
  FailureTaxonomy
      << "sample_id\tfailure_bucket_primary\tfailure_bucket_detail\tanalysis_state\texclude_reason\tsemantic_outcome\n";

  std::ofstream ClusterFile(RunRoot / "cluster.tsv");
  ClusterFile
      << "cluster_key\tanalysis_state\tresolver_pair\tvariant_name\tfingerprint_key\tsample_count\tsample_ids\n";

  std::ofstream CaseStudyIndex(RunRoot / "case_studies" / "index.tsv");
  CaseStudyIndex
      << "sample_id\tsemantic_outcome\tselection_reason\tcase_study_path\treplay_command\texecuted_resolvers\tdiff_detected\tresolver_diffs_json\n";

  BatchReplayAccumulator Accumulator;

  for (const auto &Result : Results) {
    accumulateBatchReplayResult(Accumulator, Result);
    const auto RowData = buildBatchReplayRowData(Result);

    if (Result.Triage.CaseStudyCandidate) {
      ++Accumulator.CaseStudyCount;
      const auto CaseStudyPath =
          RunRoot / "case_studies" / (Result.Identity.SampleId + ".md");
      const auto ReplayCommand = buildSyncReplayReplayCommand(
          SelfExecutableCommand, Result.Meta.SourceQueueFile.value_or("_"),
          Result.ArtifactDir, Context.Bind9BuildRoot, Context.SecondaryBuildRoot,
          Result.SecondaryResolver, Result.ResolverBuildRoots,
          Result.ResolverSourceRoots, Result.ExecutedResolvers);
      writeCaseStudyMarkdown(CaseStudyPath, Result, ReplayCommand);
      appendCaseStudyIndexRow(CaseStudyIndex, Result, CaseStudyPath,
                              ReplayCommand);
    }

    updateBatchReplaySignal(Accumulator, "response_accepted_any",
                            RowData.OracleEligible &&
                                RowData.ResponseAcceptedAny);
    updateBatchReplaySignal(Accumulator, "second_query_hit_any",
                            RowData.OracleEligible &&
                                RowData.SecondQueryHitAny);
    updateBatchReplaySignal(Accumulator, "cache_entry_created_any",
                            RowData.OracleEligible &&
                                RowData.CacheEntryCreatedAny);
    updateBatchReplaySignal(Accumulator, "oracle_diff_any",
                            RowData.OracleEligible &&
                                RowData.OracleDiffAny);
    updateBatchReplaySignal(Accumulator, "oracle_diff_plus_cache_diff",
                            RowData.OracleEligible &&
                                RowData.OracleDiffAny &&
                                RowData.CacheDiffAny);

    writeOracleAuditRow(OracleAudit, Result, RowData);
    writeFailureTaxonomyRow(FailureTaxonomy, Result);
  }

  const auto Comparability =
      dnslab::buildRunComparabilityPayload(Accumulator.MetaRecords);
  const auto Clusters =
      dnslab::clusterByFingerprint(Accumulator.ClusterRecords);
  for (const auto &Cluster : Clusters) {
    std::string SampleIds;
    for (size_t Index = 0; Index < Cluster.SampleIds.size(); ++Index) {
      if (Index != 0) {
        SampleIds.push_back(',');
      }
      SampleIds += Cluster.SampleIds[Index];
    }
    ClusterFile << Cluster.ClusterKey << '\t'
                << dnslab::toString(Cluster.State) << '\t'
                << Cluster.ResolverPair.value_or("_") << '\t'
                << Cluster.VariantName.value_or("_") << '\t'
                << Cluster.FingerprintKey << '\t'
                << Cluster.SampleCount << '\t' << SampleIds << '\n';
  }

  const size_t ManifestSize = Results.size();
  const size_t ReproducedCount = Accumulator.CompletedCount;
  const double ReproRate =
      ManifestSize == 0 ? 0.0
                        : static_cast<double>(ReproducedCount) /
                              static_cast<double>(ManifestSize);
  writeBatchAblationMatrix(RunRoot);
  writeBatchClusterCounts(RunRoot, Clusters);
  writeBatchExclusionSummary(RunRoot, Accumulator, Results.size());
  writeBatchReproRate(RunRoot, ManifestSize, ReproducedCount, ReproRate);

  const auto OracleReliability = buildBatchOracleReliabilityPayload(Accumulator);
  writeJsonFile(RunRoot / "oracle_reliability.json",
                dnslab::json::Value(OracleReliability));

  const auto Summary = buildBatchSummaryPayload(
      Accumulator, Context.SecondaryResolverName, Results.size(),
      Clusters.size(), ManifestSize, ReproducedCount, ReproRate, Comparability);
  writeJsonFile(RunRoot / "summary.json", dnslab::json::Value(Summary));

  const auto BatchSyncReplayCommand =
      SelfExecutableCommand + " batch-sync-replay";
  auto Artifacts = buildBatchReportArtifacts(RunRoot, BatchSyncReplayCommand);
  const auto Bundle = dnslab::buildEvidenceBundle(
      std::optional<std::string>("manual-batch"), std::nullopt, Comparability,
      Clusters, Artifacts);
  writeJsonFile(RunRoot / "evidence_bundle.json", dnslab::toJson(Bundle));

  dnslab::json::Value::Object Output;
  Output["run_root"] = normalizePath(RunRoot).string();
  Output["sample_count"] = static_cast<std::int64_t>(Results.size());
  Output["summary"] = Summary;
  Output["evidence_bundle"] =
      normalizePath(RunRoot / "evidence_bundle.json").string();
  printJsonValue(dnslab::json::Value(Output));
  return Accumulator.FailedCount == 0 ? 0 : 4;
}

int runLockGenerateCommand(const std::vector<std::string> &Args) {
  const auto Manifest =
      dnslab::loadResolverManifestTsv(requireCommandPath(Args, "--manifest"));
  const auto LockFile =
      dnslab::generateResolverLockFile(Manifest, dnslab::runCommand);
  dnslab::writeResolverLockFile(requireCommandPath(Args, "--output"), LockFile);
  printJsonValue(dnslab::toJson(LockFile));
  return 0;
}

int runLockResolvedTagCommand(const std::vector<std::string> &Args,
                              const std::filesystem::path &WorkspaceRoot) {
  const auto ResolverName = requireOption(Args, "--resolver");
  const auto LockPath = resolveCommandLockFilePath(
      Args, dnslab::defaultResolverLockFilePath(WorkspaceRoot));
  const auto LockFile = dnslab::loadResolverLockFileJson(LockPath);
  const auto Tag = dnslab::resolveLockedTag(LockFile, ResolverName);
  if (!Tag.has_value()) {
    std::cerr << "resolver 未在 lock 中找到或缺少 tag\n";
    return 1;
  }
  std::cout << *Tag << '\n';
  return 0;
}

std::filesystem::path resolveCommandWorkspaceRoot(
    const std::vector<std::string> &Args,
    const std::filesystem::path &DefaultWorkspaceRoot) {
  for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
    if (Args[Index] == "--workspace-root") {
      return normalizePath(Args[Index + 1]);
    }
  }
  return normalizePath(DefaultWorkspaceRoot);
}

std::filesystem::path resolveCommandLockFilePath(
    const std::vector<std::string> &Args,
    const std::filesystem::path &DefaultLockPath) {
  for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
    if (Args[Index] == "--lock-file") {
      return normalizePath(Args[Index + 1]);
    }
  }
  return normalizePath(DefaultLockPath);
}

std::optional<std::string> resolveCommandOptionalText(
    const std::vector<std::string> &Args, const std::string &OptionName) {
  return optionalOption(Args, OptionName);
}

std::optional<std::filesystem::path> resolveCommandOptionalPath(
    const std::vector<std::string> &Args, const std::string &OptionName) {
  const auto Value = optionalOption(Args, OptionName);
  if (!Value.has_value()) {
    return std::nullopt;
  }
  return normalizePath(*Value);
}

std::filesystem::path resolveAdapterSourceRootForWorkspace(
    const std::vector<std::string> &CommandArgs,
    const std::filesystem::path &WorkspaceRoot,
    const std::optional<dnslab::ResolverLockFile> &DefaultResolverLock,
    const std::string &ResolverName,
    const std::filesystem::path &BuildRoot) {
  return resolveSourceRootOverride(
      CommandArgs, "--source-root",
      resolveDefaultSourceRootForWorkspace(WorkspaceRoot, DefaultResolverLock,
                                          ResolverName, BuildRoot));
}

AdapterCommandContext buildAdapterCommandContext(
    const std::vector<std::string> &CommandArgs,
    const std::filesystem::path &WorkspaceRoot,
    const std::optional<dnslab::ResolverLockFile> &DefaultResolverLock,
    const dnslab::ResolverRegistry &RuntimeRegistry) {
  AdapterCommandContext Context;
  Context.ResolverName = requireOption(CommandArgs, "--resolver");
  Context.BuildRoot = requireCommandPath(CommandArgs, "--build-root");
  Context.SourceRoot = resolveAdapterSourceRootForWorkspace(
      CommandArgs, WorkspaceRoot, DefaultResolverLock, Context.ResolverName,
      Context.BuildRoot);
  Context.Adapter = &RuntimeRegistry.require(Context.ResolverName);
  return Context;
}

std::optional<std::string>
resolveResolverTagForCommand(const std::filesystem::path &LockPath,
                             const std::string &ResolverName,
                             const std::optional<std::string> &ExplicitTag) {
  if (ExplicitTag.has_value()) {
    return ExplicitTag;
  }
  const auto LockFile = dnslab::loadResolverLockFileJson(LockPath);
  return dnslab::resolveLockedTag(LockFile, ResolverName);
}

dnslab::json::Value::Object buildSubjectCommandOutput(
    const std::string &ResolverName, const std::string &Tag,
    const std::filesystem::path &SubjectRoot) {
  dnslab::json::Value::Object Output;
  Output["resolver"] = ResolverName;
  Output["tag"] = Tag;
  Output["subject_root"] = SubjectRoot.string();
  return Output;
}

dnslab::json::Value::Object buildExportPatchOutput(
    const std::string &ResolverName, const std::string &Purpose,
    const std::string &Tag, const std::filesystem::path &SourceRoot,
    const std::filesystem::path &OutputPath,
    std::int64_t PatchBytes) {
  dnslab::json::Value::Object Output;
  Output["resolver"] = ResolverName;
  Output["purpose"] = Purpose;
  Output["tag"] = Tag;
  Output["source_root"] = SourceRoot.string();
  Output["output_path"] = OutputPath.string();
  Output["patch_bytes"] = PatchBytes;
  return Output;
}

void printUsage();

int runPrepareSubjectCommand(const std::vector<std::string> &Args,
                             const std::filesystem::path &WorkspaceRoot) {
  const auto WorkspacePath =
      resolveCommandWorkspaceRoot(Args, WorkspaceRoot);
  const auto LockPath = resolveCommandLockFilePath(
      Args, dnslab::defaultResolverLockFilePath(WorkspaceRoot));
  const auto ExplicitTag = resolveCommandOptionalText(Args, "--tag");
  const auto ResolverName = requireOption(Args, "--resolver");
  const auto Tag =
      resolveResolverTagForCommand(LockPath, ResolverName, ExplicitTag);
  if (!Tag.has_value()) {
    std::cerr << "resolver 未在 lock 中找到或缺少 tag\n";
    return 1;
  }
  const auto Registry = dnslab::makeDefaultResolverRegistry(WorkspacePath);
  const auto &Adapter = Registry.require(ResolverName);
  const auto SubjectRoot = Adapter.prepareSource(WorkspacePath, *Tag);
  const auto Output =
      buildSubjectCommandOutput(ResolverName, *Tag, SubjectRoot);
  printJsonValue(dnslab::json::Value(Output));
  return 0;
}

int runPrepareSubjectsCommand(const std::vector<std::string> &Args,
                              const std::filesystem::path &WorkspaceRoot) {
  const auto WorkspacePath =
      resolveCommandWorkspaceRoot(Args, WorkspaceRoot);
  const auto LockPath = resolveCommandLockFilePath(
      Args, dnslab::defaultResolverLockFilePath(WorkspaceRoot));
  const auto ResolverCsv = resolveCommandOptionalText(Args, "--resolvers");

  std::set<std::string> RequestedResolvers;
  if (ResolverCsv.has_value()) {
    std::stringstream Stream(*ResolverCsv);
    std::string Token;
    while (std::getline(Stream, Token, ',')) {
      if (!Token.empty()) {
        RequestedResolvers.insert(Token);
      }
    }
  }

  const auto LockFile = dnslab::loadResolverLockFileJson(LockPath);
  const auto Registry = dnslab::makeDefaultResolverRegistry(WorkspacePath);
  dnslab::json::Value::Array Output;
  for (const auto &Entry : LockFile.Resolvers) {
    if (!RequestedResolvers.empty() &&
        !RequestedResolvers.count(Entry.Resolver)) {
      continue;
    }
    const auto Tag = Entry.ResolvedTag.value_or(Entry.DesiredTag);
    if (Tag.empty()) {
      std::cerr << "resolver 缺少 tag: " << Entry.Resolver << '\n';
      return 1;
    }
    const auto &Adapter = Registry.require(Entry.Resolver);
    const auto SubjectRoot = Adapter.prepareSource(WorkspacePath, Tag);
    Output.emplace_back(buildSubjectCommandOutput(Entry.Resolver, Tag,
                                                 SubjectRoot));
  }
  printJsonValue(dnslab::json::Value(Output));
  return 0;
}

int runExportPatchCommand(const std::vector<std::string> &Args,
                          const std::filesystem::path &WorkspaceRoot) {
  const auto WorkspacePath =
      resolveCommandWorkspaceRoot(Args, WorkspaceRoot);
  const auto LockPath = resolveCommandLockFilePath(
      Args, dnslab::defaultResolverLockFilePath(WorkspaceRoot));
  const auto ExplicitTag = resolveCommandOptionalText(Args, "--tag");
  const auto ExplicitSourceRoot =
      resolveCommandOptionalPath(Args, "--source-root");
  const auto ExplicitOutputPath =
      resolveCommandOptionalPath(Args, "--output");
  const auto ResolverName = requireOption(Args, "--resolver");
  const auto Purpose = requireOption(Args, "--purpose");
  const auto Tag =
      resolveResolverTagForCommand(LockPath, ResolverName, ExplicitTag);
  if (!Tag.has_value()) {
    std::cerr << "resolver 未在 lock 中找到或缺少 tag\n";
    return 1;
  }
  const auto SourceRoot =
      ExplicitSourceRoot.value_or(
          dnslab::defaultSubjectRoot(WorkspacePath, ResolverName, *Tag));
  const auto OutputPath = ExplicitOutputPath.value_or(
      dnslab::patchPathFor(WorkspacePath / "patch", Purpose, ResolverName, *Tag));
  std::filesystem::create_directories(OutputPath.parent_path());
  const auto Diff = dnslab::runCommand(
      {"git", "-C", SourceRoot.string(), "diff", "--binary"});
  if (Diff.ExitCode != 0) {
    std::cerr << "git diff 导出 patch 失败\n";
    return Diff.ExitCode;
  }
  std::ofstream OutputFile(OutputPath);
  if (!OutputFile) {
    throw std::runtime_error("无法写入 patch 文件: " + OutputPath.string());
  }
  OutputFile << Diff.StdoutText;
  const auto Output = buildExportPatchOutput(
      ResolverName, Purpose, *Tag, SourceRoot, OutputPath,
      static_cast<std::int64_t>(Diff.StdoutText.size()));
  printJsonValue(dnslab::json::Value(Output));
  return 0;
}

std::optional<std::filesystem::path> resolveHighValueManifestArg(
    const std::vector<std::string> &Args) {
  const auto Option = resolveCommandOptionalPath(Args, "--high-value-manifest");
  if (Option.has_value()) {
    return Option;
  }
  if (const char *EnvManifest = std::getenv("SYMCC_HIGH_VALUE_MANIFEST")) {
    if (*EnvManifest != '\0') {
      return std::filesystem::path(EnvManifest);
    }
  }
  return std::nullopt;
}

int runReportCommand(const std::vector<std::string> &Args) {
  const auto Root = requireCommandPath(Args, "--root");
  const auto HighValueManifestPath = resolveHighValueManifestArg(Args);
  const auto Artifacts =
      dnslab::generateTriageReportArtifacts(Root, HighValueManifestPath);
  printJsonValue(dnslab::toJson(Artifacts));
  return 0;
}

int runCampaignReportCommand(const std::vector<std::string> &Args) {
  const auto Root = requireCommandPath(Args, "--root");
  const auto OutputDir = resolveCommandOptionalPath(Args, "--output-dir");
  const auto Artifacts =
      dnslab::generateCampaignReportArtifacts(Root, OutputDir);
  printJsonValue(dnslab::toJson(Artifacts));
  return 0;
}

size_t resolveCaseStudyTopN(const std::vector<std::string> &Args) {
  if (const auto Option = optionalOption(Args, "--top-n")) {
    const auto Parsed = std::stoll(*Option);
    if (Parsed < 0) {
      throw std::runtime_error("--top-n 不能为负数: " + *Option);
    }
    return static_cast<size_t>(Parsed);
  }
  return 5;
}

int runCaseStudyExportCommand(const std::vector<std::string> &Args) {
  const auto Root = requireCommandPath(Args, "--root");
  const auto ReportDir = requireCommandPath(Args, "--campaign-report-dir");
  const auto TopN = resolveCaseStudyTopN(Args);
  const auto Artifacts = dnslab::exportCaseStudies(Root, ReportDir, TopN);
  printJsonValue(dnslab::toJson(Artifacts));
  return 0;
}

dnslab::ReportArtifact buildEvidenceBundleArtifactCommand(
    const std::vector<std::string> &Args, const std::string &Kind,
    const std::string &PathArg, const std::string &CmdArg) {
  dnslab::ReportArtifact Artifact;
  Artifact.Kind = Kind;
  Artifact.Path = requireCommandPath(Args, PathArg).string();
  Artifact.RegenerateCommand = optionalOption(Args, CmdArg);
  return Artifact;
}

struct EvidenceBundleArtifactCommandSpec {
  std::string Kind;
  std::string PathArg;
  std::string CommandArg;
};

std::vector<dnslab::ReportArtifact>
buildEvidenceBundleArtifactCommands(const std::vector<std::string> &Args) {
  const std::vector<EvidenceBundleArtifactCommandSpec> Specs = {
      {"summary", "--summary", "--summary-cmd"},
      {"oracle_audit", "--oracle-audit", "--oracle-audit-cmd"},
      {"failure_taxonomy", "--failure-taxonomy", "--failure-taxonomy-cmd"},
      {"cluster", "--cluster", "--cluster-cmd"},
      {"case_studies_index", "--case-index", "--case-index-cmd"},
  };

  std::vector<dnslab::ReportArtifact> Artifacts;
  Artifacts.reserve(Specs.size());
  for (const auto &Spec : Specs) {
    Artifacts.push_back(buildEvidenceBundleArtifactCommand(
        Args, Spec.Kind, Spec.PathArg, Spec.CommandArg));
  }
  return Artifacts;
}

int runEvidenceBundleCommand(const std::vector<std::string> &Args) {
  const auto RunId = resolveCommandOptionalText(Args, "--run-id");
  const auto Artifacts = buildEvidenceBundleArtifactCommands(Args);

  const auto Bundle = dnslab::buildEvidenceBundle(
      RunId, std::nullopt, dnslab::RunComparabilityPayload{}, {}, Artifacts);
  const auto BundleJson = dnslab::toJson(Bundle);
  const auto OutputPath = requireCommandPath(Args, "--output");
  writeJsonFile(OutputPath, BundleJson);
  printJsonValue(BundleJson);
  return 0;
}

template <typename RegistryT>
int runAdapterListCommand(const RegistryT &RuntimeRegistry) {
  dnslab::json::Value::Array Names;
  for (const auto &Name : RuntimeRegistry.names()) {
    Names.emplace_back(Name);
  }
  printJsonValue(dnslab::json::Value(Names));
  return 0;
}

int runTranscriptSummaryCommand(const std::vector<std::string> &Args) {
  const auto Input = readBinaryFile(requireCommandPath(Args, "--input"));
  const auto Parsed = dnslab::parseTranscript(Input);
  if (!Parsed.has_value()) {
    std::cerr << "DST1 transcript 解析失败\n";
    return 1;
  }
  const auto Summary = dnslab::summarizeTranscript(*Parsed);
  dnslab::json::Value::Object Output;
  Output["response_count"] = static_cast<std::int64_t>(Summary.ResponseCount);
  Output["client_query_size"] =
      static_cast<std::int64_t>(Summary.ClientQuerySize);
  Output["post_check_query_size"] =
      static_cast<std::int64_t>(Summary.PostCheckQuerySize);
  Output["total_response_bytes"] =
      static_cast<std::int64_t>(Summary.TotalResponseBytes);
  Output["total_transcript_bytes"] =
      static_cast<std::int64_t>(Summary.TotalTranscriptBytes);
  printJsonValue(dnslab::json::Value(Output));
  return 0;
}

int runSampleIdCommand(const std::vector<std::string> &Args) {
  const auto Input = readBinaryFile(requireCommandPath(Args, "--input"));
  const auto Identity = dnslab::buildSampleIdentity(
      requireOption(Args, "--queue-event-id"), Input);
  dnslab::json::Value::Object Output;
  Output["queue_event_id"] = Identity.QueueEventId;
  Output["sample_sha1"] = Identity.SampleSha1;
  Output["sample_id"] = Identity.SampleId;
  Output["sample_size"] = static_cast<std::int64_t>(Identity.SampleSize);
  printJsonValue(dnslab::json::Value(Output));
  return 0;
}

int runOracleParseCommand(const std::vector<std::string> &Args) {
  const auto Parsed = dnslab::parseOracleSummary(
      readTextFile(requireCommandPath(Args, "--stderr-file")),
      requireOption(Args, "--resolver"));
  printJsonValue(dnslab::toJson(Parsed));
  return 0;
}

int runFollowDiffOnceCommand() {
  const auto Artifacts = dnslab::runFollowDiffOnce();
  printJsonValue(dnslab::toJson(Artifacts));
  return Artifacts.ExitCode;
}

int runFollowDiffWindowCommand(const std::vector<std::string> &Args) {
  const double BudgetSec = std::stod(requireOption(Args, "--budget-sec"));
  const bool RetryFailed =
      std::find(Args.begin(), Args.end(), "--retry-failed") != Args.end();
  const auto QueueTailId = optionalOption(Args, "--queue-tail-id");
  const auto Artifacts =
      dnslab::runFollowDiffWindow(BudgetSec, RetryFailed, QueueTailId);
  printJsonValue(dnslab::toJson(Artifacts));
  return Artifacts.ExitCode;
}

int runCampaignCloseCommand(const std::vector<std::string> &Args) {
  const double BudgetSec = std::stod(requireOption(Args, "--budget-sec"));
  const auto Artifacts = dnslab::runCampaignClose(BudgetSec);
  printJsonValue(dnslab::toJson(Artifacts));
  return Artifacts.ExitCode;
}

MainCommandContext buildMainCommandContext(const char *Argv0) {
  MainCommandContext Context;
  Context.WorkspaceRoot = std::filesystem::current_path();
  const auto SelfExecutablePath = resolveSelfExecutablePath(Argv0);
  Context.SelfExecutableCommand = SelfExecutablePath.string();
  if (::setenv("DNSLAB_SELF_EXECUTABLE", Context.SelfExecutableCommand.c_str(),
               1) != 0) {
    throw std::runtime_error("无法设置 DNSLAB_SELF_EXECUTABLE 环境变量");
  }
  Context.DefaultResolverLock =
      loadDefaultResolverLockIfPresent(Context.WorkspaceRoot);
  Context.RuntimeRegistry =
      dnslab::makeDefaultResolverRegistry(std::filesystem::current_path());
  return Context;
}

int dispatchCommand(const MainCommandContext &Context, const std::string &Command,
                    const std::vector<std::string> &Args) {
  if (Command == "transcript-summary") {
    return runTranscriptSummaryCommand(Args);
  }

  if (Command == "sample-id") {
    return runSampleIdCommand(Args);
  }

  if (Command == "lock-generate") {
    return runLockGenerateCommand(Args);
  }

  if (Command == "lock-resolved-tag") {
    return runLockResolvedTagCommand(Args, Context.WorkspaceRoot);
  }

  if (Command == "prepare-subject") {
    return runPrepareSubjectCommand(Args, Context.WorkspaceRoot);
  }

  if (Command == "prepare-subjects") {
    return runPrepareSubjectsCommand(Args, Context.WorkspaceRoot);
  }

  if (Command == "export-patch") {
    return runExportPatchCommand(Args, Context.WorkspaceRoot);
  }

  if (Command == "adapter-list") {
    return runAdapterListCommand(Context.RuntimeRegistry);
  }

  if (Command == "adapter-build") {
    const auto AdapterContext = buildAdapterCommandContext(
        Args, Context.WorkspaceRoot, Context.DefaultResolverLock,
        Context.RuntimeRegistry);
    return runAdapterBuildCommand(AdapterContext);
  }

  if (Command == "adapter-dump-cache") {
    const auto AdapterContext = buildAdapterCommandContext(
        Args, Context.WorkspaceRoot, Context.DefaultResolverLock,
        Context.RuntimeRegistry);
    return runAdapterDumpCacheCommand(Args, AdapterContext,
                                      setResolverBuildEnvForResolver);
  }

  if (Command == "adapter-replay") {
    const auto AdapterContext = buildAdapterCommandContext(
        Args, Context.WorkspaceRoot, Context.DefaultResolverLock,
        Context.RuntimeRegistry);
    return runAdapterReplayCommand(Args, AdapterContext,
                                   setResolverBuildEnvForResolver);
  }

  if (Command == "sync-replay") {
    return runSyncReplayCliCommand(Args, Context.WorkspaceRoot,
                                   Context.DefaultResolverLock,
                                   Context.RuntimeRegistry);
  }

  if (Command == "batch-sync-replay") {
    return runBatchSyncReplayCommand(Args, Context.SelfExecutableCommand,
                                     Context.WorkspaceRoot,
                                     Context.DefaultResolverLock,
                                     Context.RuntimeRegistry);
  }

  if (Command == "oracle-parse") {
    return runOracleParseCommand(Args);
  }

  if (Command == "report") {
    return runReportCommand(Args);
  }

  if (Command == "follow-diff-once") {
    return runFollowDiffOnceCommand();
  }

  if (Command == "follow-diff-window") {
    return runFollowDiffWindowCommand(Args);
  }

  if (Command == "campaign-close") {
    return runCampaignCloseCommand(Args);
  }

  if (Command == "campaign-report") {
    return runCampaignReportCommand(Args);
  }

  if (Command == "case-study-export") {
    return runCaseStudyExportCommand(Args);
  }

  if (Command == "evidence-bundle") {
    return runEvidenceBundleCommand(Args);
  }

  printUsage();
  return 2;
}

void printUsage() {
  std::cerr
      << "用法:\n"
      << "  dnslabctl transcript-summary --input <path>\n"
      << "  dnslabctl sample-id --input <path> --queue-event-id <id>\n"
      << "  dnslabctl lock-generate --manifest <path> --output <path>\n"
      << "  dnslabctl lock-resolved-tag --resolver <name> [--lock-file <path>]\n"
      << "  dnslabctl prepare-subject --resolver <name> [--tag <tag>]"
         " [--lock-file <path>] [--workspace-root <path>]\n"
      << "  dnslabctl prepare-subjects [--lock-file <path>]"
         " [--workspace-root <path>] [--resolvers <csv>]\n"
      << "  dnslabctl export-patch --resolver <name> --purpose <name>"
         " [--tag <tag>] [--source-root <path>] [--output <path>]"
         " [--lock-file <path>] [--workspace-root <path>]\n"
      << "  dnslabctl adapter-list\n"
      << "  dnslabctl adapter-build --resolver <name> --build-root <path>"
         " [--source-root <path>]\n"
      << "  dnslabctl adapter-dump-cache --resolver <name> --build-root <path>"
         " --run-root <path> [--source-root <path>] [--sample <path>]"
         " [--output-file <path>]\n"
      << "  dnslabctl adapter-replay --resolver <name> --sample <path>"
         " --build-root <path> --run-root <path> [--source-root <path>]\n"
      << "  dnslabctl sync-replay --sample <path> --run-root <path>"
         " --bind9-build-root <path> --unbound-build-root <path>"
         " [--bind9-source-root <path>] [--unbound-source-root <path>]"
         " [--secondary-resolver <name>] [--secondary-build-root <path>]"
         " [--secondary-source-root <path>] [--resolvers <csv>]"
         " [--queue-event-id <id>]\n"
      << "  dnslabctl batch-sync-replay --sample-dir <path> --run-root <path>"
         " --bind9-build-root <path>"
         " [--unbound-build-root <path>] [--secondary-resolver <name>]"
         " [--secondary-build-root <path>]"
         " [--bind9-source-root <path>] [--unbound-source-root <path>]"
         " [--secondary-source-root <path>] [--resolvers <csv>]"
         " [--limit <n>]\n"
      << "  dnslabctl follow-diff-once\n"
      << "  dnslabctl follow-diff-window --budget-sec <sec>"
         " [--retry-failed] [--queue-tail-id <id>]\n"
      << "  dnslabctl campaign-close --budget-sec <sec>\n"
      << "  dnslabctl campaign-report --root <path> [--output-dir <path>]\n"
      << "  dnslabctl case-study-export --root <path>"
         " --campaign-report-dir <path> [--top-n <n>]\n"
      << "  dnslabctl report --root <path> [--high-value-manifest <path>]\n"
      << "  dnslabctl oracle-parse --resolver <name> --stderr-file <path>\n"
      << "  dnslabctl evidence-bundle --output <path> --summary <path>"
         " --oracle-audit <path> --failure-taxonomy <path> --cluster <path>"
         " --case-index <path> [--summary-cmd <cmd>] [--oracle-audit-cmd <cmd>]"
         " [--failure-taxonomy-cmd <cmd>] [--cluster-cmd <cmd>]"
         " [--case-index-cmd <cmd>] [--run-id <id>]\n";
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc < 2) {
      printUsage();
      return 2;
    }

    const std::string Command = argv[1];
    const std::vector<std::string> Args(argv + 2, argv + argc);
    const auto Context = buildMainCommandContext(argv[0]);
    return dispatchCommand(Context, Command, Args);
  } catch (const std::exception &Error) {
    std::cerr << Error.what() << '\n';
    return 1;
  }
}
