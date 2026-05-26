#include "dnslab_core/concrete_adapters.hpp"
#include "dnslab_core/cache_analysis.hpp"
#include "dnslab_core/evidence_contract.hpp"
#include "dnslab_core/follow_diff.hpp"
#include "dnslab_core/oracle.hpp"
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

std::string resolveVariantName() {
  const auto IsEnabled = [](const char *Name, bool DefaultValue) {
    const char *Value = std::getenv(Name);
    if (Value == nullptr) {
      return DefaultValue;
    }
    return std::string(Value) == "1";
  };

  const bool Mutator = IsEnabled("ENABLE_DST1_MUTATOR", false);
  const bool CacheDelta = IsEnabled("ENABLE_CACHE_DELTA", true);
  const bool Triage = IsEnabled("ENABLE_TRIAGE", true);
  const bool Symcc = IsEnabled("ENABLE_SYMCC", true);

  if (Mutator && CacheDelta && Triage && Symcc) {
    return "full_stack";
  }
  if (Mutator && CacheDelta && Triage && !Symcc) {
    return "afl_only";
  }
  if (!Mutator && CacheDelta && Triage && Symcc) {
    return "no_mutator";
  }
  if (Mutator && !CacheDelta && Triage && Symcc) {
    return "no_cache_delta";
  }

  std::ostringstream Output;
  Output << "custom-"
         << "mutator-" << (Mutator ? "on" : "off") << "-"
         << "cache-delta-" << (CacheDelta ? "on" : "off") << "-"
         << "triage-" << (Triage ? "on" : "off") << "-"
         << "symcc-" << (Symcc ? "on" : "off");
  return Output.str();
}

std::filesystem::path defaultBuildRootForResolver(
    const std::filesystem::path &WorkspaceRoot, const std::string &ResolverName) {
  if (ResolverName == "bind9") {
    if (const char *Env = std::getenv("BIND9_AFL_TREE")) {
      return std::filesystem::path(Env);
    }
    return WorkspaceRoot / "bind-9.18.46-afl";
  }
  if (ResolverName == "unbound") {
    if (const char *Env = std::getenv("AFL_TREE")) {
      return std::filesystem::path(Env);
    }
    return WorkspaceRoot / "unbound-1.24.2-afl";
  }
  if (ResolverName == "dnsmasq") {
    if (const char *Env = std::getenv("DNSMASQ_BUILD_TREE")) {
      return std::filesystem::path(Env);
    }
    return WorkspaceRoot / "experiments" / "subjects" / "dnsmasq" /
           "v2.92-build";
  }
  if (ResolverName == "smartdns") {
    if (const char *Env = std::getenv("SMARTDNS_BUILD_TREE")) {
      return std::filesystem::path(Env);
    }
    return WorkspaceRoot / "experiments" / "subjects" / "smartdns" /
           "Release47.1-build";
  }
  if (ResolverName == "maradns") {
    if (const char *Env = std::getenv("MARADNS_BUILD_TREE")) {
      return std::filesystem::path(Env);
    }
    return WorkspaceRoot / "experiments" / "subjects" / "maradns" /
           "deadwood-3.3.02-build";
  }
  if (ResolverName == "knot-resolver") {
    if (const char *Env = std::getenv("KNOT_RESOLVER_BUILD_TREE")) {
      return std::filesystem::path(Env);
    }
    return WorkspaceRoot / "experiments" / "subjects" / "knot-resolver" /
           "v6.2.0-build";
  }
  throw std::runtime_error("不支持的 resolver: " + ResolverName);
}

std::filesystem::path defaultSourceRootForResolver(
    const std::filesystem::path &BuildRoot, const std::string &ResolverName) {
  if (ResolverName == "bind9") {
    if (const char *Env = std::getenv("BIND9_SRC_TREE")) {
      return std::filesystem::path(Env);
    }
    return BuildRoot;
  }
  const std::map<std::string, std::vector<std::string>> EnvMap = {
      {"unbound", {"UNBOUND_SRC_TREE", "SRC_TREE"}},
      {"dnsmasq", {"DNSMASQ_SRC_TREE"}},
      {"smartdns", {"SMARTDNS_SRC_TREE"}},
      {"maradns", {"MARADNS_SRC_TREE"}},
      {"knot-resolver", {"KNOT_RESOLVER_SRC_TREE"}},
  };
  const auto Found = EnvMap.find(ResolverName);
  if (Found != EnvMap.end()) {
    for (const auto &EnvName : Found->second) {
      if (const char *Env = std::getenv(EnvName.c_str())) {
        return std::filesystem::path(Env);
      }
    }
  }
  return BuildRoot;
}

std::optional<std::string>
buildRootEnvNameForResolver(const std::string &ResolverName) {
  if (ResolverName == "unbound") {
    return "AFL_TREE";
  }
  if (ResolverName == "dnsmasq") {
    return "DNSMASQ_BUILD_TREE";
  }
  if (ResolverName == "smartdns") {
    return "SMARTDNS_BUILD_TREE";
  }
  if (ResolverName == "maradns") {
    return "MARADNS_BUILD_TREE";
  }
  if (ResolverName == "knot-resolver") {
    return "KNOT_RESOLVER_BUILD_TREE";
  }
  return std::nullopt;
}

std::optional<std::string>
sourceRootEnvNameForResolver(const std::string &ResolverName) {
  if (ResolverName == "unbound") {
    return "UNBOUND_SRC_TREE";
  }
  if (ResolverName == "dnsmasq") {
    return "DNSMASQ_SRC_TREE";
  }
  if (ResolverName == "smartdns") {
    return "SMARTDNS_SRC_TREE";
  }
  if (ResolverName == "maradns") {
    return "MARADNS_SRC_TREE";
  }
  if (ResolverName == "knot-resolver") {
    return "KNOT_RESOLVER_SRC_TREE";
  }
  return std::nullopt;
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
         " [--secondary-source-root <path>] [--resolvers <csv>]\n"
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
    const auto WorkspaceRoot = std::filesystem::current_path();
    const auto SelfExecutablePath = resolveSelfExecutablePath(argv[0]);
    const auto SelfExecutableCommand = SelfExecutablePath.string();
    if (::setenv("DNSLAB_SELF_EXECUTABLE", SelfExecutableCommand.c_str(), 1) !=
        0) {
      throw std::runtime_error("无法设置 DNSLAB_SELF_EXECUTABLE 环境变量");
    }
    std::optional<dnslab::ResolverLockFile> DefaultResolverLock;
    bool DefaultResolverLockLoaded = false;

    const auto tryLoadDefaultResolverLock = [&]() -> const std::optional<dnslab::ResolverLockFile> & {
      if (!DefaultResolverLockLoaded) {
        DefaultResolverLockLoaded = true;
        const auto LockPath = dnslab::defaultResolverLockFilePath(WorkspaceRoot);
        if (std::filesystem::is_regular_file(LockPath)) {
          try {
            DefaultResolverLock = dnslab::loadResolverLockFileJson(LockPath);
          } catch (const std::exception &) {
            DefaultResolverLock.reset();
          }
        }
      }
      return DefaultResolverLock;
    };

    const auto resolveDefaultSourceRoot =
        [&](const std::string &ResolverName,
            const std::filesystem::path &FallbackRoot) -> std::filesystem::path {
      const auto &LockFile = tryLoadDefaultResolverLock();
      if (LockFile.has_value()) {
        if (const auto Tag = dnslab::resolveLockedTag(*LockFile, ResolverName)) {
          const auto LockedSourceRoot =
              dnslab::defaultSubjectRoot(WorkspaceRoot, ResolverName, *Tag);
          if (std::filesystem::exists(LockedSourceRoot)) {
            return LockedSourceRoot;
          }
        }
      }
      return FallbackRoot;
    };

    struct ResolverRunResult {
      dnslab::CommandResult DumpResult;
      dnslab::CommandResult RunResult;
      dnslab::OracleArtifact Oracle;
      std::filesystem::path BeforeCache;
      std::filesystem::path AfterCache;
      std::filesystem::path StderrPath;
      std::vector<std::filesystem::path> Logs;
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
      bool Failed = false;
    };

    const auto setResolverBuildEnv =
        [&](const std::string &ResolverName,
            const std::filesystem::path &BuildRoot) {
          if (ResolverName == "bind9") {
            ::setenv("DNSLAB_BIND9_BUILD_ROOT", BuildRoot.c_str(), 1);
          } else if (ResolverName == "unbound") {
            ::setenv("DNSLAB_UNBOUND_BUILD_ROOT", BuildRoot.c_str(), 1);
          } else if (ResolverName == "dnsmasq") {
            ::setenv("DNSLAB_DNSMASQ_BUILD_ROOT", BuildRoot.c_str(), 1);
          } else if (ResolverName == "smartdns") {
            ::setenv("DNSLAB_SMARTDNS_BUILD_ROOT", BuildRoot.c_str(), 1);
          } else if (ResolverName == "maradns") {
            ::setenv("DNSLAB_MARADNS_BUILD_ROOT", BuildRoot.c_str(), 1);
          } else if (ResolverName == "knot-resolver") {
            ::setenv("DNSLAB_KNOT_RESOLVER_BUILD_ROOT", BuildRoot.c_str(), 1);
          }
        };

    const auto executeSyncReplay =
        [&](const std::filesystem::path &SamplePath,
            const std::filesystem::path &RunRoot, bool NestBySampleId,
            const std::filesystem::path &Bind9BuildRoot,
            const std::filesystem::path &SecondaryBuildRoot,
            const std::filesystem::path &Bind9SourceRoot,
            const std::filesystem::path &SecondarySourceRoot,
            const std::string &SecondaryResolverName,
            const std::optional<std::string> &RequestedResolversCsv =
                std::nullopt) {
          const auto Registry =
              dnslab::makeDefaultResolverRegistry(std::filesystem::current_path());
          const auto RequestedResolvers = orderedResolversForReplay(
              Registry.names(), SecondaryResolverName, RequestedResolversCsv);

          const auto SampleBytes = readBinaryFile(SamplePath);
          const auto SampleIdentity =
              dnslab::buildSampleIdentity("manual", SampleBytes);
          const auto ArtifactRoot =
              NestBySampleId ? (RunRoot / SampleIdentity.SampleId) : RunRoot;

          const auto runSingleResolver =
              [&](const std::string &ResolverName,
                  const dnslab::ResolverAdapter &Adapter,
                  const std::filesystem::path &SourceRoot,
                  const std::filesystem::path &BuildRoot) {
                const auto ResolverRunRoot = ArtifactRoot / ResolverName;
                std::filesystem::create_directories(ResolverRunRoot);
                const auto BeforeCache =
                    ResolverRunRoot / (ResolverName + ".before.cache.txt");
                const auto DumpResult =
                    Adapter.dumpCache(ResolverRunRoot, BeforeCache);
                const auto RunResult = Adapter.runSample(
                    {SourceRoot, BuildRoot, ResolverRunRoot, SamplePath,
                     SampleIdentity.SampleId, {}});
                const auto Oracle =
                    Adapter.parseOracle(ResolverRunRoot / (ResolverName + ".stderr"));
                ResolverRunResult Result;
                Result.DumpResult = DumpResult;
                Result.RunResult = RunResult;
                Result.Oracle = Oracle;
                Result.BeforeCache = BeforeCache;
                Result.AfterCache =
                    ResolverRunRoot / (ResolverName + ".after.cache.txt");
                Result.StderrPath = ResolverRunRoot / (ResolverName + ".stderr");
                Result.Logs = Adapter.collectLogs(ResolverRunRoot);
                return Result;
              };

          std::map<std::string, std::filesystem::path> BuildRoots;
          std::map<std::string, std::filesystem::path> SourceRoots;
          for (const auto &ResolverName : RequestedResolvers) {
            auto BuildRoot = defaultBuildRootForResolver(WorkspaceRoot, ResolverName);
            if (ResolverName == "bind9") {
              BuildRoot = Bind9BuildRoot;
            } else if (ResolverName == SecondaryResolverName) {
              BuildRoot = SecondaryBuildRoot;
            }
            BuildRoots[ResolverName] = BuildRoot;
            auto SourceRoot =
                resolveDefaultSourceRoot(ResolverName,
                                         defaultSourceRootForResolver(BuildRoot,
                                                                      ResolverName));
            if (ResolverName == "bind9") {
              SourceRoot = Bind9SourceRoot;
            } else if (ResolverName == SecondaryResolverName) {
              SourceRoot = SecondarySourceRoot;
            }
            SourceRoots[ResolverName] = SourceRoot;
          }

          struct ResolverExecution {
            ResolverRunResult Run;
            std::vector<dnslab::CacheRecord> BeforeRows;
            std::vector<dnslab::CacheRecord> AfterRows;
            dnslab::json::Value::Object OracleFields;
          };

          const auto parseRowsIfPresent =
              [&](const std::string &ResolverName,
                  const std::filesystem::path &DumpPath) {
                if (!std::filesystem::is_regular_file(DumpPath)) {
                  return std::vector<dnslab::CacheRecord>{};
                }
                return dnslab::parseCacheDump(ResolverName, DumpPath);
              };

          std::map<std::string, ResolverExecution> ExecutedResolvers;
          std::map<std::string, std::string> SkippedResolvers;
          for (const auto &ResolverName : RequestedResolvers) {
            const bool RequiredResolver =
                ResolverName == "bind9" || ResolverName == SecondaryResolverName;
            try {
              setResolverBuildEnv(ResolverName, BuildRoots.at(ResolverName));
              const auto &Adapter = Registry.require(ResolverName);
              auto Run = runSingleResolver(ResolverName, Adapter,
                                           SourceRoots.at(ResolverName),
                                           BuildRoots.at(ResolverName));
              ResolverExecution Execution;
              Execution.BeforeRows =
                  parseRowsIfPresent(ResolverName, Run.BeforeCache);
              Execution.AfterRows =
                  parseRowsIfPresent(ResolverName, Run.AfterCache);
              Execution.OracleFields = Run.Oracle.Fields;
              Execution.Run = std::move(Run);
              ExecutedResolvers.emplace(ResolverName, std::move(Execution));
            } catch (const std::exception &Error) {
              if (RequiredResolver) {
                throw;
              }
              SkippedResolvers[ResolverName] = Error.what();
            }
          }

          const auto Bind9Found = ExecutedResolvers.find("bind9");
          const auto SecondaryFound = ExecutedResolvers.find(SecondaryResolverName);
          if (Bind9Found == ExecutedResolvers.end() ||
              SecondaryFound == ExecutedResolvers.end()) {
            throw std::runtime_error("缺少必要 resolver 执行结果");
          }

          std::map<std::string, std::vector<dnslab::CacheRecord>> BeforeByResolver;
          std::map<std::string, std::vector<dnslab::CacheRecord>> AfterByResolver;
          std::map<std::string, dnslab::json::Value::Object> OracleByResolver;
          for (const auto &[ResolverName, Execution] : ExecutedResolvers) {
            BeforeByResolver[ResolverName] = Execution.BeforeRows;
            AfterByResolver[ResolverName] = Execution.AfterRows;
            OracleByResolver[ResolverName] = Execution.OracleFields;
          }

          const auto PreliminaryCacheDiff = dnslab::buildCacheDiff(
              SampleIdentity.SampleId, BeforeByResolver, AfterByResolver, false,
              SecondaryResolverName);
          bool Triggered = false;
          for (const auto &[ResolverName, Diff] : PreliminaryCacheDiff.Resolvers) {
            (void)ResolverName;
            if (Diff.HasCacheDiff) {
              Triggered = true;
              break;
            }
          }
          const auto CacheDiff = dnslab::buildCacheDiff(
              SampleIdentity.SampleId, BeforeByResolver, AfterByResolver,
              Triggered, SecondaryResolverName);

          dnslab::json::Value::Object OraclePayload = Bind9Found->second.OracleFields;
          for (const auto &[Key, Value] : SecondaryFound->second.OracleFields) {
            OraclePayload[Key] = Value;
            const std::string Prefix = SecondaryResolverName + ".";
            if (SecondaryResolverName != "unbound" && Key.rfind(Prefix, 0) == 0) {
              OraclePayload["unbound." + Key.substr(Prefix.size())] = Value;
            }
          }

          dnslab::StateFingerprint Fingerprint;
          Fingerprint.SchemaVersion = dnslab::kSchemaVersion;
          Fingerprint.GeneratedAt = dnslab::utcTimestampNow();
          Fingerprint.SampleId = SampleIdentity.SampleId;

          std::filesystem::create_directories(ArtifactRoot);
          std::filesystem::copy_file(
              SamplePath, ArtifactRoot / "sample.bin",
              std::filesystem::copy_options::overwrite_existing);

          const auto buildArtifactsPayload = [&]() {
            dnslab::json::Value::Object Artifacts;
            Artifacts["sample_bin"] = "sample.bin";
            Artifacts["oracle"] = "oracle.json";
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
          };

          const auto buildOracleProvenancePayload = [&]() {
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
          };

          SyncReplayResult Result;
          Result.Identity = SampleIdentity;
          Result.Fingerprint = Fingerprint;
          Result.OraclePayload = OraclePayload;
          Result.OracleByResolver = OracleByResolver;
          Result.ResolverRuns = {};
          for (const auto &[ResolverName, Execution] : ExecutedResolvers) {
            Result.ResolverRuns.emplace(ResolverName, Execution.Run);
          }
          Result.SkippedResolvers = SkippedResolvers;
          Result.ResolverBuildRoots = BuildRoots;
          Result.ResolverSourceRoots = SourceRoots;
          Result.ExecutedResolvers = CacheDiff.ExecutedResolvers;
          Result.Bind9 = Bind9Found->second.Run;
          Result.Secondary = SecondaryFound->second.Run;
          Result.SecondaryResolver = SecondaryResolverName;
          Result.ArtifactDir = ArtifactRoot;
          Result.Failed = Bind9Found->second.Run.RunResult.ExitCode != 0 ||
                          SecondaryFound->second.Run.RunResult.ExitCode != 0;

          std::optional<dnslab::FailureEvidence> Failure;
          if (Bind9Found->second.Run.RunResult.ExitCode != 0) {
            dnslab::FailureEvidence Evidence;
            Evidence.Kind = "replay_error";
            Evidence.Reason = "subprocess_failed";
            Evidence.Stage = "bind9.after";
            Evidence.Resolver = "bind9";
            Evidence.ProcessStarted = true;
            Failure = Evidence;
          } else if (SecondaryFound->second.Run.RunResult.ExitCode != 0) {
            dnslab::FailureEvidence Evidence;
            Evidence.Kind = "replay_error";
            Evidence.Reason = "subprocess_failed";
            Evidence.Stage = SecondaryResolverName + ".after";
            Evidence.Resolver = SecondaryResolverName;
            Evidence.ProcessStarted = true;
            Failure = Evidence;
          }

          const auto Triage = dnslab::buildTriageRecord(
              SampleIdentity.SampleId, OracleByResolver, CacheDiff, Fingerprint,
              Failure);

          dnslab::json::Value::Object OracleDocument = OraclePayload;
          OracleDocument["secondary_resolver"] = SecondaryResolverName;
          dnslab::json::Value::Array OracleExecutedResolvers;
          for (const auto &ResolverName : CacheDiff.ExecutedResolvers) {
            OracleExecutedResolvers.emplace_back(ResolverName);
          }
          OracleDocument["executed_resolvers"] = OracleExecutedResolvers;
          dnslab::json::Value::Object OracleSkippedResolvers;
          for (const auto &[ResolverName, Reason] : SkippedResolvers) {
            OracleSkippedResolvers[ResolverName] = Reason;
          }
          OracleDocument["skipped_resolvers"] =
              dnslab::json::Value(OracleSkippedResolvers);
          OracleDocument["diff_detected"] = Triage.DiffDetected;
          dnslab::json::Value::Object OracleResolvers;
          for (const auto &[ResolverName, Execution] : ExecutedResolvers) {
            OracleResolvers[ResolverName] =
                dnslab::json::Value(Execution.OracleFields);
          }
          OracleDocument["resolvers"] = dnslab::json::Value(OracleResolvers);
          {
            dnslab::json::Value::Array ResolverDiffs;
            for (const auto &Difference : Triage.ResolverDifferences) {
              ResolverDiffs.emplace_back(dnslab::toJson(Difference));
            }
            OracleDocument["resolver_diffs"] = ResolverDiffs;
          }
          writeJsonFile(ArtifactRoot / "oracle.json",
                        dnslab::json::Value(OracleDocument));

          double ReplayBudgetSec = 0.0;
          if (const char *BudgetEnv =
                  std::getenv("DNSLAB_SYNC_REPLAY_BUDGET_SEC")) {
            try {
              ReplayBudgetSec = std::stod(BudgetEnv);
            } catch (const std::exception &) {
              ReplayBudgetSec = 0.0;
            }
          }

          auto Meta = dnslab::buildSampleMeta(SampleIdentity.SampleId);
          Meta.QueueEventId = "manual";
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
          Meta.Aggregation.SeedTimeoutSec = 5;
          Meta.Aggregation.VariantName = resolveVariantName();
          Meta.Aggregation.AblationStatus = "enabled";
          Meta.BaselineCompare.ResolverPair = "bind9_vs_" + SecondaryResolverName;
          Meta.BaselineCompare.ProducerProfile = "poison-stateful";
          Meta.BaselineCompare.InputModel = "DST1 transcript";
          Meta.BaselineCompare.SourceQueueDir = SamplePath.parent_path().string();
          Meta.BaselineCompare.BudgetSec = ReplayBudgetSec;
          Meta.BaselineCompare.SeedTimeoutSec = 5;
          Meta.BaselineCompare.RepeatCount = 1;
          Meta.Failure = Failure;
          auto MetaPayload =
              std::get<dnslab::json::Value::Object>(dnslab::toJson(Meta).storage());
          MetaPayload["secondary_resolver"] = SecondaryResolverName;
          MetaPayload["artifacts"] = dnslab::json::Value(buildArtifactsPayload());
          MetaPayload["oracle_provenance"] =
              dnslab::json::Value(buildOracleProvenancePayload());
          MetaPayload["output_dir"] = ArtifactRoot.string();
          dnslab::json::Value::Array MetaExecutedResolvers;
          for (const auto &ResolverName : CacheDiff.ExecutedResolvers) {
            MetaExecutedResolvers.emplace_back(ResolverName);
          }
          MetaPayload["executed_resolvers"] = MetaExecutedResolvers;
          dnslab::json::Value::Object MetaSkippedResolvers;
          for (const auto &[ResolverName, Reason] : SkippedResolvers) {
            MetaSkippedResolvers[ResolverName] = Reason;
          }
          MetaPayload["skipped_resolvers"] =
              dnslab::json::Value(MetaSkippedResolvers);
          MetaPayload["diff_detected"] = Triage.DiffDetected;
          {
            dnslab::json::Value::Array ResolverDiffs;
            for (const auto &Difference : Triage.ResolverDifferences) {
              ResolverDiffs.emplace_back(dnslab::toJson(Difference));
            }
            MetaPayload["resolver_diffs"] = ResolverDiffs;
          }
          writeJsonFile(ArtifactRoot / "sample.meta.json",
                        dnslab::json::Value(MetaPayload));
          writeJsonFile(ArtifactRoot / "cache_diff.json", dnslab::toJson(CacheDiff));
          writeJsonFile(ArtifactRoot / "state_fingerprint.json",
                        dnslab::toJson(Fingerprint));
          writeJsonFile(ArtifactRoot / "triage.json", dnslab::toJson(Triage));
          Result.Meta = Meta;
          Result.CacheDiff = CacheDiff;
          Result.Triage = Triage;
          return Result;
        };

    if (Command == "transcript-summary") {
      const auto Input = readBinaryFile(requireOption(Args, "--input"));
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
      std::cout << dnslab::json::Value(Output).dump(2) << '\n';
      return 0;
    }

    if (Command == "sample-id") {
      const auto Input = readBinaryFile(requireOption(Args, "--input"));
      const auto Identity = dnslab::buildSampleIdentity(
          requireOption(Args, "--queue-event-id"), Input);
      dnslab::json::Value::Object Output;
      Output["queue_event_id"] = Identity.QueueEventId;
      Output["sample_sha1"] = Identity.SampleSha1;
      Output["sample_id"] = Identity.SampleId;
      Output["sample_size"] = static_cast<std::int64_t>(Identity.SampleSize);
      std::cout << dnslab::json::Value(Output).dump(2) << '\n';
      return 0;
    }

    if (Command == "lock-generate") {
      const auto Manifest =
          dnslab::loadResolverManifestTsv(requireOption(Args, "--manifest"));
      const auto LockFile =
          dnslab::generateResolverLockFile(Manifest, dnslab::runCommand);
      dnslab::writeResolverLockFile(requireOption(Args, "--output"), LockFile);
      std::cout << dnslab::toJson(LockFile).dump(2) << '\n';
      return 0;
    }

    if (Command == "lock-resolved-tag") {
      const auto ResolverName = requireOption(Args, "--resolver");
      std::filesystem::path LockPath =
          dnslab::defaultResolverLockFilePath(WorkspaceRoot);
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--lock-file") {
          LockPath = Args[Index + 1];
        }
      }
      const auto LockFile = dnslab::loadResolverLockFileJson(LockPath);
      const auto Tag = dnslab::resolveLockedTag(LockFile, ResolverName);
      if (!Tag.has_value()) {
        std::cerr << "resolver 未在 lock 中找到或缺少 tag\n";
        return 1;
      }
      std::cout << *Tag << '\n';
      return 0;
    }

    if (Command == "prepare-subject") {
      std::filesystem::path WorkspacePath = WorkspaceRoot;
      std::filesystem::path LockPath =
          dnslab::defaultResolverLockFilePath(WorkspaceRoot);
      std::optional<std::string> ExplicitTag;
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--workspace-root") {
          WorkspacePath = Args[Index + 1];
        } else if (Args[Index] == "--lock-file") {
          LockPath = Args[Index + 1];
        } else if (Args[Index] == "--tag") {
          ExplicitTag = Args[Index + 1];
        }
      }
      const auto ResolverName = requireOption(Args, "--resolver");
      std::optional<std::string> Tag = ExplicitTag;
      if (!Tag.has_value()) {
        const auto LockFile = dnslab::loadResolverLockFileJson(LockPath);
        Tag = dnslab::resolveLockedTag(LockFile, ResolverName);
      }
      if (!Tag.has_value()) {
        std::cerr << "resolver 未在 lock 中找到或缺少 tag\n";
        return 1;
      }
      const auto Registry = dnslab::makeDefaultResolverRegistry(WorkspacePath);
      const auto &Adapter = Registry.require(ResolverName);
      const auto SubjectRoot = Adapter.prepareSource(WorkspacePath, *Tag);
      dnslab::json::Value::Object Output;
      Output["resolver"] = ResolverName;
      Output["tag"] = *Tag;
      Output["subject_root"] = SubjectRoot.string();
      std::cout << dnslab::json::Value(Output).dump(2) << '\n';
      return 0;
    }

    if (Command == "prepare-subjects") {
      std::filesystem::path WorkspacePath = WorkspaceRoot;
      std::filesystem::path LockPath =
          dnslab::defaultResolverLockFilePath(WorkspaceRoot);
      std::optional<std::string> ResolverCsv;
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--workspace-root") {
          WorkspacePath = Args[Index + 1];
        } else if (Args[Index] == "--lock-file") {
          LockPath = Args[Index + 1];
        } else if (Args[Index] == "--resolvers") {
          ResolverCsv = Args[Index + 1];
        }
      }

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
        dnslab::json::Value::Object Record;
        Record["resolver"] = Entry.Resolver;
        Record["tag"] = Tag;
        Record["subject_root"] = SubjectRoot.string();
        Output.emplace_back(Record);
      }
      std::cout << dnslab::json::Value(Output).dump(2) << '\n';
      return 0;
    }

    if (Command == "export-patch") {
      std::filesystem::path WorkspacePath = WorkspaceRoot;
      std::filesystem::path LockPath =
          dnslab::defaultResolverLockFilePath(WorkspaceRoot);
      std::optional<std::string> ExplicitTag;
      std::optional<std::filesystem::path> ExplicitSourceRoot;
      std::optional<std::filesystem::path> ExplicitOutputPath;
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--workspace-root") {
          WorkspacePath = Args[Index + 1];
        } else if (Args[Index] == "--lock-file") {
          LockPath = Args[Index + 1];
        } else if (Args[Index] == "--tag") {
          ExplicitTag = Args[Index + 1];
        } else if (Args[Index] == "--source-root") {
          ExplicitSourceRoot = std::filesystem::path(Args[Index + 1]);
        } else if (Args[Index] == "--output") {
          ExplicitOutputPath = std::filesystem::path(Args[Index + 1]);
        }
      }
      const auto ResolverName = requireOption(Args, "--resolver");
      const auto Purpose = requireOption(Args, "--purpose");
      std::optional<std::string> Tag = ExplicitTag;
      if (!Tag.has_value()) {
        const auto LockFile = dnslab::loadResolverLockFileJson(LockPath);
        Tag = dnslab::resolveLockedTag(LockFile, ResolverName);
      }
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
      dnslab::json::Value::Object Output;
      Output["resolver"] = ResolverName;
      Output["purpose"] = Purpose;
      Output["tag"] = *Tag;
      Output["source_root"] = SourceRoot.string();
      Output["output_path"] = OutputPath.string();
      Output["patch_bytes"] =
          static_cast<std::int64_t>(Diff.StdoutText.size());
      std::cout << dnslab::json::Value(Output).dump(2) << '\n';
      return 0;
    }

    if (Command == "adapter-list") {
      const auto Registry =
          dnslab::makeDefaultResolverRegistry(std::filesystem::current_path());
      dnslab::json::Value::Array Names;
      for (const auto &Name : Registry.names()) {
        Names.emplace_back(Name);
      }
      std::cout << dnslab::json::Value(Names).dump(2) << '\n';
      return 0;
    }

    if (Command == "adapter-build") {
      const auto ResolverName = requireOption(Args, "--resolver");
      const auto BuildRoot =
          std::filesystem::path(requireOption(Args, "--build-root"));
      std::filesystem::path SourceRoot =
          resolveDefaultSourceRoot(ResolverName, BuildRoot);
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--source-root") {
          SourceRoot = Args[Index + 1];
        }
      }
      const auto Registry =
          dnslab::makeDefaultResolverRegistry(std::filesystem::current_path());
      const auto &Adapter = Registry.require(ResolverName);
      const auto BuildResult = Adapter.build(SourceRoot, BuildRoot);
      dnslab::json::Value::Object Output;
      Output["resolver"] = ResolverName;
      Output["source_root"] = SourceRoot.string();
      Output["build_root"] = BuildRoot.string();
      Output["exit_code"] = BuildResult.ExitCode;
      Output["stdout"] = BuildResult.StdoutText;
      Output["stderr"] = BuildResult.StderrText;
      std::cout << dnslab::json::Value(Output).dump(2) << '\n';
      return BuildResult.ExitCode;
    }

    if (Command == "adapter-dump-cache") {
      const auto ResolverName = requireOption(Args, "--resolver");
      const auto BuildRoot =
          std::filesystem::path(requireOption(Args, "--build-root"));
      const auto RunRoot =
          std::filesystem::path(requireOption(Args, "--run-root"));
      std::filesystem::path SourceRoot =
          resolveDefaultSourceRoot(ResolverName, BuildRoot);
      std::optional<std::filesystem::path> SamplePath;
      std::optional<std::filesystem::path> OutputFile;
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--source-root") {
          SourceRoot = Args[Index + 1];
        } else if (Args[Index] == "--sample") {
          SamplePath = std::filesystem::path(Args[Index + 1]);
        } else if (Args[Index] == "--output-file") {
          OutputFile = std::filesystem::path(Args[Index + 1]);
        }
      }

      const auto Registry =
          dnslab::makeDefaultResolverRegistry(std::filesystem::current_path());
      const auto &Adapter = Registry.require(ResolverName);
      std::filesystem::create_directories(RunRoot);
      setResolverBuildEnv(ResolverName, BuildRoot);

      dnslab::CommandResult DumpResult;
      std::filesystem::path EffectiveOutput;
      if (SamplePath.has_value()) {
        const auto SampleBytes = readBinaryFile(*SamplePath);
        const auto SampleIdentity = dnslab::buildSampleIdentity(
            SamplePath->filename().string(), SampleBytes);
        DumpResult = Adapter.runSample(
            {SourceRoot, BuildRoot, RunRoot, *SamplePath, SampleIdentity.SampleId, {}});
        EffectiveOutput = RunRoot / (ResolverName + ".after.cache.txt");
      } else {
        EffectiveOutput =
            OutputFile.value_or(RunRoot / (ResolverName + ".before.cache.txt"));
        DumpResult = Adapter.dumpCache(RunRoot, EffectiveOutput);
      }

      if (OutputFile.has_value() && EffectiveOutput != *OutputFile &&
          std::filesystem::is_regular_file(EffectiveOutput)) {
        std::filesystem::create_directories(OutputFile->parent_path());
        std::filesystem::copy_file(EffectiveOutput, *OutputFile,
                                   std::filesystem::copy_options::overwrite_existing);
        EffectiveOutput = *OutputFile;
      }

      dnslab::json::Value::Object Output;
      Output["resolver"] = ResolverName;
      Output["source_root"] = SourceRoot.string();
      Output["build_root"] = BuildRoot.string();
      Output["run_root"] = RunRoot.string();
      if (SamplePath.has_value()) {
        Output["sample"] = SamplePath->string();
      }
      Output["output_file"] = EffectiveOutput.string();
      Output["exit_code"] = DumpResult.ExitCode;
      Output["stdout"] = DumpResult.StdoutText;
      Output["stderr"] = DumpResult.StderrText;
      std::cout << dnslab::json::Value(Output).dump(2) << '\n';
      return DumpResult.ExitCode;
    }

    if (Command == "adapter-replay") {
      const auto ResolverName = requireOption(Args, "--resolver");
      const auto BuildRoot =
          std::filesystem::path(requireOption(Args, "--build-root"));
      const auto RunRoot =
          std::filesystem::path(requireOption(Args, "--run-root"));
      const auto SamplePath = std::filesystem::path(requireOption(Args, "--sample"));
      std::filesystem::path SourceRoot =
          resolveDefaultSourceRoot(ResolverName, BuildRoot);
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--source-root") {
          SourceRoot = Args[Index + 1];
        }
      }

      const auto Registry =
          dnslab::makeDefaultResolverRegistry(std::filesystem::current_path());
      const auto &Adapter = Registry.require(ResolverName);
      std::filesystem::create_directories(RunRoot);
      setResolverBuildEnv(ResolverName, BuildRoot);

      const auto BeforeCache = RunRoot / (ResolverName + ".before.cache.txt");
      const auto DumpResult = Adapter.dumpCache(RunRoot, BeforeCache);
      if (DumpResult.ExitCode != 0) {
        std::cerr << "adapter dump-cache 失败\n";
        return DumpResult.ExitCode;
      }

      const auto RunResult = Adapter.runSample({SourceRoot,
                                                BuildRoot,
                                                RunRoot,
                                                SamplePath,
                                                SamplePath.filename().string(),
                                                {}});
      const auto Oracle = Adapter.parseOracle(RunRoot / (ResolverName + ".stderr"));

      dnslab::json::Value::Object Output;
      Output["resolver"] = ResolverName;
      Output["dump_cache_exit_code"] = DumpResult.ExitCode;
      Output["run_sample_exit_code"] = RunResult.ExitCode;
      Output["before_cache"] = BeforeCache.string();
      Output["after_cache"] =
          (RunRoot / (ResolverName + ".after.cache.txt")).string();
      Output["stderr"] = (RunRoot / (ResolverName + ".stderr")).string();
      Output["oracle"] = dnslab::json::Value(Oracle.Fields);
      dnslab::json::Value::Array Logs;
      for (const auto &Path : Adapter.collectLogs(RunRoot)) {
        Logs.emplace_back(Path.string());
      }
      Output["logs"] = Logs;
      std::cout << dnslab::json::Value(Output).dump(2) << '\n';
      return RunResult.ExitCode;
    }

    if (Command == "sync-replay") {
      const auto SamplePath = std::filesystem::path(requireOption(Args, "--sample"));
      const auto RunRoot = std::filesystem::path(requireOption(Args, "--run-root"));
      const auto Bind9BuildRoot =
          std::filesystem::path(requireOption(Args, "--bind9-build-root"));
      const auto SecondaryResolverName =
          optionalOption(Args, "--secondary-resolver").value_or("unbound");
      const auto SecondaryBuildRoot = std::filesystem::path(
          optionalOption(Args, "--secondary-build-root")
              .value_or(requireOption(Args, "--unbound-build-root")));

      std::filesystem::path Bind9SourceRoot =
          resolveDefaultSourceRoot("bind9", Bind9BuildRoot);
      std::filesystem::path SecondarySourceRoot =
          resolveDefaultSourceRoot(SecondaryResolverName, SecondaryBuildRoot);
      const auto RequestedResolversCsv = optionalOption(Args, "--resolvers");
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--bind9-source-root") {
          Bind9SourceRoot = Args[Index + 1];
        } else if (Args[Index] == "--unbound-source-root") {
          SecondarySourceRoot = Args[Index + 1];
        } else if (Args[Index] == "--secondary-source-root") {
          SecondarySourceRoot = Args[Index + 1];
        }
      }

      const auto ReplayResult = executeSyncReplay(
          SamplePath, RunRoot, false, Bind9BuildRoot, SecondaryBuildRoot,
          Bind9SourceRoot, SecondarySourceRoot, SecondaryResolverName,
          RequestedResolversCsv);

      dnslab::json::Value::Object Output;
      Output["sample_id"] = ReplayResult.Identity.SampleId;
      Output["sample_sha1"] = ReplayResult.Identity.SampleSha1;
      Output["sample_size"] =
          static_cast<std::int64_t>(ReplayResult.Identity.SampleSize);

      const auto toResolverJson = [&](const std::string &,
                                      const ResolverRunResult &Result) {
        dnslab::json::Value::Object ResolverOutput;
        ResolverOutput["dump_cache_exit_code"] = Result.DumpResult.ExitCode;
        ResolverOutput["run_sample_exit_code"] = Result.RunResult.ExitCode;
        ResolverOutput["before_cache"] = Result.BeforeCache.string();
        ResolverOutput["after_cache"] = Result.AfterCache.string();
        ResolverOutput["stderr"] = Result.StderrPath.string();
        ResolverOutput["oracle"] = dnslab::json::Value(Result.Oracle.Fields);
        dnslab::json::Value::Array Logs;
        for (const auto &Path : Result.Logs) {
          Logs.emplace_back(Path.string());
        }
        ResolverOutput["logs"] = Logs;
        return ResolverOutput;
      };

      Output["bind9"] = toResolverJson("bind9", ReplayResult.Bind9);
      Output["secondary_resolver"] = ReplayResult.SecondaryResolver;
      Output[ReplayResult.SecondaryResolver] =
          toResolverJson(ReplayResult.SecondaryResolver, ReplayResult.Secondary);
      dnslab::json::Value::Object Resolvers;
      for (const auto &[ResolverName, ResolverResult] : ReplayResult.ResolverRuns) {
        Resolvers[ResolverName] = toResolverJson(ResolverName, ResolverResult);
      }
      Output["resolvers"] = dnslab::json::Value(Resolvers);
      dnslab::json::Value::Array ExecutedResolvers;
      for (const auto &ResolverName : ReplayResult.ExecutedResolvers) {
        ExecutedResolvers.emplace_back(ResolverName);
      }
      Output["executed_resolvers"] = ExecutedResolvers;
      dnslab::json::Value::Object SkippedResolvers;
      for (const auto &[ResolverName, Reason] : ReplayResult.SkippedResolvers) {
        SkippedResolvers[ResolverName] = Reason;
      }
      Output["skipped_resolvers"] = dnslab::json::Value(SkippedResolvers);
      Output["diff_detected"] = ReplayResult.Triage.DiffDetected;
      const auto TriageJsonObject =
          std::get<dnslab::json::Value::Object>(dnslab::toJson(ReplayResult.Triage)
                                                    .storage());
      const auto ResolverDiffs = TriageJsonObject.find("resolver_diffs");
      if (ResolverDiffs != TriageJsonObject.end()) {
        Output["resolver_diffs"] = ResolverDiffs->second;
      } else {
        Output["resolver_diffs"] = dnslab::json::Value::Array{};
      }
      Output["artifact_dir"] = ReplayResult.ArtifactDir.string();
      std::cout << dnslab::json::Value(Output).dump(2) << '\n';
      return ReplayResult.Failed ? 4 : 0;
    }

    if (Command == "batch-sync-replay") {
      const auto SampleDir =
          std::filesystem::path(requireOption(Args, "--sample-dir"));
      const auto RunRoot = std::filesystem::path(requireOption(Args, "--run-root"));
      const auto Bind9BuildRoot =
          std::filesystem::path(requireOption(Args, "--bind9-build-root"));
      const auto SecondaryResolverName =
          optionalOption(Args, "--secondary-resolver").value_or("unbound");
      const auto SecondaryBuildRootArg = optionalOption(Args, "--secondary-build-root");
      const auto LegacyUnboundBuildRootArg = optionalOption(Args, "--unbound-build-root");
      if (!SecondaryBuildRootArg.has_value() &&
          !LegacyUnboundBuildRootArg.has_value()) {
        throw std::runtime_error(
            "缺少参数: --secondary-build-root 或 --unbound-build-root");
      }
      const auto SecondaryBuildRoot = std::filesystem::path(
          SecondaryBuildRootArg.value_or(*LegacyUnboundBuildRootArg));
      std::filesystem::path Bind9SourceRoot =
          resolveDefaultSourceRoot("bind9", Bind9BuildRoot);
      std::filesystem::path SecondarySourceRoot =
          resolveDefaultSourceRoot(SecondaryResolverName, SecondaryBuildRoot);
      std::optional<size_t> Limit;
      const auto RequestedResolversCsv = optionalOption(Args, "--resolvers");
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--bind9-source-root") {
          Bind9SourceRoot = Args[Index + 1];
        } else if (Args[Index] == "--unbound-source-root") {
          SecondarySourceRoot = Args[Index + 1];
        } else if (Args[Index] == "--secondary-source-root") {
          SecondarySourceRoot = Args[Index + 1];
        } else if (Args[Index] == "--limit") {
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
        Results.push_back(executeSyncReplay(SamplePath, RunRoot / "samples", true,
                                            Bind9BuildRoot, SecondaryBuildRoot,
                                            Bind9SourceRoot, SecondarySourceRoot,
                                            SecondaryResolverName,
                                            RequestedResolversCsv));
      }

      const auto objectBool = [](const dnslab::json::Value::Object &Object,
                                 const std::string &Key) -> std::optional<bool> {
        const auto Found = Object.find(Key);
        if (Found == Object.end()) {
          return std::nullopt;
        }
        if (const auto *BoolValue =
                std::get_if<bool>(&Found->second.storage())) {
          return *BoolValue;
        }
        return std::nullopt;
      };

      const auto joinValues = [](const std::vector<std::string> &Values,
                                 const std::string &Separator) {
        std::ostringstream Stream;
        for (size_t Index = 0; Index < Values.size(); ++Index) {
          if (Index != 0) {
            Stream << Separator;
          }
          Stream << Values[Index];
        }
        return Stream.str();
      };

      const auto compactJson = [](const dnslab::json::Value &Value) {
        return Value.dump(0);
      };

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

      const auto updateSignal = [&](const std::string &Name,
                                    bool EligibleCondition) {
        if (!EligibleCondition) {
          return;
        }
        ++SignalEligibleCounts[Name];
        ++SignalPendingCounts[Name];
      };

      for (const auto &Result : Results) {
        MetaRecords.push_back(Result.Meta);
        ClusterRecords.push_back({Result.Meta, Result.Fingerprint});
        if (Result.Failed) {
          ++FailedCount;
        } else {
          ++CompletedCount;
        }

        if (Result.Triage.AnalysisState == "included") {
          ++IncludedCount;
        } else if (Result.Triage.AnalysisState == "excluded") {
          ++ExcludedCount;
        } else {
          ++UnknownCount;
        }
        ++FailurePrimaryCounts[Result.Triage.FailureBucketPrimary];
        if (Result.Triage.OracleAuditCandidate) {
          ++OracleAuditCount;
        }
        if (Result.Triage.DiffDetected) {
          ++DiffDetectedCount;
        }
        for (const auto &ResolverName : Result.ExecutedResolvers) {
          ++ExecutedResolverSampleCounts[ResolverName];
        }
        for (const auto &[ResolverName, Reason] : Result.SkippedResolvers) {
          (void)Reason;
          ++SkippedResolverSampleCounts[ResolverName];
        }
        for (const auto &Difference : Result.Triage.ResolverDifferences) {
          const std::string PairName =
              Difference.LeftResolver + "_vs_" + Difference.RightResolver;
          ++ResolverPairDiffCounts[PairName];
        }

        const auto buildResolverBoolMap =
            [&](const std::string &FieldSuffix) {
              dnslab::json::Value::Object Output;
              for (const auto &ResolverName : Result.ExecutedResolvers) {
                const auto OracleFound = Result.OracleByResolver.find(ResolverName);
                const auto Value =
                    OracleFound == Result.OracleByResolver.end()
                        ? std::optional<bool>()
                        : objectBool(OracleFound->second,
                                     ResolverName + "." + FieldSuffix);
                if (Value.has_value()) {
                  Output[ResolverName] = *Value;
                } else {
                  Output[ResolverName] = dnslab::json::Value();
                }
              }
              return Output;
            };

        const auto responseAcceptedByResolver =
            buildResolverBoolMap("response_accepted");
        const auto secondQueryHitByResolver =
            buildResolverBoolMap("second_query_hit");
        const auto cacheEntryCreatedByResolver =
            buildResolverBoolMap("cache_entry_created");
        const auto anyResolverTrue =
            [&](const dnslab::json::Value::Object &Object) {
              for (const auto &[ResolverName, Value] : Object) {
                (void)ResolverName;
                if (const auto *BoolValue =
                        std::get_if<bool>(&Value.storage())) {
                  if (*BoolValue) {
                    return true;
                  }
                }
              }
              return false;
            };
        const auto executedResolversText =
            joinValues(Result.ExecutedResolvers, ",");
        const auto skippedResolversJson = [&]() {
          dnslab::json::Value::Object Output;
          for (const auto &[ResolverName, Reason] : Result.SkippedResolvers) {
            Output[ResolverName] = Reason;
          }
          return dnslab::json::Value(Output);
        }();
        const auto resolverDiffsJson = [&]() {
          dnslab::json::Value::Array Output;
          for (const auto &Difference : Result.Triage.ResolverDifferences) {
            Output.emplace_back(dnslab::toJson(Difference));
          }
          return dnslab::json::Value(Output);
        }();

        if (Result.Triage.CaseStudyCandidate) {
          ++CaseStudyCount;
          const auto CaseStudyPath =
              RunRoot / "case_studies" / (Result.Identity.SampleId + ".md");
          std::string ReplayCommand;
          for (const auto &ResolverName : Result.ExecutedResolvers) {
            if (ResolverName == "bind9" || ResolverName == Result.SecondaryResolver) {
              continue;
            }
            if (ResolverName == "unbound") {
              continue;
            }
            if (const auto EnvName = buildRootEnvNameForResolver(ResolverName);
                EnvName.has_value()) {
              ReplayCommand += *EnvName + "=" +
                               Result.ResolverBuildRoots.at(ResolverName).string() +
                               " ";
            }
            if (const auto EnvName = sourceRootEnvNameForResolver(ResolverName);
                EnvName.has_value()) {
              ReplayCommand += *EnvName + "=" +
                               Result.ResolverSourceRoots.at(ResolverName).string() +
                               " ";
            }
          }
          ReplayCommand +=
              SelfExecutableCommand + " sync-replay --sample " +
              Result.Meta.SourceQueueFile.value_or("_") + " --run-root " +
              Result.ArtifactDir.string() + " --bind9-build-root " +
              Bind9BuildRoot.string() + " --bind9-source-root " +
              Result.ResolverSourceRoots.at("bind9").string();
          if (Result.ResolverBuildRoots.count("unbound")) {
            ReplayCommand += " --unbound-build-root " +
                             Result.ResolverBuildRoots.at("unbound").string();
          } else {
            ReplayCommand += " --unbound-build-root " + SecondaryBuildRoot.string();
          }
          if (Result.SecondaryResolver != "unbound") {
            ReplayCommand += " --secondary-resolver " + Result.SecondaryResolver +
                             " --secondary-build-root " +
                             Result.ResolverBuildRoots.at(Result.SecondaryResolver).string() +
                             " --secondary-source-root " +
                             Result.ResolverSourceRoots.at(Result.SecondaryResolver).string();
          }
          ReplayCommand += " --resolvers " + executedResolversText;
          std::ofstream CaseStudyFile(CaseStudyPath);
          CaseStudyFile << "# " << Result.Identity.SampleId << "\n\n";
          CaseStudyFile << "- semantic_outcome: " << Result.Triage.SemanticOutcome
                        << "\n";
          CaseStudyFile << "- manual_truth_status: "
                        << Result.Triage.ManualTruthStatus << "\n";
          CaseStudyFile << "- executed_resolvers: " << executedResolversText
                        << "\n";
          CaseStudyFile << "- skipped_resolvers_json: "
                        << compactJson(skippedResolversJson) << "\n";
          CaseStudyFile << "- diff_detected: "
                        << (Result.Triage.DiffDetected ? "true" : "false") << "\n";
          CaseStudyFile << "- resolver_diffs_json: "
                        << compactJson(resolverDiffsJson) << "\n";
          CaseStudyFile << "- notes: ";
          if (Result.Triage.Notes.empty()) {
            CaseStudyFile << "_\n";
          } else {
            for (size_t Index = 0; Index < Result.Triage.Notes.size(); ++Index) {
              if (Index != 0) {
                CaseStudyFile << " | ";
              }
              CaseStudyFile << Result.Triage.Notes[Index];
            }
            CaseStudyFile << "\n";
          }
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

          CaseStudyIndex << Result.Identity.SampleId << '\t'
                         << Result.Triage.SemanticOutcome << '\t'
                         << "oracle_audit_candidate" << '\t'
                         << CaseStudyPath.string() << '\t' << ReplayCommand
                         << '\t' << executedResolversText << '\t'
                         << (Result.Triage.DiffDetected ? "true" : "false")
                         << '\t' << compactJson(resolverDiffsJson)
                         << '\n';
        }

        const bool OracleEligible = Result.Triage.AnalysisState == "included" &&
                                    Result.Triage.OracleAuditCandidate;
        const bool OracleDiffAny = std::any_of(
            Result.Triage.ResolverDifferences.begin(),
            Result.Triage.ResolverDifferences.end(),
            [](const dnslab::ResolverPairDifference &Difference) {
              return !Difference.OracleDiffFields.empty();
            });
        const bool CacheDiffAny = Result.CacheDiff.DiffDetected;
        updateSignal("response_accepted_any",
                     OracleEligible && anyResolverTrue(responseAcceptedByResolver));
        updateSignal("second_query_hit_any",
                     OracleEligible && anyResolverTrue(secondQueryHitByResolver));
        updateSignal("cache_entry_created_any",
                     OracleEligible && anyResolverTrue(cacheEntryCreatedByResolver));
        updateSignal("oracle_diff_any", OracleEligible && OracleDiffAny);
        updateSignal("oracle_diff_plus_cache_diff",
                     OracleEligible && OracleDiffAny && CacheDiffAny);

        OracleAudit << Result.Identity.SampleId << '\t'
                    << Result.Triage.AnalysisState << '\t'
                    << Result.Triage.Status << '\t'
                    << Result.Triage.SemanticOutcome << '\t'
                    << (Result.Triage.OracleAuditCandidate ? "true" : "false")
                    << '\t'
                    << (Result.Triage.CaseStudyCandidate ? "true" : "false")
                    << '\t'
                    << executedResolversText << '\t'
                    << compactJson(skippedResolversJson) << '\t'
                    << (Result.Triage.DiffDetected ? "true" : "false") << '\t'
                    << compactJson(resolverDiffsJson) << '\t'
                    << (anyResolverTrue(responseAcceptedByResolver) ? "true"
                                                                  : "false")
                    << '\t'
                    << (anyResolverTrue(secondQueryHitByResolver) ? "true"
                                                                 : "false")
                    << '\t'
                    << (anyResolverTrue(cacheEntryCreatedByResolver) ? "true"
                                                                    : "false")
                    << '\t'
                    << compactJson(dnslab::json::Value(responseAcceptedByResolver))
                    << '\t'
                    << compactJson(dnslab::json::Value(secondQueryHitByResolver))
                    << '\t'
                    << compactJson(dnslab::json::Value(cacheEntryCreatedByResolver))
                    << '\n';

        FailureTaxonomy
            << Result.Identity.SampleId << '\t'
            << Result.Triage.FailureBucketPrimary << '\t'
            << Result.Triage.FailureBucketDetail << '\t'
            << Result.Triage.AnalysisState << '\t'
            << Result.Triage.ExcludeReason.value_or("_") << '\t'
            << Result.Triage.SemanticOutcome << '\n';
      }

      const auto Comparability =
          dnslab::buildRunComparabilityPayload(MetaRecords);
      const auto Clusters = dnslab::clusterByFingerprint(ClusterRecords);
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

      std::ofstream AblationMatrix(RunRoot / "ablation_matrix.tsv");
      AblationMatrix << "module\tstatus\n";
      AblationMatrix << "mutator\ton\n";
      AblationMatrix << "cache-delta\ton\n";
      AblationMatrix << "triage\ton\n";
      AblationMatrix << "symcc\ton\n";

      std::ofstream ClusterCounts(RunRoot / "cluster_counts.tsv");
      ClusterCounts << "cluster_key\tcount\n";
      if (Clusters.empty()) {
        ClusterCounts << "_\t0\n";
      } else {
        for (const auto &Cluster : Clusters) {
          ClusterCounts << Cluster.ClusterKey << '\t' << Cluster.SampleCount
                        << '\n';
        }
      }

      std::ofstream ExclusionSummary(RunRoot / "exclusion_summary.tsv");
      ExclusionSummary << "failure_bucket_primary\tanalysis_state\tcount\n";
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
                         << FailurePrimaryCounts[Primary] << '\n';
      }
      ExclusionSummary << "__total__\t-\t" << Results.size() << '\n';

      const size_t ManifestSize = Results.size();
      const size_t ReproducedCount = CompletedCount;
      const double ReproRate =
          ManifestSize == 0 ? 0.0
                            : static_cast<double>(ReproducedCount) /
                                  static_cast<double>(ManifestSize);
      std::ofstream ReproRateFile(RunRoot / "repro_rate.tsv");
      ReproRateFile << "metric\tvalue\n";
      ReproRateFile << "manifest_size\t" << ManifestSize << '\n';
      ReproRateFile << "reproduced_count\t" << ReproducedCount << '\n';
      ReproRateFile << "repro_rate\t" << ReproRate << '\n';

      dnslab::json::Value::Object OracleReliability;
      dnslab::json::Value::Object Signals;
      for (const auto &SignalName : {"response_accepted_any", "second_query_hit_any",
                                     "cache_entry_created_any", "oracle_diff_any"}) {
        dnslab::json::Value::Object Bucket;
        Bucket["eligible_count"] =
            static_cast<std::int64_t>(SignalEligibleCounts[SignalName]);
        Bucket["pending_manual_count"] =
            static_cast<std::int64_t>(SignalPendingCounts[SignalName]);
        Bucket["judged_count"] = static_cast<std::int64_t>(0);
        Bucket["confirmed_relevant_count"] = static_cast<std::int64_t>(0);
        Bucket["false_positive_count"] = static_cast<std::int64_t>(0);
        Bucket["inconclusive_count"] = static_cast<std::int64_t>(0);
        Signals[SignalName] = Bucket;
      }
      dnslab::json::Value::Object SignalCombos;
      dnslab::json::Value::Object ComboBucket;
      ComboBucket["eligible_count"] = static_cast<std::int64_t>(
          SignalEligibleCounts["oracle_diff_plus_cache_diff"]);
      ComboBucket["pending_manual_count"] = static_cast<std::int64_t>(
          SignalPendingCounts["oracle_diff_plus_cache_diff"]);
      ComboBucket["judged_count"] = static_cast<std::int64_t>(0);
      ComboBucket["confirmed_relevant_count"] = static_cast<std::int64_t>(0);
      ComboBucket["false_positive_count"] = static_cast<std::int64_t>(0);
      ComboBucket["inconclusive_count"] = static_cast<std::int64_t>(0);
      SignalCombos["oracle_diff_plus_cache_diff"] = ComboBucket;
      OracleReliability["signals"] = Signals;
      OracleReliability["signal_combos"] = SignalCombos;
      writeJsonFile(RunRoot / "oracle_reliability.json",
                    dnslab::json::Value(OracleReliability));

      dnslab::json::Value::Object Summary;
      Summary["generated_at"] = dnslab::utcTimestampNow();
      Summary["status"] = FailedCount == 0 ? "success" : "partial_failure";
      Summary["compatibility_secondary_resolver"] = SecondaryResolverName;
      Summary["sample_count"] = static_cast<std::int64_t>(Results.size());
      Summary["completed_count"] = static_cast<std::int64_t>(CompletedCount);
      Summary["failed_count"] = static_cast<std::int64_t>(FailedCount);
      Summary["diff_detected_sample_count"] =
          static_cast<std::int64_t>(DiffDetectedCount);
      dnslab::json::Value::Object AnalysisStateCounts;
      AnalysisStateCounts["included"] = static_cast<std::int64_t>(IncludedCount);
      AnalysisStateCounts["excluded"] = static_cast<std::int64_t>(ExcludedCount);
      AnalysisStateCounts["unknown"] = static_cast<std::int64_t>(UnknownCount);
      Summary["analysis_state"] = AnalysisStateCounts;
      dnslab::json::Value::Array ExecutedResolversSummary;
      for (const auto &[ResolverName, Count] : ExecutedResolverSampleCounts) {
        (void)Count;
        ExecutedResolversSummary.emplace_back(ResolverName);
      }
      Summary["executed_resolvers"] = ExecutedResolversSummary;
      dnslab::json::Value::Object ExecutedResolverCounts;
      for (const auto &[ResolverName, Count] : ExecutedResolverSampleCounts) {
        ExecutedResolverCounts[ResolverName] =
            static_cast<std::int64_t>(Count);
      }
      Summary["executed_resolver_sample_counts"] =
          dnslab::json::Value(ExecutedResolverCounts);
      dnslab::json::Value::Object SkippedResolverCounts;
      for (const auto &[ResolverName, Count] : SkippedResolverSampleCounts) {
        SkippedResolverCounts[ResolverName] =
            static_cast<std::int64_t>(Count);
      }
      Summary["skipped_resolver_sample_counts"] =
          dnslab::json::Value(SkippedResolverCounts);
      dnslab::json::Value::Object ResolverDiffCounts;
      for (const auto &[ResolverPair, Count] : ResolverPairDiffCounts) {
        ResolverDiffCounts[ResolverPair] = static_cast<std::int64_t>(Count);
      }
      Summary["resolver_pair_diff_counts"] =
          dnslab::json::Value(ResolverDiffCounts);
      Summary["oracle_audit_candidate_count"] =
          static_cast<std::int64_t>(OracleAuditCount);
      Summary["case_study_candidate_count"] =
          static_cast<std::int64_t>(CaseStudyCount);
      Summary["cluster_count"] = static_cast<std::int64_t>(Clusters.size());
      Summary["contract_version"] = dnslab::kContractVersion;
      Summary["manifest_size"] = static_cast<std::int64_t>(ManifestSize);
      Summary["reproduced_count"] = static_cast<std::int64_t>(ReproducedCount);
      Summary["repro_rate"] = ReproRate;
      Summary["comparability"] = dnslab::toJson(Comparability);
      writeJsonFile(RunRoot / "summary.json", dnslab::json::Value(Summary));

      const auto BatchSyncReplayCommand =
          SelfExecutableCommand + " batch-sync-replay";
      std::vector<dnslab::ReportArtifact> Artifacts = {
          {"summary", (RunRoot / "summary.json").string(),
           BatchSyncReplayCommand},
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
          {"cluster", (RunRoot / "cluster.tsv").string(),
           BatchSyncReplayCommand},
          {"case_studies_index", (RunRoot / "case_studies/index.tsv").string(),
           BatchSyncReplayCommand},
      };
      const auto Bundle = dnslab::buildEvidenceBundle(
          std::optional<std::string>("manual-batch"), std::nullopt,
          Comparability, Clusters, Artifacts);
      writeJsonFile(RunRoot / "evidence_bundle.json", dnslab::toJson(Bundle));

      dnslab::json::Value::Object Output;
      Output["run_root"] = RunRoot.string();
      Output["sample_count"] = static_cast<std::int64_t>(Results.size());
      Output["summary"] = Summary;
      Output["evidence_bundle"] = (RunRoot / "evidence_bundle.json").string();
      std::cout << dnslab::json::Value(Output).dump(2) << '\n';
      return FailedCount == 0 ? 0 : 4;
    }

    if (Command == "oracle-parse") {
      const auto Parsed = dnslab::parseOracleSummary(
          readTextFile(requireOption(Args, "--stderr-file")),
          requireOption(Args, "--resolver"));
      std::cout << dnslab::toJson(Parsed).dump(2) << '\n';
      return 0;
    }

    if (Command == "report") {
      const auto Root = std::filesystem::path(requireOption(Args, "--root"));
      std::optional<std::filesystem::path> HighValueManifestPath;
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--high-value-manifest") {
          HighValueManifestPath = std::filesystem::path(Args[Index + 1]);
        }
      }
      if (!HighValueManifestPath.has_value()) {
        if (const char *EnvManifest = std::getenv("SYMCC_HIGH_VALUE_MANIFEST")) {
          if (*EnvManifest != '\0') {
            HighValueManifestPath = std::filesystem::path(EnvManifest);
          }
        }
      }
      const auto Artifacts =
          dnslab::generateTriageReportArtifacts(Root, HighValueManifestPath);
      std::cout << dnslab::toJson(Artifacts).dump(2) << '\n';
      return 0;
    }

    if (Command == "follow-diff-once") {
      const auto Artifacts = dnslab::runFollowDiffOnce();
      std::cout << dnslab::toJson(Artifacts).dump(2) << '\n';
      return Artifacts.ExitCode;
    }

    if (Command == "follow-diff-window") {
      const double BudgetSec =
          std::stod(requireOption(Args, "--budget-sec"));
      const bool RetryFailed =
          std::find(Args.begin(), Args.end(), "--retry-failed") != Args.end();
      const auto QueueTailId = optionalOption(Args, "--queue-tail-id");
      const auto Artifacts =
          dnslab::runFollowDiffWindow(BudgetSec, RetryFailed, QueueTailId);
      std::cout << dnslab::toJson(Artifacts).dump(2) << '\n';
      return Artifacts.ExitCode;
    }

    if (Command == "campaign-close") {
      const double BudgetSec =
          std::stod(requireOption(Args, "--budget-sec"));
      const auto Artifacts = dnslab::runCampaignClose(BudgetSec);
      std::cout << dnslab::toJson(Artifacts).dump(2) << '\n';
      return Artifacts.ExitCode;
    }

    if (Command == "campaign-report") {
      const auto Root = std::filesystem::path(requireOption(Args, "--root"));
      std::optional<std::filesystem::path> OutputDir;
      if (const auto Option = optionalOption(Args, "--output-dir")) {
        OutputDir = std::filesystem::path(*Option);
      }
      const auto Artifacts =
          dnslab::generateCampaignReportArtifacts(Root, OutputDir);
      std::cout << dnslab::toJson(Artifacts).dump(2) << '\n';
      return 0;
    }

    if (Command == "case-study-export") {
      const auto Root = std::filesystem::path(requireOption(Args, "--root"));
      const auto ReportDir =
          std::filesystem::path(requireOption(Args, "--campaign-report-dir"));
      size_t TopN = 5;
      if (const auto Option = optionalOption(Args, "--top-n")) {
        const auto Parsed = std::stoll(*Option);
        if (Parsed < 0) {
          throw std::runtime_error("--top-n 不能为负数: " + *Option);
        }
        TopN = static_cast<size_t>(Parsed);
      }
      const auto Artifacts =
          dnslab::exportCaseStudies(Root, ReportDir, TopN);
      std::cout << dnslab::toJson(Artifacts).dump(2) << '\n';
      return 0;
    }

    if (Command == "evidence-bundle") {
      const auto buildArtifact = [&](const std::string &Kind,
                                     const std::string &PathArg,
                                     const std::string &CmdArg) {
        dnslab::ReportArtifact Artifact;
        Artifact.Kind = Kind;
        Artifact.Path = requireOption(Args, PathArg);
        for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
          if (Args[Index] == CmdArg) {
            Artifact.RegenerateCommand = Args[Index + 1];
          }
        }
        return Artifact;
      };

      std::optional<std::string> RunId;
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--run-id") {
          RunId = Args[Index + 1];
        }
      }

      std::vector<dnslab::ReportArtifact> Artifacts;
      Artifacts.push_back(
          buildArtifact("summary", "--summary", "--summary-cmd"));
      Artifacts.push_back(buildArtifact("oracle_audit", "--oracle-audit",
                                        "--oracle-audit-cmd"));
      Artifacts.push_back(buildArtifact("failure_taxonomy",
                                        "--failure-taxonomy",
                                        "--failure-taxonomy-cmd"));
      Artifacts.push_back(
          buildArtifact("cluster", "--cluster", "--cluster-cmd"));
      Artifacts.push_back(
          buildArtifact("case_studies_index", "--case-index", "--case-index-cmd"));

      const auto Bundle = dnslab::buildEvidenceBundle(
          RunId, std::nullopt, dnslab::RunComparabilityPayload{}, {}, Artifacts);
      const auto OutputPath = requireOption(Args, "--output");
      std::ofstream Output(OutputPath);
      if (!Output) {
        throw std::runtime_error("无法写入文件: " + OutputPath);
      }
      Output << dnslab::toJson(Bundle).dump(2) << '\n';
      std::cout << dnslab::toJson(Bundle).dump(2) << '\n';
      return 0;
    }

    printUsage();
    return 2;
  } catch (const std::exception &Error) {
    std::cerr << Error.what() << '\n';
    return 1;
  }
}
