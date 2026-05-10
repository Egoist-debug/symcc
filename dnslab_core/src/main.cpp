#include "dnslab_core/concrete_adapters.hpp"
#include "dnslab_core/cache_analysis.hpp"
#include "dnslab_core/evidence_contract.hpp"
#include "dnslab_core/oracle.hpp"
#include "dnslab_core/reporting.hpp"
#include "dnslab_core/resolver_lock.hpp"
#include "dnslab_core/transcript.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <cstdlib>
#include <algorithm>
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
         " [--secondary-source-root <path>]\n"
      << "  dnslabctl batch-sync-replay --sample-dir <path> --run-root <path>"
         " --bind9-build-root <path> --unbound-build-root <path>"
         " [--bind9-source-root <path>] [--unbound-source-root <path>]"
         " [--limit <n>]\n"
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
          return dnslab::defaultSubjectRoot(WorkspaceRoot, ResolverName, *Tag);
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
          }
        };

    const auto executeSyncReplay =
        [&](const std::filesystem::path &SamplePath,
            const std::filesystem::path &RunRoot, bool NestBySampleId,
            const std::filesystem::path &Bind9BuildRoot,
            const std::filesystem::path &SecondaryBuildRoot,
            const std::filesystem::path &Bind9SourceRoot,
            const std::filesystem::path &SecondarySourceRoot,
            const std::string &SecondaryResolverName) {
          const auto Registry =
              dnslab::makeDefaultResolverRegistry(std::filesystem::current_path());
          const auto &Bind9Adapter = Registry.require("bind9");
          const auto &SecondaryAdapter = Registry.require(SecondaryResolverName);

          setResolverBuildEnv("bind9", Bind9BuildRoot);
          setResolverBuildEnv(SecondaryResolverName, SecondaryBuildRoot);

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

          const auto Bind9Result = runSingleResolver(
              "bind9", Bind9Adapter, Bind9SourceRoot, Bind9BuildRoot);
          const auto SecondaryResult = runSingleResolver(
              SecondaryResolverName, SecondaryAdapter, SecondarySourceRoot,
              SecondaryBuildRoot);

          dnslab::json::Value::Object OraclePayload = Bind9Result.Oracle.Fields;
          for (const auto &[Key, Value] : SecondaryResult.Oracle.Fields) {
            OraclePayload[Key] = Value;
          }

          auto NormalizedOraclePayload = OraclePayload;
          if (SecondaryResolverName != "unbound") {
            for (const auto &[Key, Value] : SecondaryResult.Oracle.Fields) {
              const std::string Prefix = SecondaryResolverName + ".";
              if (Key.rfind(Prefix, 0) != 0) {
                continue;
              }
              const auto Suffix = Key.substr(Prefix.size());
              NormalizedOraclePayload.emplace("unbound." + Suffix, Value);
            }
          }

          const auto normalizeSecondaryRows =
              [&](std::vector<dnslab::CacheRecord> Rows) {
                if (SecondaryResolverName == "unbound") {
                  return Rows;
                }
                for (auto &Row : Rows) {
                  Row.Resolver = "unbound";
                }
                return Rows;
              };

          const auto Bind9BeforeRows =
              dnslab::parseCacheDump("bind9", Bind9Result.BeforeCache);
          const auto Bind9AfterRows =
              dnslab::parseCacheDump("bind9", Bind9Result.AfterCache);
          const auto SecondaryBeforeRows = normalizeSecondaryRows(
              dnslab::parseCacheDump(SecondaryResolverName,
                                     SecondaryResult.BeforeCache));
          const auto SecondaryAfterRows = normalizeSecondaryRows(
              dnslab::parseCacheDump(SecondaryResolverName,
                                     SecondaryResult.AfterCache));
          const auto PreliminaryCacheDiff = dnslab::buildCacheDiff(
              SampleIdentity.SampleId, Bind9BeforeRows, Bind9AfterRows,
              SecondaryBeforeRows, SecondaryAfterRows, false);
          const bool Triggered = PreliminaryCacheDiff.Bind9.HasCacheDiff ||
                                 PreliminaryCacheDiff.Unbound.HasCacheDiff;
          const auto CacheDiff = dnslab::buildCacheDiff(
              SampleIdentity.SampleId, Bind9BeforeRows, Bind9AfterRows,
              SecondaryBeforeRows, SecondaryAfterRows, Triggered);

          dnslab::StateFingerprint Fingerprint;
          Fingerprint.SchemaVersion = dnslab::kSchemaVersion;
          Fingerprint.GeneratedAt = dnslab::utcTimestampNow();
          Fingerprint.SampleId = SampleIdentity.SampleId;

          std::filesystem::create_directories(ArtifactRoot);
          std::filesystem::copy_file(
              SamplePath, ArtifactRoot / "sample.bin",
              std::filesystem::copy_options::overwrite_existing);
          writeJsonFile(ArtifactRoot / "oracle.json",
                        dnslab::json::Value(OraclePayload));

          SyncReplayResult Result;
          Result.Identity = SampleIdentity;
          Result.Fingerprint = Fingerprint;
          Result.OraclePayload = OraclePayload;
          Result.Bind9 = Bind9Result;
          Result.Secondary = SecondaryResult;
          Result.SecondaryResolver = SecondaryResolverName;
          Result.ArtifactDir = ArtifactRoot;
          Result.Failed = Bind9Result.RunResult.ExitCode != 0 ||
                          SecondaryResult.RunResult.ExitCode != 0;

          std::optional<dnslab::FailureEvidence> Failure;
          if (Bind9Result.RunResult.ExitCode != 0) {
            dnslab::FailureEvidence Evidence;
            Evidence.Kind = "replay_error";
            Evidence.Reason = "subprocess_failed";
            Evidence.Stage = "bind9.after";
            Evidence.Resolver = "bind9";
            Evidence.ProcessStarted = true;
            Failure = Evidence;
          } else if (SecondaryResult.RunResult.ExitCode != 0) {
            dnslab::FailureEvidence Evidence;
            Evidence.Kind = "replay_error";
            Evidence.Reason = "subprocess_failed";
            Evidence.Stage = SecondaryResolverName + ".after";
            Evidence.Resolver = SecondaryResolverName;
            Evidence.ProcessStarted = true;
            Failure = Evidence;
          }

          const auto Triage = dnslab::buildTriageRecord(
              SampleIdentity.SampleId, NormalizedOraclePayload, CacheDiff,
              Fingerprint, Failure);

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
          Meta.Aggregation.BudgetSec = 0;
          Meta.Aggregation.SeedTimeoutSec = 5;
          Meta.Aggregation.VariantName = "full_stack";
          Meta.Aggregation.AblationStatus = "enabled";
          Meta.BaselineCompare.ResolverPair = "bind9_vs_" + SecondaryResolverName;
          Meta.BaselineCompare.ProducerProfile = "poison-stateful";
          Meta.BaselineCompare.InputModel = "DST1 transcript";
          Meta.BaselineCompare.SourceQueueDir = SamplePath.parent_path().string();
          Meta.BaselineCompare.BudgetSec = 0;
          Meta.BaselineCompare.SeedTimeoutSec = 5;
          Meta.BaselineCompare.RepeatCount = 1;
          Meta.Failure = Failure;
          writeJsonFile(ArtifactRoot / "sample.meta.json", dnslab::toJson(Meta));
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
      }

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
      }

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
          Bind9SourceRoot, SecondarySourceRoot, SecondaryResolverName);

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
      const auto UnboundBuildRoot =
          std::filesystem::path(requireOption(Args, "--unbound-build-root"));
      std::filesystem::path Bind9SourceRoot =
          resolveDefaultSourceRoot("bind9", Bind9BuildRoot);
      std::filesystem::path UnboundSourceRoot =
          resolveDefaultSourceRoot("unbound", UnboundBuildRoot);
      std::optional<size_t> Limit;
      for (size_t Index = 0; Index + 1 < Args.size(); ++Index) {
        if (Args[Index] == "--bind9-source-root") {
          Bind9SourceRoot = Args[Index + 1];
        } else if (Args[Index] == "--unbound-source-root") {
          UnboundSourceRoot = Args[Index + 1];
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
                                            Bind9BuildRoot, UnboundBuildRoot,
                                            Bind9SourceRoot, UnboundSourceRoot,
                                            "unbound"));
      }

      const auto boolText = [](const std::optional<bool> &Value) {
        if (!Value.has_value()) {
          return std::string("null");
        }
        return *Value ? std::string("true") : std::string("false");
      };

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

      std::ofstream OracleAudit(RunRoot / "oracle_audit.tsv");
      OracleAudit
          << "sample_id\tanalysis_state\tstatus\tsemantic_outcome\toracle_audit_candidate\tcase_study_candidate\tbind9.response_accepted\tunbound.response_accepted\tbind9.second_query_hit\tunbound.second_query_hit\tbind9.cache_entry_created\tunbound.cache_entry_created\n";

      std::ofstream FailureTaxonomy(RunRoot / "failure_taxonomy.tsv");
      FailureTaxonomy
          << "sample_id\tfailure_bucket_primary\tfailure_bucket_detail\tanalysis_state\texclude_reason\tsemantic_outcome\n";

      std::ofstream ClusterFile(RunRoot / "cluster.tsv");
      ClusterFile
          << "cluster_key\tanalysis_state\tresolver_pair\tvariant_name\tfingerprint_key\tsample_count\tsample_ids\n";

      std::ofstream CaseStudyIndex(RunRoot / "case_studies" / "index.tsv");
      CaseStudyIndex
          << "sample_id\tsemantic_outcome\tselection_reason\tcase_study_path\treplay_command\n";

      std::vector<dnslab::SampleMeta> MetaRecords;
      std::vector<dnslab::ClusterRecord> ClusterRecords;
      size_t CompletedCount = 0;
      size_t FailedCount = 0;
      size_t IncludedCount = 0;
      size_t ExcludedCount = 0;
      size_t UnknownCount = 0;
      size_t OracleAuditCount = 0;
      size_t CaseStudyCount = 0;
      std::map<std::string, int> FailurePrimaryCounts;
      std::map<std::string, int> SignalEligibleCounts;
      std::map<std::string, int> SignalPendingCounts;

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
        if (Result.Triage.CaseStudyCandidate) {
          ++CaseStudyCount;
          const auto CaseStudyPath =
              RunRoot / "case_studies" / (Result.Identity.SampleId + ".md");
          const std::string ReplayCommand =
              "./build/linux/x86_64/release/dnslabctl sync-replay --sample " +
              Result.Meta.SourceQueueFile.value_or("_") + " --run-root " +
              Result.ArtifactDir.string() + " --bind9-build-root " +
              Bind9BuildRoot.string() + " --unbound-build-root " +
              UnboundBuildRoot.string();
          std::ofstream CaseStudyFile(CaseStudyPath);
          CaseStudyFile << "# " << Result.Identity.SampleId << "\n\n";
          CaseStudyFile << "- semantic_outcome: " << Result.Triage.SemanticOutcome
                        << "\n";
          CaseStudyFile << "- manual_truth_status: "
                        << Result.Triage.ManualTruthStatus << "\n";
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
          CaseStudyFile << "- bind9_before_cache: "
                        << Result.Bind9.BeforeCache.string() << "\n";
          CaseStudyFile << "- bind9_after_cache: "
                        << Result.Bind9.AfterCache.string() << "\n";
          CaseStudyFile << "- unbound_before_cache: "
                        << Result.Secondary.BeforeCache.string() << "\n";
          CaseStudyFile << "- unbound_after_cache: "
                        << Result.Secondary.AfterCache.string() << "\n";
          CaseStudyFile << "- bind9_logs:\n";
          for (const auto &Path : Result.Bind9.Logs) {
            CaseStudyFile << "  - " << Path.string() << "\n";
          }
          CaseStudyFile << "- unbound_logs:\n";
          for (const auto &Path : Result.Secondary.Logs) {
            CaseStudyFile << "  - " << Path.string() << "\n";
          }
          CaseStudyFile << "- replay_command: `" << ReplayCommand << "`\n";

          CaseStudyIndex << Result.Identity.SampleId << '\t'
                         << Result.Triage.SemanticOutcome << '\t'
                         << "oracle_audit_candidate" << '\t'
                         << CaseStudyPath.string() << '\t' << ReplayCommand
                         << '\n';
        }

        const bool OracleEligible = Result.Triage.AnalysisState == "included" &&
                                    Result.Triage.OracleAuditCandidate;
        const auto bind9ResponseAccepted =
            objectBool(Result.OraclePayload, "bind9.response_accepted")
                .value_or(false);
        const auto unboundResponseAccepted =
            objectBool(Result.OraclePayload, "unbound.response_accepted")
                .value_or(false);
        const auto bind9SecondHit =
            objectBool(Result.OraclePayload, "bind9.second_query_hit")
                .value_or(false);
        const auto unboundSecondHit =
            objectBool(Result.OraclePayload, "unbound.second_query_hit")
                .value_or(false);
        const auto bind9CacheCreated =
            objectBool(Result.OraclePayload, "bind9.cache_entry_created")
                .value_or(false);
        const auto unboundCacheCreated =
            objectBool(Result.OraclePayload, "unbound.cache_entry_created")
                .value_or(false);
        const bool OracleDiffAny = bind9ResponseAccepted != unboundResponseAccepted ||
                                   bind9SecondHit != unboundSecondHit ||
                                   bind9CacheCreated != unboundCacheCreated;
        const bool CacheDiffAny = Result.CacheDiff.Bind9.HasCacheDiff ||
                                  Result.CacheDiff.Unbound.HasCacheDiff;
        updateSignal("response_accepted_any",
                     OracleEligible &&
                         (bind9ResponseAccepted || unboundResponseAccepted));
        updateSignal("second_query_hit_any",
                     OracleEligible && (bind9SecondHit || unboundSecondHit));
        updateSignal("cache_entry_created_any",
                     OracleEligible && (bind9CacheCreated || unboundCacheCreated));
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
                    << boolText(objectBool(Result.OraclePayload,
                                           "bind9.response_accepted"))
                    << '\t'
                    << boolText(objectBool(Result.OraclePayload,
                                           "unbound.response_accepted"))
                    << '\t'
                    << boolText(objectBool(Result.OraclePayload,
                                           "bind9.second_query_hit"))
                    << '\t'
                    << boolText(objectBool(Result.OraclePayload,
                                           "unbound.second_query_hit"))
                    << '\t'
                    << boolText(objectBool(Result.OraclePayload,
                                           "bind9.cache_entry_created"))
                    << '\t'
                    << boolText(objectBool(Result.OraclePayload,
                                           "unbound.cache_entry_created"))
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
      Summary["sample_count"] = static_cast<std::int64_t>(Results.size());
      Summary["completed_count"] = static_cast<std::int64_t>(CompletedCount);
      Summary["failed_count"] = static_cast<std::int64_t>(FailedCount);
      dnslab::json::Value::Object AnalysisStateCounts;
      AnalysisStateCounts["included"] = static_cast<std::int64_t>(IncludedCount);
      AnalysisStateCounts["excluded"] = static_cast<std::int64_t>(ExcludedCount);
      AnalysisStateCounts["unknown"] = static_cast<std::int64_t>(UnknownCount);
      Summary["analysis_state"] = AnalysisStateCounts;
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

      std::vector<dnslab::ReportArtifact> Artifacts = {
          {"summary", (RunRoot / "summary.json").string(),
           "./build/linux/x86_64/release/dnslabctl batch-sync-replay"},
          {"ablation_matrix", (RunRoot / "ablation_matrix.tsv").string(),
           "./build/linux/x86_64/release/dnslabctl batch-sync-replay"},
          {"cluster_counts", (RunRoot / "cluster_counts.tsv").string(),
           "./build/linux/x86_64/release/dnslabctl batch-sync-replay"},
          {"repro_rate", (RunRoot / "repro_rate.tsv").string(),
           "./build/linux/x86_64/release/dnslabctl batch-sync-replay"},
          {"oracle_audit", (RunRoot / "oracle_audit.tsv").string(),
           "./build/linux/x86_64/release/dnslabctl batch-sync-replay"},
          {"oracle_reliability", (RunRoot / "oracle_reliability.json").string(),
           "./build/linux/x86_64/release/dnslabctl batch-sync-replay"},
          {"failure_taxonomy", (RunRoot / "failure_taxonomy.tsv").string(),
           "./build/linux/x86_64/release/dnslabctl batch-sync-replay"},
          {"exclusion_summary", (RunRoot / "exclusion_summary.tsv").string(),
           "./build/linux/x86_64/release/dnslabctl batch-sync-replay"},
          {"cluster", (RunRoot / "cluster.tsv").string(),
           "./build/linux/x86_64/release/dnslabctl batch-sync-replay"},
          {"case_studies_index", (RunRoot / "case_studies/index.tsv").string(),
           "./build/linux/x86_64/release/dnslabctl batch-sync-replay"},
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
