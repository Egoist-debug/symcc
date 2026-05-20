#include "dnslab_core/concrete_adapters.hpp"

#include "dnslab_core/oracle.hpp"

#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>

namespace dnslab {

namespace {

std::filesystem::path requireExisting(const std::filesystem::path &InputPath,
                                      const std::string &Message) {
  if (!std::filesystem::exists(InputPath)) {
    throw std::runtime_error(Message + ": " + InputPath.string());
  }
  return InputPath;
}

CommandResult copyPatchTree(const std::filesystem::path &PatchRoot,
                            const std::filesystem::path &SourceRoot) {
  if (!std::filesystem::is_directory(PatchRoot)) {
    throw std::runtime_error("patch 目录不存在: " + PatchRoot.string());
  }
  for (const auto &Entry : std::filesystem::recursive_directory_iterator(PatchRoot)) {
    if (!Entry.is_regular_file()) {
      continue;
    }
    const auto Relative = std::filesystem::relative(Entry.path(), PatchRoot);
    const auto Target = SourceRoot / Relative;
    std::filesystem::create_directories(Target.parent_path());
    std::filesystem::copy_file(Entry.path(), Target,
                               std::filesystem::copy_options::overwrite_existing);
  }
  return {0, "", ""};
}

std::filesystem::path cloneIfMissing(const std::filesystem::path &WorkspaceRoot,
                                     const std::string &Resolver,
                                     const std::string &Tag,
                                     const std::string &RepoUrl) {
  const auto SubjectRoot = defaultSubjectRoot(WorkspaceRoot, Resolver, Tag);
  if (std::filesystem::exists(SubjectRoot)) {
    return SubjectRoot;
  }
  std::filesystem::create_directories(SubjectRoot.parent_path());
  const CommandResult Result = runProcess({
      {"git", "clone", "--depth", "1", "--branch", Tag, RepoUrl,
       SubjectRoot.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  if (Result.ExitCode != 0) {
    throw std::runtime_error("git clone 失败: " + Result.StderrText);
  }
  return SubjectRoot;
}

std::optional<std::filesystem::path>
prepareBind9ReleaseTarballIfAvailable(const std::filesystem::path &WorkspaceRoot,
                                      const std::string &Tag) {
  if (Tag.empty() || Tag.front() != 'v') {
    return std::nullopt;
  }

  const auto Version = Tag.substr(1);
  const auto SubjectRoot = defaultSubjectRoot(WorkspaceRoot, "bind9", Tag);
  if (std::filesystem::exists(SubjectRoot)) {
    return SubjectRoot;
  }

  const auto ParentRoot = SubjectRoot.parent_path();
  const auto ExtractedRoot = ParentRoot / ("bind-" + Version);
  const auto ArchivePath = ParentRoot / ("bind-" + Version + ".tar.xz");
  const auto ReleaseUrl =
      "https://downloads.isc.org/isc/bind9/" + Version + "/bind-" + Version +
      ".tar.xz";

  auto cleanupPath = [](const std::filesystem::path &Path) {
    std::error_code Error;
    std::filesystem::remove_all(Path, Error);
  };

  cleanupPath(SubjectRoot);
  cleanupPath(ExtractedRoot);
  cleanupPath(ArchivePath);
  std::filesystem::create_directories(ParentRoot);

  const CommandResult DownloadResult = runProcess({
      {"curl", "-fsSL", ReleaseUrl, "-o", ArchivePath.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  if (DownloadResult.ExitCode != 0) {
    cleanupPath(ArchivePath);
    return std::nullopt;
  }

  const CommandResult ExtractResult = runProcess({
      {"tar", "-xJf", ArchivePath.string(), "-C", ParentRoot.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  cleanupPath(ArchivePath);
  if (ExtractResult.ExitCode != 0 || !std::filesystem::exists(ExtractedRoot)) {
    cleanupPath(ExtractedRoot);
    return std::nullopt;
  }

  std::filesystem::rename(ExtractedRoot, SubjectRoot);

  const CommandResult GitInitResult = runProcess({
      {"git", "-C", SubjectRoot.string(), "init", "-q"},
      std::nullopt,
      {},
      std::nullopt,
  });
  if (GitInitResult.ExitCode == 0) {
    runProcess({
        {"git", "-C", SubjectRoot.string(), "add", "-A"},
        std::nullopt,
        {},
        std::nullopt,
    });
    runProcess({
        {"git", "-C", SubjectRoot.string(),
         "-c", "user.name=dnslabctl",
         "-c", "user.email=dnslabctl@example.invalid",
         "commit", "-q", "-m",
         "Import bind9 " + Tag + " release tarball"},
        std::nullopt,
        {},
        std::nullopt,
    });
  }

  return SubjectRoot;
}

void renderNamedConf(const std::filesystem::path &TemplatePath,
                     const std::filesystem::path &RuntimeDir,
                     const std::filesystem::path &OutputPath) {
  const auto Template = requireExisting(TemplatePath, "缺少 named.conf 模板");
  std::ifstream Input(Template);
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  std::string Text = Buffer.str();
  const std::string Needle = "__RUNTIME_STATE_DIR__";
  const auto Position = Text.find(Needle);
  if (Position != std::string::npos) {
    Text.replace(Position, Needle.size(), RuntimeDir.string());
  }
  std::filesystem::create_directories(OutputPath.parent_path());
  std::ofstream Output(OutputPath);
  Output << Text;
}

std::filesystem::path firstExisting(
    const std::vector<std::filesystem::path> &Candidates) {
  for (const auto &Candidate : Candidates) {
    if (std::filesystem::exists(Candidate)) {
      return Candidate;
    }
  }
  return {};
}

std::string collectDotLibs(const std::filesystem::path &TreeRoot) {
  std::set<std::string> LibDirs;
  if (!std::filesystem::is_directory(TreeRoot)) {
    return "";
  }
  for (const auto &Entry : std::filesystem::recursive_directory_iterator(TreeRoot)) {
    if (!Entry.is_directory() || Entry.path().filename() != ".libs") {
      continue;
    }
    LibDirs.insert(std::filesystem::absolute(Entry.path()).string());
  }
  std::ostringstream Output;
  for (auto It = LibDirs.begin(); It != LibDirs.end(); ++It) {
    if (It != LibDirs.begin()) {
      Output << ':';
    }
    Output << *It;
  }
  return Output.str();
}

std::filesystem::path bind9BinaryPath(const Bind9AdapterConfig &Config,
                                      const std::filesystem::path &BuildRoot) {
  if (Config.BinaryPathOverride.has_value()) {
    return *Config.BinaryPathOverride;
  }
  const char *EnvBuildRoot = std::getenv("DNSLAB_BIND9_BUILD_ROOT");
  return firstExisting(
      {BuildRoot / "bin" / "named" / ".libs" / "named",
       BuildRoot / "bind9-afl" / "bin" / "named" / ".libs" / "named",
       EnvBuildRoot != nullptr
           ? std::filesystem::path(EnvBuildRoot) / "bin" / "named" / ".libs" /
                 "named"
           : std::filesystem::path(),
       EnvBuildRoot != nullptr
           ? std::filesystem::path(EnvBuildRoot) / "bind9-afl" / "bin" / "named" /
                 ".libs" / "named"
           : std::filesystem::path(),
       Config.WorkspaceRoot / "bind-9.18.46-afl" / "bin" / "named" / ".libs" /
           "named"});
}

std::filesystem::path unboundBinaryPath(const UnboundAdapterConfig &Config,
                                        const std::filesystem::path &BuildRoot) {
  if (Config.BinaryPathOverride.has_value()) {
    return *Config.BinaryPathOverride;
  }
  const char *EnvBuildRoot = std::getenv("DNSLAB_UNBOUND_BUILD_ROOT");
  return firstExisting({BuildRoot / ".libs" / "unbound-fuzzme",
                        BuildRoot / "unbound-afl" / ".libs" / "unbound-fuzzme",
                        EnvBuildRoot != nullptr
                            ? std::filesystem::path(EnvBuildRoot) / ".libs" /
                                  "unbound-fuzzme"
                            : std::filesystem::path(),
                        EnvBuildRoot != nullptr
                            ? std::filesystem::path(EnvBuildRoot) / "unbound-afl" /
                                  ".libs" / "unbound-fuzzme"
                            : std::filesystem::path(),
                        Config.WorkspaceRoot / "unbound-1.24.2-afl" / ".libs" /
                            "unbound-fuzzme"});
}

std::filesystem::path dnsmasqBinaryPath(const DnsmasqAdapterConfig &Config,
                                        const std::filesystem::path &BuildRoot) {
  if (Config.BinaryPathOverride.has_value()) {
    return *Config.BinaryPathOverride;
  }
  const char *EnvBuildRoot = std::getenv("DNSLAB_DNSMASQ_BUILD_ROOT");
  return firstExisting({BuildRoot / "dnsmasq",
                        BuildRoot / "dnsmasq-afl" / "dnsmasq",
                        EnvBuildRoot != nullptr
                            ? std::filesystem::path(EnvBuildRoot) / "dnsmasq"
                            : std::filesystem::path(),
                        EnvBuildRoot != nullptr
                            ? std::filesystem::path(EnvBuildRoot) / "dnsmasq-afl" /
                                  "dnsmasq"
                            : std::filesystem::path(),
                        Config.WorkspaceRoot / "experiments" / "subjects" /
                            "dnsmasq" / "v2.92-afl" / "dnsmasq",
                        Config.WorkspaceRoot / "dnsmasq-2.92-afl" / "dnsmasq"});
}

std::filesystem::path smartdnsBinaryPath(const SmartdnsAdapterConfig &Config,
                                         const std::filesystem::path &BuildRoot) {
  if (Config.BinaryPathOverride.has_value()) {
    return *Config.BinaryPathOverride;
  }
  const char *EnvBuildRoot = std::getenv("DNSLAB_SMARTDNS_BUILD_ROOT");
  return firstExisting({BuildRoot / "src" / "smartdns",
                        BuildRoot / "smartdns-build" / "src" / "smartdns",
                        BuildRoot / "smartdns",
                        EnvBuildRoot != nullptr
                            ? std::filesystem::path(EnvBuildRoot) / "src" / "smartdns"
                            : std::filesystem::path(),
                        EnvBuildRoot != nullptr
                            ? std::filesystem::path(EnvBuildRoot) / "smartdns-build" / "src" / "smartdns"
                            : std::filesystem::path(),
                        Config.WorkspaceRoot / "experiments" / "subjects" /
                            "smartdns" / "Release47.1-build" / "src" / "smartdns"});
}

std::filesystem::path maradnsBinaryPath(const MaradnsAdapterConfig &Config,
                                        const std::filesystem::path &BuildRoot) {
  if (Config.BinaryPathOverride.has_value()) {
    return *Config.BinaryPathOverride;
  }
  const char *EnvBuildRoot = std::getenv("DNSLAB_MARADNS_BUILD_ROOT");
  return firstExisting({BuildRoot / "deadwood-build" / "deadwood-github" / "src" / "Deadwood",
                        BuildRoot / "deadwood-github" / "src" / "Deadwood",
                        BuildRoot / "Deadwood",
                        EnvBuildRoot != nullptr
                            ? std::filesystem::path(EnvBuildRoot) / "deadwood-build" / "deadwood-github" / "src" / "Deadwood"
                            : std::filesystem::path(),
                        EnvBuildRoot != nullptr
                            ? std::filesystem::path(EnvBuildRoot) / "deadwood-github" / "src" / "Deadwood"
                            : std::filesystem::path(),
                        Config.WorkspaceRoot / "experiments" / "subjects" / "maradns" /
                            "deadwood-3.3.02-build" / "deadwood-github" / "src" / "Deadwood"});
}

std::filesystem::path knotResolverBinaryPath(
    const KnotResolverAdapterConfig &Config,
    const std::filesystem::path &BuildRoot) {
  if (Config.BinaryPathOverride.has_value()) {
    return *Config.BinaryPathOverride;
  }
  const char *EnvBuildRoot = std::getenv("DNSLAB_KNOT_RESOLVER_BUILD_ROOT");
  return firstExisting({BuildRoot / "knot-build" / "daemon" / "kresd",
                        BuildRoot / "daemon" / "kresd",
                        EnvBuildRoot != nullptr
                            ? std::filesystem::path(EnvBuildRoot) / "knot-build" /
                                  "daemon" / "kresd"
                            : std::filesystem::path(),
                        EnvBuildRoot != nullptr
                            ? std::filesystem::path(EnvBuildRoot) / "daemon" /
                                  "kresd"
                            : std::filesystem::path(),
                        Config.WorkspaceRoot / "experiments" / "subjects" /
                            "knot-resolver" / "v6.2.0-build" / "knot-build" /
                            "daemon" / "kresd"});
}

OracleArtifact makeOracleArtifact(const OracleSnapshot &Snapshot) {
  OracleArtifact Output;
  Output.ResolverName = Snapshot.Resolver;
  Output.ParseOk = Snapshot.ParseOk.value_or(false);
  const auto JsonValue = toJson(Snapshot);
  Output.Fields = std::get<json::Value::Object>(JsonValue.storage());
  return Output;
}

struct ScaffoldResolverAdapterConfig {
  std::filesystem::path WorkspaceRoot;
  std::string ResolverName;
  std::string RepoUrl;
  std::optional<std::filesystem::path> SourceFallbackPath;
};

class ScaffoldResolverAdapter final : public ResolverAdapter {
public:
  explicit ScaffoldResolverAdapter(ScaffoldResolverAdapterConfig Config)
      : Config_(std::move(Config)) {}

  std::string name() const override { return Config_.ResolverName; }

  std::filesystem::path
  prepareSource(const std::filesystem::path &WorkspaceRoot,
                const std::string &Tag) const override {
    const auto SubjectRoot =
        defaultSubjectRoot(WorkspaceRoot, Config_.ResolverName, Tag);
    if (std::filesystem::exists(SubjectRoot)) {
      return SubjectRoot;
    }
    if (Config_.SourceFallbackPath.has_value() &&
        std::filesystem::exists(*Config_.SourceFallbackPath)) {
      return *Config_.SourceFallbackPath;
    }
    return cloneIfMissing(WorkspaceRoot, Config_.ResolverName, Tag,
                          Config_.RepoUrl);
  }

  CommandResult
  applyPatch(const std::filesystem::path &SourceRoot,
             const std::filesystem::path &PatchFile) const override {
    if (std::filesystem::is_directory(PatchFile)) {
      return copyPatchTree(PatchFile, SourceRoot);
    }
    return runProcess({{"git", "-C", SourceRoot.string(), "apply",
                        PatchFile.string()},
                       std::nullopt,
                       {},
                       std::nullopt});
  }

  CommandResult build(const std::filesystem::path &SourceRoot,
                      const std::filesystem::path &BuildRoot) const override {
    std::filesystem::create_directories(BuildRoot);
    return unsupported("build", SourceRoot);
  }

  CommandResult runSample(const RunSampleRequest &Request) const override {
    std::filesystem::create_directories(Request.RunRoot);
    return unsupported("run-sample", Request.RunRoot);
  }

  CommandResult dumpCache(const std::filesystem::path &RunRoot,
                          const std::filesystem::path &OutputFile) const override {
    std::filesystem::create_directories(RunRoot);
    std::ofstream(OutputFile) << "";
    return unsupported("dump-cache", RunRoot);
  }

  CommandResult flushCache(const std::filesystem::path &RunRoot) const override {
    std::filesystem::remove_all(RunRoot);
    return {0, "", ""};
  }

  OracleArtifact
  parseOracle(const std::filesystem::path &OraclePath) const override {
    (void)OraclePath;
    OracleArtifact Output;
    Output.ResolverName = Config_.ResolverName;
    Output.ParseOk = false;
    Output.Fields["resolver"] = Config_.ResolverName;
    Output.Fields["parse_ok"] = false;
    Output.Fields["reason"] = "resolver scaffold only";
    return Output;
  }

  std::vector<std::filesystem::path>
  collectLogs(const std::filesystem::path &RunRoot) const override {
    if (std::filesystem::exists(RunRoot)) {
      return {RunRoot};
    }
    return {};
  }

private:
  CommandResult unsupported(const std::string &Stage,
                            const std::filesystem::path &ArtifactRoot) const {
    const std::string Message =
        "resolver scaffold only: " + Config_.ResolverName + " stage=" + Stage;
    std::ofstream(ArtifactRoot / (Config_.ResolverName + ".stderr")) << Message
                                                                      << '\n';
    return {95, "", Message};
  }

  ScaffoldResolverAdapterConfig Config_;
};

} // namespace

Bind9ResolverAdapter::Bind9ResolverAdapter(Bind9AdapterConfig Config)
    : Config_(std::move(Config)) {}

std::string Bind9ResolverAdapter::name() const { return "bind9"; }

std::filesystem::path
Bind9ResolverAdapter::prepareSource(const std::filesystem::path &WorkspaceRoot,
                                    const std::string &Tag) const {
  const auto SubjectRoot = defaultSubjectRoot(WorkspaceRoot, "bind9", Tag);
  if (std::filesystem::exists(SubjectRoot)) {
    return SubjectRoot;
  }
  if (Config_.SourceFallbackPath.has_value() &&
      std::filesystem::exists(*Config_.SourceFallbackPath)) {
    return *Config_.SourceFallbackPath;
  }
  const auto Legacy = WorkspaceRoot / "bind-9.18.46";
  if (std::filesystem::exists(Legacy)) {
    return Legacy;
  }
  if (const auto ReleaseTarballRoot =
          prepareBind9ReleaseTarballIfAvailable(WorkspaceRoot, Tag);
      ReleaseTarballRoot.has_value()) {
    return *ReleaseTarballRoot;
  }
  return cloneIfMissing(WorkspaceRoot, "bind9", Tag,
                        "https://gitlab.isc.org/isc-projects/bind9.git");
}

CommandResult
Bind9ResolverAdapter::applyPatch(const std::filesystem::path &SourceRoot,
                                 const std::filesystem::path &PatchFile) const {
  if (std::filesystem::is_directory(PatchFile)) {
    return copyPatchTree(PatchFile, SourceRoot);
  }
  return runProcess({{"git", "-C", SourceRoot.string(), "apply",
                      PatchFile.string()},
                     std::nullopt,
                     {},
                     std::nullopt});
}

CommandResult Bind9ResolverAdapter::build(const std::filesystem::path &SourceRoot,
                                          const std::filesystem::path &BuildRoot) const {
  const auto Script = requireExisting(Config_.ScriptPath, "缺少 named 构建脚本");
  std::filesystem::create_directories(BuildRoot);
  return runProcess({
      {Script.string(), "build"},
      Config_.WorkspaceRoot,
      {
          {"SRC_TREE", SourceRoot.string()},
          {"AFL_TREE", (BuildRoot / "bind9-afl").string()},
          {"SYMCC_TREE", (BuildRoot / "bind9-symcc").string()},
          {"WORK_DIR", (BuildRoot / "work").string()},
          {"PATCH_VARIANT", "cache"},
      },
      std::nullopt,
  });
}

CommandResult
Bind9ResolverAdapter::runSample(const RunSampleRequest &Request) const {
  const auto Binary = requireExisting(bind9BinaryPath(Config_, Request.BuildRoot),
                                      "缺少 bind9 可执行文件");
  const auto ResponseCorpusDir =
      requireExisting(Config_.ResponseCorpusDir, "缺少 bind9 response 语料目录");
  const auto LdLibraryPath = collectDotLibs(Request.BuildRoot);
  const auto RuntimeDir = Request.RunRoot / "bind9_runtime";
  const auto NamedConf = RuntimeDir / "named.conf";

  std::filesystem::create_directories(Request.RunRoot);
  renderNamedConf(Config_.NamedConfTemplate, RuntimeDir, NamedConf);
  const CommandResult Result = runProcess({
      {"timeout", "-k", "2", std::to_string(Config_.SeedTimeoutSec),
       Binary.string(), "-g", "-c", NamedConf.string(), "-A",
       "resolver-afl-symcc:" + Config_.MutatorAddr + ",input=" +
           Request.TranscriptPath.string()},
      Request.SourceRoot,
      {
          {"LD_LIBRARY_PATH", LdLibraryPath},
          {"NAMED_RESOLVER_AFL_SYMCC_TARGET", Config_.TargetAddr},
          {"NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR",
           ResponseCorpusDir.string()},
          {"NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS",
           std::to_string(Config_.ReplyTimeoutMs)},
          {"NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH",
           (Request.RunRoot / "bind9.after.cache.txt").string()},
          {"NAMED_RESOLVER_AFL_SYMCC_LOG", "1"},
      },
      std::nullopt,
  });
  std::ofstream(Request.RunRoot / "bind9.stderr") << Result.StderrText;
  return Result;
}

CommandResult
Bind9ResolverAdapter::dumpCache(const std::filesystem::path &RunRoot,
                                const std::filesystem::path &OutputFile) const {
  const auto Binary = requireExisting(
      bind9BinaryPath(Config_, RunRoot), "缺少 bind9 dump-cache 可执行文件");
  const auto ResponseCorpusDir =
      requireExisting(Config_.ResponseCorpusDir, "缺少 bind9 response 语料目录");
  const auto BuildRoot = std::filesystem::path(
      std::getenv("DNSLAB_BIND9_BUILD_ROOT") != nullptr
          ? std::getenv("DNSLAB_BIND9_BUILD_ROOT")
          : "");
  const auto LdLibraryPath = collectDotLibs(
      BuildRoot.empty() ? Config_.WorkspaceRoot / "bind-9.18.46-afl" : BuildRoot);
  const auto RuntimeDir = RunRoot / "bind9_runtime";
  const auto NamedConf = RuntimeDir / "named.conf";

  renderNamedConf(Config_.NamedConfTemplate, RuntimeDir, NamedConf);
  const CommandResult Result = runProcess({
      {"timeout", "-k", "2", std::to_string(Config_.SeedTimeoutSec),
       Binary.string(), "-g", "-c", NamedConf.string(), "-A",
       "resolver-afl-symcc:" + Config_.MutatorAddr},
      std::nullopt,
      {
          {"LD_LIBRARY_PATH", LdLibraryPath},
          {"NAMED_RESOLVER_AFL_SYMCC_TARGET", Config_.TargetAddr},
          {"NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR",
           ResponseCorpusDir.string()},
          {"NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS",
           std::to_string(Config_.ReplyTimeoutMs)},
          {"NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH", OutputFile.string()},
          {"NAMED_RESOLVER_AFL_SYMCC_LOG", "1"},
      },
      std::nullopt,
  });
  std::ofstream(RunRoot / "bind9.stderr") << Result.StderrText;
  return Result;
}

CommandResult
Bind9ResolverAdapter::flushCache(const std::filesystem::path &RunRoot) const {
  std::filesystem::remove_all(RunRoot / "bind9_runtime");
  return {0, "", ""};
}

OracleArtifact
Bind9ResolverAdapter::parseOracle(const std::filesystem::path &OraclePath) const {
  std::ifstream Input(OraclePath);
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  return makeOracleArtifact(parseOracleSummary(Buffer.str(), "bind9"));
}

std::vector<std::filesystem::path>
Bind9ResolverAdapter::collectLogs(const std::filesystem::path &RunRoot) const {
  std::vector<std::filesystem::path> Output;
  for (const auto &Candidate :
       {RunRoot / "bind9.stderr", RunRoot / "bind9_runtime" / "named.conf"}) {
    if (std::filesystem::exists(Candidate)) {
      Output.push_back(Candidate);
    }
  }
  return Output;
}

UnboundResolverAdapter::UnboundResolverAdapter(UnboundAdapterConfig Config)
    : Config_(std::move(Config)) {}

std::string UnboundResolverAdapter::name() const { return "unbound"; }

std::filesystem::path
UnboundResolverAdapter::prepareSource(const std::filesystem::path &WorkspaceRoot,
                                      const std::string &Tag) const {
  const auto SubjectRoot = defaultSubjectRoot(WorkspaceRoot, "unbound", Tag);
  if (std::filesystem::exists(SubjectRoot)) {
    return SubjectRoot;
  }
  if (Config_.SourceFallbackPath.has_value() &&
      std::filesystem::exists(*Config_.SourceFallbackPath)) {
    return *Config_.SourceFallbackPath;
  }
  const auto Legacy = WorkspaceRoot / "unbound-1.24.2";
  if (std::filesystem::exists(Legacy)) {
    return Legacy;
  }
  return cloneIfMissing(WorkspaceRoot, "unbound", Tag,
                        "https://github.com/NLnetLabs/unbound.git");
}

CommandResult
UnboundResolverAdapter::applyPatch(const std::filesystem::path &SourceRoot,
                                   const std::filesystem::path &PatchFile) const {
  if (std::filesystem::is_directory(PatchFile)) {
    return copyPatchTree(PatchFile, SourceRoot);
  }
  return runProcess({{"git", "-C", SourceRoot.string(), "apply",
                      PatchFile.string()},
                     std::nullopt,
                     {},
                     std::nullopt});
}

CommandResult
UnboundResolverAdapter::build(const std::filesystem::path &SourceRoot,
                              const std::filesystem::path &BuildRoot) const {
  const auto TargetRoot =
      std::filesystem::exists(BuildRoot / ".libs") ? BuildRoot : (BuildRoot / "unbound-afl");
  if (!std::filesystem::exists(TargetRoot)) {
    std::filesystem::create_directories(TargetRoot.parent_path());
    std::filesystem::copy(SourceRoot, TargetRoot,
                          std::filesystem::copy_options::recursive |
                              std::filesystem::copy_options::copy_symlinks);
  }

  if (!std::filesystem::exists(TargetRoot / "config.status") &&
      std::filesystem::exists(TargetRoot / "configure")) {
    const auto ConfigureResult = runProcess({
        {"./configure"},
        TargetRoot,
        {},
        std::nullopt,
    });
    if (ConfigureResult.ExitCode != 0) {
      return ConfigureResult;
    }
  }
  return runProcess({{"make", "-j2"}, TargetRoot, {}, std::nullopt});
}

CommandResult
UnboundResolverAdapter::runSample(const RunSampleRequest &Request) const {
  const auto Binary = requireExisting(unboundBinaryPath(Config_, Request.BuildRoot),
                                      "缺少 unbound 可执行文件");
  const auto ResponseCorpusDir =
      requireExisting(Config_.ResponseCorpusDir, "缺少 unbound response 语料目录");
  const auto LdLibraryPath = collectDotLibs(Request.BuildRoot);
  std::filesystem::create_directories(Request.RunRoot);
  const CommandResult Result = runProcess({
      {"timeout", "-k", "2", std::to_string(Config_.SeedTimeoutSec),
       Binary.string()},
      Request.SourceRoot,
      {
          {"LD_LIBRARY_PATH", LdLibraryPath},
          {"UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR",
           ResponseCorpusDir.string()},
          {"UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH",
           (Request.RunRoot / "unbound.after.cache.txt").string()},
          {"UNBOUND_RESOLVER_AFL_SYMCC_LOG", "1"},
      },
      Request.TranscriptPath,
  });
  std::ofstream(Request.RunRoot / "unbound.stderr") << Result.StderrText;
  return Result;
}

CommandResult
UnboundResolverAdapter::dumpCache(const std::filesystem::path &RunRoot,
                                  const std::filesystem::path &OutputFile) const {
  const auto Binary = requireExisting(
      unboundBinaryPath(Config_, RunRoot), "缺少 unbound dump-cache 可执行文件");
  const auto ResponseCorpusDir =
      requireExisting(Config_.ResponseCorpusDir, "缺少 unbound response 语料目录");
  const auto BuildRoot = std::filesystem::path(
      std::getenv("DNSLAB_UNBOUND_BUILD_ROOT") != nullptr
          ? std::getenv("DNSLAB_UNBOUND_BUILD_ROOT")
          : "");
  const auto LdLibraryPath = collectDotLibs(
      BuildRoot.empty() ? Config_.WorkspaceRoot / "unbound-1.24.2-afl" : BuildRoot);
  const CommandResult Result = runProcess({
      {"timeout", "-k", "2", std::to_string(Config_.SeedTimeoutSec),
       Binary.string()},
      std::nullopt,
      {
          {"LD_LIBRARY_PATH", LdLibraryPath},
          {"UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR",
           ResponseCorpusDir.string()},
          {"UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH", OutputFile.string()},
          {"UNBOUND_RESOLVER_AFL_SYMCC_LOG", "1"},
      },
      std::nullopt,
  });
  std::ofstream(RunRoot / "unbound.stderr") << Result.StderrText;
  return Result;
}

CommandResult
UnboundResolverAdapter::flushCache(const std::filesystem::path &RunRoot) const {
  std::filesystem::remove(RunRoot / "unbound.after.cache.txt");
  std::filesystem::remove(RunRoot / "unbound.before.cache.txt");
  return {0, "", ""};
}

OracleArtifact
UnboundResolverAdapter::parseOracle(const std::filesystem::path &OraclePath) const {
  std::ifstream Input(OraclePath);
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  return makeOracleArtifact(parseOracleSummary(Buffer.str(), "unbound"));
}

std::vector<std::filesystem::path>
UnboundResolverAdapter::collectLogs(const std::filesystem::path &RunRoot) const {
  std::vector<std::filesystem::path> Output;
  if (std::filesystem::exists(RunRoot / "unbound.stderr")) {
    Output.push_back(RunRoot / "unbound.stderr");
  }
  return Output;
}

DnsmasqResolverAdapter::DnsmasqResolverAdapter(DnsmasqAdapterConfig Config)
    : Config_(std::move(Config)) {}

std::string DnsmasqResolverAdapter::name() const { return "dnsmasq"; }

std::filesystem::path
DnsmasqResolverAdapter::prepareSource(const std::filesystem::path &WorkspaceRoot,
                                      const std::string &Tag) const {
  const auto SubjectRoot = defaultSubjectRoot(WorkspaceRoot, "dnsmasq", Tag);
  if (std::filesystem::exists(SubjectRoot)) {
    return SubjectRoot;
  }
  if (Config_.SourceFallbackPath.has_value() &&
      std::filesystem::exists(*Config_.SourceFallbackPath)) {
    return *Config_.SourceFallbackPath;
  }
  const auto Legacy = WorkspaceRoot / "dnsmasq-2.92";
  if (std::filesystem::exists(Legacy)) {
    return Legacy;
  }
  return cloneIfMissing(WorkspaceRoot, "dnsmasq", Tag,
                        "https://github.com/imp/dnsmasq.git");
}

CommandResult
DnsmasqResolverAdapter::applyPatch(const std::filesystem::path &SourceRoot,
                                   const std::filesystem::path &PatchFile) const {
  if (std::filesystem::is_directory(PatchFile)) {
    return copyPatchTree(PatchFile, SourceRoot);
  }
  return runProcess({{"git", "-C", SourceRoot.string(), "apply",
                      PatchFile.string()},
                     std::nullopt,
                     {},
                     std::nullopt});
}

CommandResult
DnsmasqResolverAdapter::build(const std::filesystem::path &SourceRoot,
                              const std::filesystem::path &BuildRoot) const {
  std::filesystem::create_directories(BuildRoot);
  const CommandResult Result = runProcess({
      {"make", "-j" + std::to_string(Config_.BuildJobs),
       "BUILDDIR=" + BuildRoot.string(), "all"},
      SourceRoot,
      {},
      std::nullopt,
  });
  if (Result.ExitCode != 0) {
    return Result;
  }
  requireExisting(dnsmasqBinaryPath(Config_, BuildRoot),
                  "缺少 dnsmasq 可执行文件");
  return Result;
}

CommandResult
DnsmasqResolverAdapter::runSample(const RunSampleRequest &Request) const {
  const auto Binary = requireExisting(dnsmasqBinaryPath(Config_, Request.BuildRoot),
                                      "缺少 dnsmasq 可执行文件");
  const auto Harness =
      requireExisting(Config_.HarnessScriptPath, "缺少 dnsmasq replay harness");
  std::filesystem::create_directories(Request.RunRoot);
  const auto CacheDumpPath = Request.RunRoot / "dnsmasq.after.cache.txt";
  const auto NativeStderrPath = Request.RunRoot / "dnsmasq.native.stderr";
  const CommandResult Result = runProcess({
      {"python3",
       Harness.string(),
       "--dnsmasq-bin",
       Binary.string(),
       "--mode",
       "run",
       "--transcript",
       Request.TranscriptPath.string(),
       "--cache-dump-path",
       CacheDumpPath.string(),
       "--dnsmasq-stderr-path",
       NativeStderrPath.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  std::ofstream(Request.RunRoot / "dnsmasq.stderr") << Result.StdoutText;
  return Result;
}

CommandResult
DnsmasqResolverAdapter::dumpCache(const std::filesystem::path &RunRoot,
                                  const std::filesystem::path &OutputFile) const {
  const auto Binary = requireExisting(dnsmasqBinaryPath(Config_, RunRoot),
                                      "缺少 dnsmasq 可执行文件");
  const auto Harness =
      requireExisting(Config_.HarnessScriptPath, "缺少 dnsmasq replay harness");
  std::filesystem::create_directories(RunRoot);
  const auto NativeStderrPath = RunRoot / "dnsmasq.native.stderr";
  const CommandResult Result = runProcess({
      {"python3",
       Harness.string(),
       "--dnsmasq-bin",
       Binary.string(),
       "--mode",
       "dump",
       "--cache-dump-path",
       OutputFile.string(),
       "--dnsmasq-stderr-path",
       NativeStderrPath.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  std::ofstream(RunRoot / "dnsmasq.stderr") << Result.StdoutText;
  return Result;
}

CommandResult
DnsmasqResolverAdapter::flushCache(const std::filesystem::path &RunRoot) const {
  std::filesystem::remove_all(RunRoot);
  return {0, "", ""};
}

OracleArtifact
DnsmasqResolverAdapter::parseOracle(const std::filesystem::path &OraclePath) const {
  std::ifstream Input(OraclePath);
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  return makeOracleArtifact(parseOracleSummary(Buffer.str(), "dnsmasq"));
}

std::vector<std::filesystem::path>
DnsmasqResolverAdapter::collectLogs(const std::filesystem::path &RunRoot) const {
  std::vector<std::filesystem::path> Output;
  for (const auto &Candidate :
       {RunRoot / "dnsmasq.stderr", RunRoot / "dnsmasq.native.stderr"}) {
    if (std::filesystem::exists(Candidate)) {
      Output.push_back(Candidate);
    }
  }
  return Output;
}

SmartdnsResolverAdapter::SmartdnsResolverAdapter(SmartdnsAdapterConfig Config)
    : Config_(std::move(Config)) {}

std::string SmartdnsResolverAdapter::name() const { return "smartdns"; }

std::filesystem::path
SmartdnsResolverAdapter::prepareSource(const std::filesystem::path &WorkspaceRoot,
                                       const std::string &Tag) const {
  const auto SubjectRoot = defaultSubjectRoot(WorkspaceRoot, "smartdns", Tag);
  if (std::filesystem::exists(SubjectRoot)) {
    return SubjectRoot;
  }
  if (Config_.SourceFallbackPath.has_value() &&
      std::filesystem::exists(*Config_.SourceFallbackPath)) {
    return *Config_.SourceFallbackPath;
  }
  const auto Legacy = WorkspaceRoot / "smartdns-Release47.1";
  if (std::filesystem::exists(Legacy)) {
    return Legacy;
  }
  return cloneIfMissing(WorkspaceRoot, "smartdns", Tag,
                        "https://github.com/pymumu/smartdns.git");
}

CommandResult
SmartdnsResolverAdapter::applyPatch(const std::filesystem::path &SourceRoot,
                                    const std::filesystem::path &PatchFile) const {
  if (std::filesystem::is_directory(PatchFile)) {
    return copyPatchTree(PatchFile, SourceRoot);
  }
  return runProcess({{"git", "-C", SourceRoot.string(), "apply",
                      PatchFile.string()},
                     std::nullopt,
                     {},
                     std::nullopt});
}

CommandResult
SmartdnsResolverAdapter::build(const std::filesystem::path &SourceRoot,
                               const std::filesystem::path &BuildRoot) const {
  const auto TargetRoot =
      std::filesystem::exists(BuildRoot / "src") ? BuildRoot : (BuildRoot / "smartdns-build");
  if (!std::filesystem::exists(TargetRoot)) {
    std::filesystem::create_directories(TargetRoot.parent_path());
    std::filesystem::copy(SourceRoot, TargetRoot,
                          std::filesystem::copy_options::recursive |
                              std::filesystem::copy_options::copy_symlinks);
  }
  const CommandResult Result = runProcess({
      {"make", "-j" + std::to_string(Config_.BuildJobs), "-C",
       (TargetRoot / "src").string(), "all"},
      std::nullopt,
      {},
      std::nullopt,
  });
  if (Result.ExitCode != 0) {
    return Result;
  }
  requireExisting(smartdnsBinaryPath(Config_, TargetRoot),
                  "缺少 smartdns 可执行文件");
  return Result;
}

CommandResult
SmartdnsResolverAdapter::runSample(const RunSampleRequest &Request) const {
  const auto Binary = requireExisting(smartdnsBinaryPath(Config_, Request.BuildRoot),
                                      "缺少 smartdns 可执行文件");
  const auto Harness =
      requireExisting(Config_.HarnessScriptPath, "缺少 smartdns replay harness");
  std::filesystem::create_directories(Request.RunRoot);
  const auto CacheDumpPath = Request.RunRoot / "smartdns.after.cache.txt";
  const auto NativeLogPath = Request.RunRoot / "smartdns.native.log";
  const CommandResult Result = runProcess({
      {"python3",
       Harness.string(),
       "--smartdns-bin",
       Binary.string(),
       "--mode",
       "run",
       "--transcript",
       Request.TranscriptPath.string(),
       "--cache-dump-path",
       CacheDumpPath.string(),
       "--smartdns-log-path",
       NativeLogPath.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  std::ofstream(Request.RunRoot / "smartdns.stderr") << Result.StdoutText;
  return Result;
}

CommandResult
SmartdnsResolverAdapter::dumpCache(const std::filesystem::path &RunRoot,
                                   const std::filesystem::path &OutputFile) const {
  const auto Binary = requireExisting(smartdnsBinaryPath(Config_, RunRoot),
                                      "缺少 smartdns 可执行文件");
  const auto Harness =
      requireExisting(Config_.HarnessScriptPath, "缺少 smartdns replay harness");
  std::filesystem::create_directories(RunRoot);
  const auto NativeLogPath = RunRoot / "smartdns.native.log";
  const CommandResult Result = runProcess({
      {"python3",
       Harness.string(),
       "--smartdns-bin",
       Binary.string(),
       "--mode",
       "dump",
       "--cache-dump-path",
       OutputFile.string(),
       "--smartdns-log-path",
       NativeLogPath.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  std::ofstream(RunRoot / "smartdns.stderr") << Result.StdoutText;
  return Result;
}

CommandResult
SmartdnsResolverAdapter::flushCache(const std::filesystem::path &RunRoot) const {
  std::filesystem::remove_all(RunRoot);
  return {0, "", ""};
}

OracleArtifact
SmartdnsResolverAdapter::parseOracle(const std::filesystem::path &OraclePath) const {
  std::ifstream Input(OraclePath);
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  return makeOracleArtifact(parseOracleSummary(Buffer.str(), "smartdns"));
}

std::vector<std::filesystem::path>
SmartdnsResolverAdapter::collectLogs(const std::filesystem::path &RunRoot) const {
  std::vector<std::filesystem::path> Output;
  for (const auto &Candidate :
       {RunRoot / "smartdns.stderr", RunRoot / "smartdns.native.log"}) {
    if (std::filesystem::exists(Candidate)) {
      Output.push_back(Candidate);
    }
  }
  return Output;
}

MaradnsResolverAdapter::MaradnsResolverAdapter(MaradnsAdapterConfig Config)
    : Config_(std::move(Config)) {}

std::string MaradnsResolverAdapter::name() const { return "maradns"; }

std::filesystem::path
MaradnsResolverAdapter::prepareSource(const std::filesystem::path &WorkspaceRoot,
                                      const std::string &Tag) const {
  const auto SubjectRoot = defaultSubjectRoot(WorkspaceRoot, "maradns", Tag);
  if (std::filesystem::exists(SubjectRoot)) {
    return SubjectRoot;
  }
  if (Config_.SourceFallbackPath.has_value() &&
      std::filesystem::exists(*Config_.SourceFallbackPath)) {
    return *Config_.SourceFallbackPath;
  }
  const auto Legacy = WorkspaceRoot / "maradns-deadwood-3.3.02";
  if (std::filesystem::exists(Legacy)) {
    return Legacy;
  }
  return cloneIfMissing(WorkspaceRoot, "maradns", Tag,
                        "https://github.com/samboy/MaraDNS.git");
}

CommandResult
MaradnsResolverAdapter::applyPatch(const std::filesystem::path &SourceRoot,
                                   const std::filesystem::path &PatchFile) const {
  if (std::filesystem::is_directory(PatchFile)) {
    return copyPatchTree(PatchFile, SourceRoot);
  }
  return runProcess({{"git", "-C", SourceRoot.string(), "apply",
                      PatchFile.string()},
                     std::nullopt,
                     {},
                     std::nullopt});
}

CommandResult
MaradnsResolverAdapter::build(const std::filesystem::path &SourceRoot,
                              const std::filesystem::path &BuildRoot) const {
  const auto TargetRoot =
      std::filesystem::exists(BuildRoot / "deadwood-github")
          ? BuildRoot
          : (BuildRoot / "deadwood-build");
  if (!std::filesystem::exists(TargetRoot)) {
    std::filesystem::create_directories(TargetRoot.parent_path());
    std::filesystem::copy(SourceRoot, TargetRoot,
                          std::filesystem::copy_options::recursive |
                              std::filesystem::copy_options::copy_symlinks);
  }
  const auto SrcDir = TargetRoot / "deadwood-github" / "src";
  const CommandResult VersionResult = runProcess({
      {"make", "version.h"},
      SrcDir,
      {},
      std::nullopt,
  });
  if (VersionResult.ExitCode != 0) {
    return VersionResult;
  }
  const CommandResult BuildResult = runProcess({
      {"make", "-j" + std::to_string(Config_.BuildJobs), "all"},
      SrcDir,
      {},
      std::nullopt,
  });
  if (BuildResult.ExitCode != 0) {
    return BuildResult;
  }
  requireExisting(maradnsBinaryPath(Config_, BuildRoot),
                  "缺少 maradns/deadwood 可执行文件");
  return BuildResult;
}

CommandResult
MaradnsResolverAdapter::runSample(const RunSampleRequest &Request) const {
  const auto Binary = requireExisting(maradnsBinaryPath(Config_, Request.BuildRoot),
                                      "缺少 maradns/deadwood 可执行文件");
  const auto Harness =
      requireExisting(Config_.HarnessScriptPath, "缺少 maradns replay harness");
  std::filesystem::create_directories(Request.RunRoot);
  const auto CacheDumpPath = Request.RunRoot / "maradns.after.cache.txt";
  const auto NativeLogPath = Request.RunRoot / "maradns.native.log";
  const CommandResult Result = runProcess({
      {"python3",
       Harness.string(),
       "--deadwood-bin",
       Binary.string(),
       "--mode",
       "run",
       "--transcript",
       Request.TranscriptPath.string(),
       "--cache-dump-path",
       CacheDumpPath.string(),
       "--maradns-log-path",
       NativeLogPath.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  std::ofstream(Request.RunRoot / "maradns.stderr") << Result.StdoutText;
  return Result;
}

CommandResult
MaradnsResolverAdapter::dumpCache(const std::filesystem::path &RunRoot,
                                  const std::filesystem::path &OutputFile) const {
  const auto Binary = requireExisting(maradnsBinaryPath(Config_, RunRoot),
                                      "缺少 maradns/deadwood 可执行文件");
  const auto Harness =
      requireExisting(Config_.HarnessScriptPath, "缺少 maradns replay harness");
  std::filesystem::create_directories(RunRoot);
  const auto NativeLogPath = RunRoot / "maradns.native.log";
  const CommandResult Result = runProcess({
      {"python3",
       Harness.string(),
       "--deadwood-bin",
       Binary.string(),
       "--mode",
       "dump",
       "--cache-dump-path",
       OutputFile.string(),
       "--maradns-log-path",
       NativeLogPath.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  std::ofstream(RunRoot / "maradns.stderr") << Result.StdoutText;
  return Result;
}

CommandResult
MaradnsResolverAdapter::flushCache(const std::filesystem::path &RunRoot) const {
  std::filesystem::remove_all(RunRoot);
  return {0, "", ""};
}

OracleArtifact
MaradnsResolverAdapter::parseOracle(const std::filesystem::path &OraclePath) const {
  std::ifstream Input(OraclePath);
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  return makeOracleArtifact(parseOracleSummary(Buffer.str(), "maradns"));
}

std::vector<std::filesystem::path>
MaradnsResolverAdapter::collectLogs(const std::filesystem::path &RunRoot) const {
  std::vector<std::filesystem::path> Output;
  for (const auto &Candidate :
       {RunRoot / "maradns.stderr", RunRoot / "maradns.native.log"}) {
    if (std::filesystem::exists(Candidate)) {
      Output.push_back(Candidate);
    }
  }
  return Output;
}

KnotResolverAdapter::KnotResolverAdapter(KnotResolverAdapterConfig Config)
    : Config_(std::move(Config)) {}

std::string KnotResolverAdapter::name() const { return "knot-resolver"; }

std::filesystem::path
KnotResolverAdapter::prepareSource(const std::filesystem::path &WorkspaceRoot,
                                   const std::string &Tag) const {
  const auto SubjectRoot =
      defaultSubjectRoot(WorkspaceRoot, "knot-resolver", Tag);
  if (std::filesystem::exists(SubjectRoot)) {
    return SubjectRoot;
  }
  if (Config_.SourceFallbackPath.has_value() &&
      std::filesystem::exists(*Config_.SourceFallbackPath)) {
    return *Config_.SourceFallbackPath;
  }
  const auto Legacy = WorkspaceRoot / ("knot-resolver-" + Tag);
  if (std::filesystem::exists(Legacy)) {
    return Legacy;
  }
  return cloneIfMissing(WorkspaceRoot, "knot-resolver", Tag,
                        "https://github.com/CZ-NIC/knot-resolver.git");
}

CommandResult
KnotResolverAdapter::applyPatch(const std::filesystem::path &SourceRoot,
                                const std::filesystem::path &PatchFile) const {
  if (std::filesystem::is_directory(PatchFile)) {
    return copyPatchTree(PatchFile, SourceRoot);
  }
  return runProcess({{"git", "-C", SourceRoot.string(), "apply",
                      PatchFile.string()},
                     std::nullopt,
                     {},
                     std::nullopt});
}

CommandResult
KnotResolverAdapter::build(const std::filesystem::path &SourceRoot,
                           const std::filesystem::path &BuildRoot) const {
  const auto TargetRoot = BuildRoot / "knot-build";
  const auto RuntimePrefix = BuildRoot / "knot-runtime";
  std::filesystem::create_directories(TargetRoot.parent_path());
  if (std::filesystem::exists(TargetRoot / "meson.build") &&
      !std::filesystem::exists(TargetRoot / "build.ninja")) {
    std::filesystem::remove_all(TargetRoot);
  }
  std::vector<std::string> SetupArgs = {
      "meson",
      "setup",
      TargetRoot.string(),
      SourceRoot.string(),
      "--prefix",
      RuntimePrefix.string(),
      "--libdir",
      "lib",
      "-Ddoc=disabled",
      "-Dextra_tests=disabled",
      "-Dconfig_tests=disabled",
      "-Dutils=disabled",
      "-Dsystemd_files=disabled",
      "-Dquic=disabled",
      "-Ddnstap=disabled",
      "-Dmanaged_ta=disabled",
  };
  if (std::filesystem::exists(TargetRoot / "build.ninja")) {
    SetupArgs.insert(SetupArgs.begin() + 2, "--reconfigure");
  }
  const auto SetupResult = runProcess({
      SetupArgs,
      std::nullopt,
      {},
      std::nullopt,
  });
  if (SetupResult.ExitCode != 0) {
    return SetupResult;
  }
  const auto BuildResult = runProcess({
      {"ninja", "daemon/kresd"},
      TargetRoot,
      {},
      std::nullopt,
  });
  if (BuildResult.ExitCode != 0) {
    return BuildResult;
  }
  const auto InstallResult = runProcess({
      {"meson", "install", "-C", TargetRoot.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  if (InstallResult.ExitCode != 0) {
    return InstallResult;
  }
  const auto RuntimeLuaDir = RuntimePrefix / "lib" / "knot-resolver";
  const auto RuntimeEtcDir = RuntimePrefix / "etc" / "knot-resolver";
  std::filesystem::create_directories(RuntimeLuaDir);
  std::filesystem::create_directories(RuntimeEtcDir);
  const auto copyLuaDir = [&](const std::filesystem::path &LuaDir) {
    if (!std::filesystem::is_directory(LuaDir)) {
      return;
    }
    for (const auto &Entry : std::filesystem::directory_iterator(LuaDir)) {
      if (!Entry.is_regular_file()) {
        continue;
      }
      std::filesystem::copy_file(
          Entry.path(), RuntimeLuaDir / Entry.path().filename(),
          std::filesystem::copy_options::overwrite_existing);
    }
  };
  copyLuaDir(SourceRoot / "daemon" / "lua");
  copyLuaDir(TargetRoot / "daemon" / "lua");
  const auto RootKeysSource = SourceRoot / "etc" / "root.keys";
  if (std::filesystem::is_regular_file(RootKeysSource)) {
    std::filesystem::copy_file(
        RootKeysSource, RuntimeEtcDir / "root.keys",
        std::filesystem::copy_options::overwrite_existing);
  }
  requireExisting(RuntimeLuaDir / "sandbox.lua",
                  "缺少 knot-resolver Lua runtime");
  requireExisting(RuntimeLuaDir / "kres_modules" / "ta_update.lua",
                  "缺少 knot-resolver 内置模块");
  requireExisting(RuntimeEtcDir / "root.keys",
                  "缺少 knot-resolver trust anchor");
  requireExisting(knotResolverBinaryPath(Config_, BuildRoot),
                  "缺少 knot-resolver 可执行文件");
  return BuildResult;
}

CommandResult
KnotResolverAdapter::runSample(const RunSampleRequest &Request) const {
  const auto Binary =
      requireExisting(knotResolverBinaryPath(Config_, Request.BuildRoot),
                      "缺少 knot-resolver 可执行文件");
  const auto Harness = requireExisting(Config_.HarnessScriptPath,
                                       "缺少 knot-resolver replay harness");
  std::filesystem::create_directories(Request.RunRoot);
  const auto CacheDumpPath = Request.RunRoot / "knot-resolver.after.cache.txt";
  const auto NativeLogPath = Request.RunRoot / "knot-resolver.native.log";
  const CommandResult Result = runProcess({
      {"python3",
       Harness.string(),
       "--kresd-bin",
       Binary.string(),
       "--mode",
       "run",
       "--transcript",
       Request.TranscriptPath.string(),
       "--cache-dump-path",
       CacheDumpPath.string(),
       "--kresd-log-path",
       NativeLogPath.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  std::ofstream(Request.RunRoot / "knot-resolver.stderr") << Result.StdoutText;
  return Result;
}

CommandResult
KnotResolverAdapter::dumpCache(const std::filesystem::path &RunRoot,
                               const std::filesystem::path &OutputFile) const {
  const auto Binary = requireExisting(knotResolverBinaryPath(Config_, RunRoot),
                                      "缺少 knot-resolver 可执行文件");
  const auto Harness = requireExisting(Config_.HarnessScriptPath,
                                       "缺少 knot-resolver replay harness");
  std::filesystem::create_directories(RunRoot);
  const auto NativeLogPath = RunRoot / "knot-resolver.native.log";
  const CommandResult Result = runProcess({
      {"python3",
       Harness.string(),
       "--kresd-bin",
       Binary.string(),
       "--mode",
       "dump",
       "--cache-dump-path",
       OutputFile.string(),
       "--kresd-log-path",
       NativeLogPath.string()},
      std::nullopt,
      {},
      std::nullopt,
  });
  std::ofstream(RunRoot / "knot-resolver.stderr") << Result.StdoutText;
  return Result;
}

CommandResult
KnotResolverAdapter::flushCache(const std::filesystem::path &RunRoot) const {
  std::filesystem::remove_all(RunRoot);
  return {0, "", ""};
}

OracleArtifact
KnotResolverAdapter::parseOracle(const std::filesystem::path &OraclePath) const {
  std::ifstream Input(OraclePath);
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  return makeOracleArtifact(parseOracleSummary(Buffer.str(), "knot-resolver"));
}

std::vector<std::filesystem::path>
KnotResolverAdapter::collectLogs(const std::filesystem::path &RunRoot) const {
  std::vector<std::filesystem::path> Output;
  for (const auto &Candidate :
       {RunRoot / "knot-resolver.stderr", RunRoot / "knot-resolver.native.log"}) {
    if (std::filesystem::exists(Candidate)) {
      Output.push_back(Candidate);
    }
  }
  return Output;
}

ResolverRegistry
makeDefaultResolverRegistry(const std::filesystem::path &WorkspaceRoot) {
  ResolverRegistry Registry;
  Bind9AdapterConfig Bind9Config;
  Bind9Config.WorkspaceRoot = WorkspaceRoot;
  Bind9Config.ScriptPath =
      WorkspaceRoot / "named_experiment" / "run_named_afl_symcc.sh";
  if (const char *NamedConfEnv = std::getenv("BIND9_NAMED_CONF_TEMPLATE")) {
    Bind9Config.NamedConfTemplate = std::filesystem::path(NamedConfEnv);
  } else {
    Bind9Config.NamedConfTemplate =
        WorkspaceRoot / "named_experiment" / "runtime" / "named.conf";
  }
  if (const char *ResponseCorpusEnv = std::getenv("RESPONSE_CORPUS_DIR")) {
    Bind9Config.ResponseCorpusDir = std::filesystem::path(ResponseCorpusEnv);
  } else {
    Bind9Config.ResponseCorpusDir =
        WorkspaceRoot / "named_experiment" / "work" / "response_corpus";
  }
  Bind9Config.SourceFallbackPath = std::nullopt;
  Bind9Config.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<Bind9ResolverAdapter>(std::move(Bind9Config)));

  UnboundAdapterConfig UnboundConfig;
  UnboundConfig.WorkspaceRoot = WorkspaceRoot;
  if (const char *ResponseCorpusEnv = std::getenv("RESPONSE_CORPUS_DIR")) {
    UnboundConfig.ResponseCorpusDir = std::filesystem::path(ResponseCorpusEnv);
  } else {
    UnboundConfig.ResponseCorpusDir =
        WorkspaceRoot / "unbound_experiment" / "work_stateful" /
        "response_corpus";
  }
  UnboundConfig.SourceFallbackPath = std::nullopt;
  UnboundConfig.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<UnboundResolverAdapter>(std::move(UnboundConfig)));

  DnsmasqAdapterConfig DnsmasqConfig;
  DnsmasqConfig.WorkspaceRoot = WorkspaceRoot;
  DnsmasqConfig.BuildJobs = 2;
  if (const char *HarnessEnv = std::getenv("DNSMASQ_HARNESS_SCRIPT")) {
    DnsmasqConfig.HarnessScriptPath = std::filesystem::path(HarnessEnv);
  } else {
    DnsmasqConfig.HarnessScriptPath =
        WorkspaceRoot / "tools" / "dnsmasq_replay_harness.py";
  }
  DnsmasqConfig.SourceFallbackPath = std::nullopt;
  DnsmasqConfig.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<DnsmasqResolverAdapter>(std::move(DnsmasqConfig)));

  SmartdnsAdapterConfig SmartdnsConfig;
  SmartdnsConfig.WorkspaceRoot = WorkspaceRoot;
  SmartdnsConfig.BuildJobs = 2;
  if (const char *HarnessEnv = std::getenv("SMARTDNS_HARNESS_SCRIPT")) {
    SmartdnsConfig.HarnessScriptPath = std::filesystem::path(HarnessEnv);
  } else {
    SmartdnsConfig.HarnessScriptPath =
        WorkspaceRoot / "tools" / "smartdns_replay_harness.py";
  }
  SmartdnsConfig.SourceFallbackPath = std::nullopt;
  SmartdnsConfig.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<SmartdnsResolverAdapter>(std::move(SmartdnsConfig)));

  MaradnsAdapterConfig MaradnsConfig;
  MaradnsConfig.WorkspaceRoot = WorkspaceRoot;
  MaradnsConfig.BuildJobs = 2;
  if (const char *HarnessEnv = std::getenv("MARADNS_HARNESS_SCRIPT")) {
    MaradnsConfig.HarnessScriptPath = std::filesystem::path(HarnessEnv);
  } else {
    MaradnsConfig.HarnessScriptPath =
        WorkspaceRoot / "tools" / "maradns_replay_harness.py";
  }
  MaradnsConfig.SourceFallbackPath = std::nullopt;
  MaradnsConfig.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<MaradnsResolverAdapter>(std::move(MaradnsConfig)));

  KnotResolverAdapterConfig KnotConfig;
  KnotConfig.WorkspaceRoot = WorkspaceRoot;
  if (const char *HarnessEnv = std::getenv("KNOT_RESOLVER_HARNESS_SCRIPT")) {
    KnotConfig.HarnessScriptPath = std::filesystem::path(HarnessEnv);
  } else {
    KnotConfig.HarnessScriptPath =
        WorkspaceRoot / "tools" / "knot_resolver_replay_harness.py";
  }
  KnotConfig.SourceFallbackPath = std::nullopt;
  KnotConfig.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<KnotResolverAdapter>(std::move(KnotConfig)));

  return Registry;
}

} // namespace dnslab
