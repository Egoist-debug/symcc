#include "dnslab_core/concrete_adapters.hpp"

#include "dnslab_core/oracle.hpp"

#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>

namespace dnslab {

namespace {

std::filesystem::path normalizePath(const std::filesystem::path &InputPath) {
  std::error_code Error;
  const auto Absolute = std::filesystem::absolute(InputPath, Error);
  if (Error) {
    return InputPath.lexically_normal();
  }
  return Absolute.lexically_normal();
}

std::filesystem::path requireExisting(const std::filesystem::path &InputPath,
                                      const std::string &Message) {
  if (!std::filesystem::exists(InputPath)) {
    throw std::runtime_error(Message + ": " + InputPath.string());
  }
  return InputPath;
}

CommandResult copyPatchTree(const std::filesystem::path &PatchRoot,
                            const std::filesystem::path &SourceRoot);
std::filesystem::path cloneIfMissing(const std::filesystem::path &WorkspaceRoot,
                                     const std::string &Resolver,
                                     const std::string &Tag,
                                     const std::string &RepoUrl);

std::filesystem::path prepareGitResolverSource(
    const std::filesystem::path &WorkspaceRoot, const std::string &Resolver,
    const std::string &Tag,
    const std::optional<std::filesystem::path> &SourceFallbackPath,
    const std::filesystem::path &LegacyPath, const std::string &RepoUrl) {
  const auto SubjectRoot = defaultSubjectRoot(WorkspaceRoot, Resolver, Tag);
  if (std::filesystem::exists(SubjectRoot)) {
    return SubjectRoot;
  }
  if (SourceFallbackPath.has_value() &&
      std::filesystem::exists(*SourceFallbackPath)) {
    return *SourceFallbackPath;
  }
  if (std::filesystem::exists(LegacyPath)) {
    return LegacyPath;
  }
  return cloneIfMissing(WorkspaceRoot, Resolver, Tag, RepoUrl);
}

CommandResult applyPatchFileOrTree(const std::filesystem::path &SourceRoot,
                                   const std::filesystem::path &PatchFile) {
  if (std::filesystem::is_directory(PatchFile)) {
    return copyPatchTree(PatchFile, SourceRoot);
  }
  return runProcess({{"git", "-C", SourceRoot.string(), "apply",
                      PatchFile.string()},
                     std::nullopt,
                     {},
                     std::nullopt});
}

void copyRegularFilesWithRelativeLayout(
    const std::filesystem::path &SourceRoot,
    const std::filesystem::path &TargetRoot) {
  for (const auto &Entry :
       std::filesystem::recursive_directory_iterator(SourceRoot)) {
    if (!Entry.is_regular_file()) {
      continue;
    }
    const auto Relative = std::filesystem::relative(Entry.path(), SourceRoot);
    const auto Target = TargetRoot / Relative;
    std::filesystem::create_directories(Target.parent_path());
    std::filesystem::copy_file(Entry.path(), Target,
                               std::filesystem::copy_options::overwrite_existing);
  }
}

CommandResult copyPatchTree(const std::filesystem::path &PatchRoot,
                            const std::filesystem::path &SourceRoot) {
  if (!std::filesystem::is_directory(PatchRoot)) {
    throw std::runtime_error("patch 目录不存在: " + PatchRoot.string());
  }
  copyRegularFilesWithRelativeLayout(PatchRoot, SourceRoot);
  return {0, "", ""};
}

void copyRegularFilesRecursively(const std::filesystem::path &SourceRoot,
                                 const std::filesystem::path &TargetRoot) {
  if (!std::filesystem::is_directory(SourceRoot)) {
    return;
  }
  copyRegularFilesWithRelativeLayout(SourceRoot, TargetRoot);
}

void copyFirstExistingFile(
    const std::vector<std::filesystem::path> &Candidates,
    const std::filesystem::path &TargetPath) {
  for (const auto &Candidate : Candidates) {
    if (!std::filesystem::is_regular_file(Candidate)) {
      continue;
    }
    std::filesystem::create_directories(TargetPath.parent_path());
    std::filesystem::copy_file(
        Candidate, TargetPath,
        std::filesystem::copy_options::overwrite_existing);
    return;
  }
}

void prepareKnotRuntimeAssets(const std::filesystem::path &SourceRoot,
                              const std::filesystem::path &TargetRoot,
                              const std::filesystem::path &RuntimePrefix) {
  const auto RuntimeLuaDir = RuntimePrefix / "lib" / "knot-resolver";
  const auto RuntimeEtcDir = RuntimePrefix / "etc" / "knot-resolver";
  std::filesystem::create_directories(RuntimeLuaDir);
  std::filesystem::create_directories(RuntimeEtcDir);
  copyRegularFilesRecursively(SourceRoot / "daemon" / "lua", RuntimeLuaDir);
  copyRegularFilesRecursively(TargetRoot / "daemon" / "lua", RuntimeLuaDir);
  copyFirstExistingFile({SourceRoot / "etc" / "root.keys",
                         TargetRoot / "etc" / "root.keys"},
                        RuntimeEtcDir / "root.keys");
  requireExisting(RuntimeLuaDir / "sandbox.lua",
                  "缺少 knot-resolver Lua runtime");
  requireExisting(RuntimeLuaDir / "kres_modules" / "ta_update.lua",
                  "缺少 knot-resolver 内置模块");
  requireExisting(RuntimeEtcDir / "root.keys",
                  "缺少 knot-resolver trust anchor");
}

std::string readTextFile(const std::filesystem::path &InputPath) {
  std::ifstream Input(InputPath);
  if (!Input) {
    throw std::runtime_error("无法读取文件: " + InputPath.string());
  }
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  return Buffer.str();
}

void writeTextFile(const std::filesystem::path &OutputPath,
                   const std::string &Text) {
  std::ofstream Output(OutputPath);
  if (!Output) {
    throw std::runtime_error("无法写入文件: " + OutputPath.string());
  }
  Output << Text;
}

bool replaceOnce(std::string &Text, const std::string &Needle,
                 const std::string &Replacement) {
  const auto Position = Text.find(Needle);
  if (Position == std::string::npos) {
    return false;
  }
  Text.replace(Position, Needle.size(), Replacement);
  return true;
}

void ensureUnboundFuzzmeMakefile(const std::filesystem::path &TargetRoot) {
  const auto MakefileInPath = TargetRoot / "Makefile.in";
  auto MakefileIn = readTextFile(MakefileInPath);
  if (MakefileIn.find("unbound_afl_symcc_orchestrator") != std::string::npos) {
    return;
  }

  const std::string FuzzmeBlock =
      "FUZZME_SRC=smallapp/unbound-fuzzme.c "
      "smallapp/unbound_afl_symcc_orchestrator.c "
      "smallapp/unbound_afl_symcc_mutator_server.c\n"
      "FUZZME_OBJ=unbound-fuzzme.lo unbound_afl_symcc_orchestrator.lo "
      "unbound_afl_symcc_mutator_server.lo\n"
      "FUZZME_OBJ_LINK=$(FUZZME_OBJ) cachedump.lo $(COMMON_OBJ_ALL_SYMBOLS) "
      "$(SLDNS_OBJ) $(COMPAT_OBJ)\n";

  if (!replaceOnce(MakefileIn,
                   "DAEMON_OBJ_LINK=$(DAEMON_OBJ) $(COMMON_OBJ_ALL_SYMBOLS) $(SLDNS_OBJ) \\\n"
                   "$(COMPAT_OBJ) @WIN_DAEMON_OBJ_LINK@\n",
                   "DAEMON_OBJ_LINK=$(DAEMON_OBJ) $(COMMON_OBJ_ALL_SYMBOLS) "
                   "$(SLDNS_OBJ) \\\n$(COMPAT_OBJ) @WIN_DAEMON_OBJ_LINK@\n" +
                       FuzzmeBlock)) {
    throw std::runtime_error("无法定位 unbound Makefile.in 的 daemon 链接段");
  }

  if (!replaceOnce(MakefileIn,
                   "unbound$(EXEEXT):\t$(DAEMON_OBJ_LINK) libunbound.la\n"
                   "\t$(LINK) -o $@ $(DAEMON_OBJ_LINK) $(EXTRALINK) $(SSLLIB) $(LIBS)\n\n",
                   "unbound$(EXEEXT):\t$(DAEMON_OBJ_LINK) libunbound.la\n"
                   "\t$(LINK) -o $@ $(DAEMON_OBJ_LINK) $(EXTRALINK) $(SSLLIB) "
                   "$(LIBS)\n\n"
                   "unbound-fuzzme$(EXEEXT):\t$(FUZZME_OBJ_LINK) libunbound.la\n"
                   "\t$(LINK) -o $@ $(FUZZME_OBJ_LINK) libunbound.la "
                   "$(EXTRALINK) $(SSLLIB) $(LIBS)\n\n")) {
    throw std::runtime_error("无法定位 unbound Makefile.in 的 daemon 链接规则");
  }

  if (!replaceOnce(MakefileIn,
                   "ALL_SRC=$(COMMON_SRC) $(UNITTEST_SRC) $(DAEMON_SRC) \\\n",
                   "ALL_SRC=$(COMMON_SRC) $(UNITTEST_SRC) $(DAEMON_SRC) \\\n"
                   "\t$(FUZZME_SRC) \\\n")) {
    throw std::runtime_error("无法定位 unbound Makefile.in 的 ALL_SRC 段");
  }

  if (!replaceOnce(MakefileIn,
                   "ALL_OBJ=$(COMMON_OBJ) $(UNITTEST_OBJ) $(DAEMON_OBJ) \\\n",
                   "ALL_OBJ=$(COMMON_OBJ) $(UNITTEST_OBJ) $(DAEMON_OBJ) \\\n"
                   "\t$(FUZZME_OBJ) \\\n")) {
    throw std::runtime_error("无法定位 unbound Makefile.in 的 ALL_OBJ 段");
  }

  if (!replaceOnce(MakefileIn,
                   "alltargets:\tunbound$(EXEEXT) unbound-checkconf$(EXEEXT) lib "
                   "unbound-host$(EXEEXT) unbound-control$(EXEEXT) "
                   "unbound-anchor$(EXEEXT) unbound-control-setup $(WINAPPS) "
                   "$(PYUNBOUND_TARGET)\n",
                   "alltargets:\tunbound$(EXEEXT) unbound-checkconf$(EXEEXT) lib "
                   "unbound-host$(EXEEXT) unbound-control$(EXEEXT) "
                   "unbound-anchor$(EXEEXT) unbound-control-setup "
                   "unbound-fuzzme$(EXEEXT) $(WINAPPS) $(PYUNBOUND_TARGET)\n")) {
    throw std::runtime_error("无法定位 unbound Makefile.in 的 alltargets 段");
  }

  if (!replaceOnce(MakefileIn,
                   "clean:\n\trm -f *.o *.d *.lo *~ tags\n\trm -f "
                   "unbound$(EXEEXT) unbound-checkconf$(EXEEXT) "
                   "unbound-host$(EXEEXT) unbound-control$(EXEEXT) "
                   "unbound-anchor$(EXEEXT) unbound-control-setup libunbound.la "
                   "unbound.h\n",
                   "clean:\n\trm -f *.o *.d *.lo *~ tags\n\trm -f "
                   "unbound$(EXEEXT) unbound-checkconf$(EXEEXT) "
                   "unbound-fuzzme$(EXEEXT) unbound-host$(EXEEXT) "
                   "unbound-control$(EXEEXT) unbound-anchor$(EXEEXT) "
                   "unbound-control-setup libunbound.la unbound.h\n")) {
    throw std::runtime_error("无法定位 unbound Makefile.in 的 clean 段");
  }

  if (!replaceOnce(
          MakefileIn,
          "$(srcdir)/respip/respip.h $(srcdir)/dnstap/dtstream.h\n",
          "$(srcdir)/respip/respip.h $(srcdir)/dnstap/dtstream.h\n"
          "unbound-fuzzme.lo unbound-fuzzme.o: "
          "$(srcdir)/smallapp/unbound-fuzzme.c config.h\n"
          "unbound_afl_symcc_orchestrator.lo unbound_afl_symcc_orchestrator.o: "
          "$(srcdir)/smallapp/unbound_afl_symcc_orchestrator.c config.h\n"
          "unbound_afl_symcc_mutator_server.lo unbound_afl_symcc_mutator_server.o: "
          "$(srcdir)/smallapp/unbound_afl_symcc_mutator_server.c config.h\n")) {
    throw std::runtime_error("无法定位 unbound Makefile.in 的 worker_cb 依赖尾部");
  }

  writeTextFile(MakefileInPath, MakefileIn);
}

void ensureUnboundHarnessTree(const std::filesystem::path &WorkspaceRoot,
                              const std::filesystem::path &TargetRoot) {
  copyPatchTree(WorkspaceRoot / "patch" / "cache" / "unbound", TargetRoot);
  ensureUnboundFuzzmeMakefile(TargetRoot);
  const auto ConfigStatus = TargetRoot / "config.status";
  if (std::filesystem::exists(ConfigStatus)) {
    const auto Result =
        runProcess({{"./config.status"}, TargetRoot, {}, std::nullopt});
    if (Result.ExitCode != 0) {
      throw std::runtime_error("unbound config.status 失败: " + Result.StderrText);
    }
  }
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

std::optional<std::filesystem::path> envRootPath(const char *EnvName) {
  if (EnvName == nullptr || *EnvName == '\0') {
    return std::nullopt;
  }
  if (const char *EnvValue = std::getenv(EnvName);
      EnvValue != nullptr && *EnvValue != '\0') {
    return normalizePath(EnvValue);
  }
  return std::nullopt;
}

std::filesystem::path resolveEnvPathOrDefault(
    const char *EnvName, const std::filesystem::path &DefaultPath) {
  if (const auto EnvPath = envRootPath(EnvName)) {
    return *EnvPath;
  }
  return DefaultPath;
}

void appendRelativeCandidates(
    std::vector<std::filesystem::path> &Candidates,
    const std::filesystem::path &Root,
    std::initializer_list<std::filesystem::path> RelativePaths) {
  if (Root.empty()) {
    return;
  }
  for (const auto &RelativePath : RelativePaths) {
    Candidates.push_back(Root / RelativePath);
  }
}

OracleArtifact makeOracleArtifact(const OracleSnapshot &Snapshot);

CommandResult runResolverHarness(const std::string &ResolverName,
                                 const std::vector<std::string> &HarnessArgs,
                                 const std::filesystem::path &RunRoot) {
  std::filesystem::create_directories(RunRoot);
  CommandResult Result =
      runProcess({HarnessArgs, std::nullopt, {}, std::nullopt});
  std::ofstream(RunRoot / (ResolverName + ".stderr")) << Result.StdoutText;
  return Result;
}

CommandResult runScriptedResolverMode(
    const std::string &ResolverName, const std::filesystem::path &BinaryPath,
    const std::string &MissingBinaryMessage,
    const std::filesystem::path &HarnessPath,
    const std::string &MissingHarnessMessage, const std::string &BinaryArgName,
    const std::string &Mode, const std::filesystem::path &CacheDumpPath,
    const std::string &NativeOutputArgName,
    const std::filesystem::path &NativeOutputPath,
    const std::filesystem::path &RunRoot,
    const std::optional<std::filesystem::path> &TranscriptPath = std::nullopt) {
  const auto Binary = requireExisting(BinaryPath, MissingBinaryMessage);
  const auto Harness = requireExisting(HarnessPath, MissingHarnessMessage);
  std::vector<std::string> HarnessArgs = {"python3", Harness.string(),
                                          BinaryArgName, Binary.string(),
                                          "--mode", Mode};
  if (TranscriptPath.has_value()) {
    HarnessArgs.push_back("--transcript");
    HarnessArgs.push_back(TranscriptPath->string());
  }
  HarnessArgs.push_back("--cache-dump-path");
  HarnessArgs.push_back(CacheDumpPath.string());
  HarnessArgs.push_back(NativeOutputArgName);
  HarnessArgs.push_back(NativeOutputPath.string());
  return runResolverHarness(ResolverName, HarnessArgs, RunRoot);
}

std::filesystem::path prepareMirroredBuildTree(
    const std::filesystem::path &SourceRoot,
    const std::filesystem::path &BuildRoot,
    const std::filesystem::path &ExistingLayoutProbe,
    const std::filesystem::path &MirroredSubdir) {
  if (std::filesystem::exists(BuildRoot / ExistingLayoutProbe)) {
    return BuildRoot;
  }
  const auto TargetRoot = BuildRoot / MirroredSubdir;
  if (std::filesystem::exists(TargetRoot / ExistingLayoutProbe)) {
    return TargetRoot;
  }
  if (std::filesystem::exists(TargetRoot)) {
    std::filesystem::remove_all(TargetRoot);
  }
  std::filesystem::create_directories(TargetRoot.parent_path());
  std::filesystem::copy(SourceRoot, TargetRoot,
                        std::filesystem::copy_options::recursive |
                            std::filesystem::copy_options::copy_symlinks);
  return TargetRoot;
}

OracleArtifact parseResolverOracleFile(const std::filesystem::path &OraclePath,
                                       const std::string &ResolverName) {
  std::ifstream Input(OraclePath);
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  return makeOracleArtifact(parseOracleSummary(Buffer.str(), ResolverName));
}

std::vector<std::filesystem::path>
collectResolverLogPair(const std::filesystem::path &RunRoot,
                       const std::string &ResolverName,
                       const std::filesystem::path &NativeLogPath) {
  std::vector<std::filesystem::path> Output;
  for (const auto &Candidate :
       {RunRoot / (ResolverName + ".stderr"), NativeLogPath}) {
    if (std::filesystem::exists(Candidate)) {
      Output.push_back(Candidate);
    }
  }
  return Output;
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
  std::vector<std::filesystem::path> Candidates;
  appendRelativeCandidates(Candidates, BuildRoot,
                           {"dnsmasq", "dnsmasq-afl/dnsmasq"});
  if (const auto EnvBuildRoot = envRootPath("DNSLAB_DNSMASQ_BUILD_ROOT");
      EnvBuildRoot.has_value()) {
    appendRelativeCandidates(Candidates, *EnvBuildRoot,
                             {"dnsmasq", "dnsmasq-afl/dnsmasq"});
  }
  appendRelativeCandidates(
      Candidates,
      Config.WorkspaceRoot / "experiments" / "subjects" / "dnsmasq" /
          "v2.92-afl",
      {"dnsmasq"});
  appendRelativeCandidates(Candidates, Config.WorkspaceRoot / "dnsmasq-2.92-afl",
                           {"dnsmasq"});
  return firstExisting(Candidates);
}

std::filesystem::path smartdnsBinaryPath(const SmartdnsAdapterConfig &Config,
                                         const std::filesystem::path &BuildRoot) {
  if (Config.BinaryPathOverride.has_value()) {
    return *Config.BinaryPathOverride;
  }
  std::vector<std::filesystem::path> Candidates;
  appendRelativeCandidates(
      Candidates, BuildRoot,
      {"src/smartdns", "smartdns-build/src/smartdns", "smartdns"});
  if (const auto EnvBuildRoot = envRootPath("DNSLAB_SMARTDNS_BUILD_ROOT");
      EnvBuildRoot.has_value()) {
    appendRelativeCandidates(
        Candidates, *EnvBuildRoot,
        {"src/smartdns", "smartdns-build/src/smartdns", "smartdns"});
  }
  appendRelativeCandidates(
      Candidates,
      Config.WorkspaceRoot / "experiments" / "subjects" / "smartdns" /
          "Release47.1-build",
      {"src/smartdns"});
  return firstExisting(Candidates);
}

std::filesystem::path maradnsBinaryPath(const MaradnsAdapterConfig &Config,
                                        const std::filesystem::path &BuildRoot) {
  if (Config.BinaryPathOverride.has_value()) {
    return *Config.BinaryPathOverride;
  }
  std::vector<std::filesystem::path> Candidates;
  appendRelativeCandidates(
      Candidates, BuildRoot,
      {"deadwood-build/deadwood-github/src/Deadwood",
       "deadwood-github/src/Deadwood", "Deadwood"});
  if (const auto EnvBuildRoot = envRootPath("DNSLAB_MARADNS_BUILD_ROOT");
      EnvBuildRoot.has_value()) {
    appendRelativeCandidates(
        Candidates, *EnvBuildRoot,
        {"deadwood-build/deadwood-github/src/Deadwood",
         "deadwood-github/src/Deadwood", "Deadwood"});
  }
  appendRelativeCandidates(
      Candidates,
      Config.WorkspaceRoot / "experiments" / "subjects" / "maradns" /
          "deadwood-3.3.02-build",
      {"deadwood-github/src/Deadwood"});
  return firstExisting(Candidates);
}

std::filesystem::path knotResolverBinaryPath(
    const KnotResolverAdapterConfig &Config,
    const std::filesystem::path &BuildRoot) {
  if (Config.BinaryPathOverride.has_value()) {
    return *Config.BinaryPathOverride;
  }
  std::vector<std::filesystem::path> Candidates;
  appendRelativeCandidates(Candidates, BuildRoot,
                           {"knot-build/daemon/kresd", "daemon/kresd"});
  if (const auto EnvBuildRoot = envRootPath("DNSLAB_KNOT_RESOLVER_BUILD_ROOT");
      EnvBuildRoot.has_value()) {
    appendRelativeCandidates(Candidates, *EnvBuildRoot,
                             {"knot-build/daemon/kresd", "daemon/kresd"});
  }
  appendRelativeCandidates(
      Candidates,
      Config.WorkspaceRoot / "experiments" / "subjects" / "knot-resolver" /
          "v6.2.0-build",
      {"knot-build/daemon/kresd"});
  return firstExisting(Candidates);
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
  ensureUnboundHarnessTree(Config_.WorkspaceRoot, TargetRoot);

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
  auto BuildResult =
      runProcess({{"make", "-j2", "unbound-fuzzme"}, TargetRoot, {}, std::nullopt});
  if (BuildResult.ExitCode != 0) {
    return BuildResult;
  }

  const auto TopLevelBinary = TargetRoot / "unbound-fuzzme";
  const auto CanonicalBinary = TargetRoot / ".libs" / "unbound-fuzzme";
  if (!std::filesystem::exists(CanonicalBinary) &&
      std::filesystem::exists(TopLevelBinary)) {
    std::filesystem::create_directories(CanonicalBinary.parent_path());
    std::filesystem::copy_file(TopLevelBinary, CanonicalBinary,
                               std::filesystem::copy_options::overwrite_existing);
  }
  return BuildResult;
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
  return prepareGitResolverSource(WorkspaceRoot, "dnsmasq", Tag,
                                  Config_.SourceFallbackPath,
                                  WorkspaceRoot / "dnsmasq-2.92",
                                  "https://github.com/imp/dnsmasq.git");
}

CommandResult
DnsmasqResolverAdapter::applyPatch(const std::filesystem::path &SourceRoot,
                                   const std::filesystem::path &PatchFile) const {
  return applyPatchFileOrTree(SourceRoot, PatchFile);
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
  const auto CacheDumpPath = Request.RunRoot / "dnsmasq.after.cache.txt";
  const auto NativeStderrPath = Request.RunRoot / "dnsmasq.native.stderr";
  return runScriptedResolverMode(
      "dnsmasq", dnsmasqBinaryPath(Config_, Request.BuildRoot),
      "缺少 dnsmasq 可执行文件", Config_.HarnessScriptPath,
      "缺少 dnsmasq replay harness", "--dnsmasq-bin", "run", CacheDumpPath,
      "--dnsmasq-stderr-path", NativeStderrPath, Request.RunRoot,
      Request.TranscriptPath);
}

CommandResult
DnsmasqResolverAdapter::dumpCache(const std::filesystem::path &RunRoot,
                                  const std::filesystem::path &OutputFile) const {
  const auto NativeStderrPath = RunRoot / "dnsmasq.native.stderr";
  return runScriptedResolverMode(
      "dnsmasq", dnsmasqBinaryPath(Config_, RunRoot), "缺少 dnsmasq 可执行文件",
      Config_.HarnessScriptPath, "缺少 dnsmasq replay harness",
      "--dnsmasq-bin", "dump", OutputFile, "--dnsmasq-stderr-path",
      NativeStderrPath, RunRoot);
}

CommandResult
DnsmasqResolverAdapter::flushCache(const std::filesystem::path &RunRoot) const {
  std::filesystem::remove_all(RunRoot);
  return {0, "", ""};
}

OracleArtifact
DnsmasqResolverAdapter::parseOracle(const std::filesystem::path &OraclePath) const {
  return parseResolverOracleFile(OraclePath, "dnsmasq");
}

std::vector<std::filesystem::path>
DnsmasqResolverAdapter::collectLogs(const std::filesystem::path &RunRoot) const {
  return collectResolverLogPair(RunRoot, "dnsmasq",
                                RunRoot / "dnsmasq.native.stderr");
}

SmartdnsResolverAdapter::SmartdnsResolverAdapter(SmartdnsAdapterConfig Config)
    : Config_(std::move(Config)) {}

std::string SmartdnsResolverAdapter::name() const { return "smartdns"; }

std::filesystem::path
SmartdnsResolverAdapter::prepareSource(const std::filesystem::path &WorkspaceRoot,
                                       const std::string &Tag) const {
  return prepareGitResolverSource(WorkspaceRoot, "smartdns", Tag,
                                  Config_.SourceFallbackPath,
                                  WorkspaceRoot / "smartdns-Release47.1",
                                  "https://github.com/pymumu/smartdns.git");
}

CommandResult
SmartdnsResolverAdapter::applyPatch(const std::filesystem::path &SourceRoot,
                                    const std::filesystem::path &PatchFile) const {
  return applyPatchFileOrTree(SourceRoot, PatchFile);
}

CommandResult
SmartdnsResolverAdapter::build(const std::filesystem::path &SourceRoot,
                               const std::filesystem::path &BuildRoot) const {
  const auto TargetRoot = prepareMirroredBuildTree(
      SourceRoot, BuildRoot, "src", "smartdns-build");
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
  const auto CacheDumpPath = Request.RunRoot / "smartdns.after.cache.txt";
  const auto NativeLogPath = Request.RunRoot / "smartdns.native.log";
  return runScriptedResolverMode(
      "smartdns", smartdnsBinaryPath(Config_, Request.BuildRoot),
      "缺少 smartdns 可执行文件", Config_.HarnessScriptPath,
      "缺少 smartdns replay harness", "--smartdns-bin", "run", CacheDumpPath,
      "--smartdns-log-path", NativeLogPath, Request.RunRoot,
      Request.TranscriptPath);
}

CommandResult
SmartdnsResolverAdapter::dumpCache(const std::filesystem::path &RunRoot,
                                   const std::filesystem::path &OutputFile) const {
  const auto NativeLogPath = RunRoot / "smartdns.native.log";
  return runScriptedResolverMode(
      "smartdns", smartdnsBinaryPath(Config_, RunRoot), "缺少 smartdns 可执行文件",
      Config_.HarnessScriptPath, "缺少 smartdns replay harness",
      "--smartdns-bin", "dump", OutputFile, "--smartdns-log-path",
      NativeLogPath, RunRoot);
}

CommandResult
SmartdnsResolverAdapter::flushCache(const std::filesystem::path &RunRoot) const {
  std::filesystem::remove_all(RunRoot);
  return {0, "", ""};
}

OracleArtifact
SmartdnsResolverAdapter::parseOracle(const std::filesystem::path &OraclePath) const {
  return parseResolverOracleFile(OraclePath, "smartdns");
}

std::vector<std::filesystem::path>
SmartdnsResolverAdapter::collectLogs(const std::filesystem::path &RunRoot) const {
  return collectResolverLogPair(RunRoot, "smartdns",
                                RunRoot / "smartdns.native.log");
}

MaradnsResolverAdapter::MaradnsResolverAdapter(MaradnsAdapterConfig Config)
    : Config_(std::move(Config)) {}

std::string MaradnsResolverAdapter::name() const { return "maradns"; }

std::filesystem::path
MaradnsResolverAdapter::prepareSource(const std::filesystem::path &WorkspaceRoot,
                                      const std::string &Tag) const {
  return prepareGitResolverSource(WorkspaceRoot, "maradns", Tag,
                                  Config_.SourceFallbackPath,
                                  WorkspaceRoot / "maradns-deadwood-3.3.02",
                                  "https://github.com/samboy/MaraDNS.git");
}

CommandResult
MaradnsResolverAdapter::applyPatch(const std::filesystem::path &SourceRoot,
                                   const std::filesystem::path &PatchFile) const {
  return applyPatchFileOrTree(SourceRoot, PatchFile);
}

CommandResult
MaradnsResolverAdapter::build(const std::filesystem::path &SourceRoot,
                              const std::filesystem::path &BuildRoot) const {
  const auto TargetRoot = prepareMirroredBuildTree(
      SourceRoot, BuildRoot, "deadwood-github", "deadwood-build");
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
  const auto CacheDumpPath = Request.RunRoot / "maradns.after.cache.txt";
  const auto NativeLogPath = Request.RunRoot / "maradns.native.log";
  return runScriptedResolverMode(
      "maradns", maradnsBinaryPath(Config_, Request.BuildRoot),
      "缺少 maradns/deadwood 可执行文件", Config_.HarnessScriptPath,
      "缺少 maradns replay harness", "--deadwood-bin", "run", CacheDumpPath,
      "--maradns-log-path", NativeLogPath, Request.RunRoot,
      Request.TranscriptPath);
}

CommandResult
MaradnsResolverAdapter::dumpCache(const std::filesystem::path &RunRoot,
                                  const std::filesystem::path &OutputFile) const {
  const auto NativeLogPath = RunRoot / "maradns.native.log";
  return runScriptedResolverMode(
      "maradns", maradnsBinaryPath(Config_, RunRoot),
      "缺少 maradns/deadwood 可执行文件", Config_.HarnessScriptPath,
      "缺少 maradns replay harness", "--deadwood-bin", "dump", OutputFile,
      "--maradns-log-path", NativeLogPath, RunRoot);
}

CommandResult
MaradnsResolverAdapter::flushCache(const std::filesystem::path &RunRoot) const {
  std::filesystem::remove_all(RunRoot);
  return {0, "", ""};
}

OracleArtifact
MaradnsResolverAdapter::parseOracle(const std::filesystem::path &OraclePath) const {
  return parseResolverOracleFile(OraclePath, "maradns");
}

std::vector<std::filesystem::path>
MaradnsResolverAdapter::collectLogs(const std::filesystem::path &RunRoot) const {
  return collectResolverLogPair(RunRoot, "maradns",
                                RunRoot / "maradns.native.log");
}

KnotResolverAdapter::KnotResolverAdapter(KnotResolverAdapterConfig Config)
    : Config_(std::move(Config)) {}

std::string KnotResolverAdapter::name() const { return "knot-resolver"; }

std::filesystem::path
KnotResolverAdapter::prepareSource(const std::filesystem::path &WorkspaceRoot,
                                   const std::string &Tag) const {
  return prepareGitResolverSource(WorkspaceRoot, "knot-resolver", Tag,
                                  Config_.SourceFallbackPath,
                                  WorkspaceRoot / ("knot-resolver-" + Tag),
                                  "https://github.com/CZ-NIC/knot-resolver.git");
}

CommandResult
KnotResolverAdapter::applyPatch(const std::filesystem::path &SourceRoot,
                                const std::filesystem::path &PatchFile) const {
  return applyPatchFileOrTree(SourceRoot, PatchFile);
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
  prepareKnotRuntimeAssets(SourceRoot, TargetRoot, RuntimePrefix);
  requireExisting(knotResolverBinaryPath(Config_, BuildRoot),
                  "缺少 knot-resolver 可执行文件");
  return BuildResult;
}

CommandResult
KnotResolverAdapter::runSample(const RunSampleRequest &Request) const {
  const auto CacheDumpPath = Request.RunRoot / "knot-resolver.after.cache.txt";
  const auto NativeLogPath = Request.RunRoot / "knot-resolver.native.log";
  return runScriptedResolverMode(
      "knot-resolver", knotResolverBinaryPath(Config_, Request.BuildRoot),
      "缺少 knot-resolver 可执行文件", Config_.HarnessScriptPath,
      "缺少 knot-resolver replay harness", "--kresd-bin", "run",
      CacheDumpPath, "--kresd-log-path", NativeLogPath, Request.RunRoot,
      Request.TranscriptPath);
}

CommandResult
KnotResolverAdapter::dumpCache(const std::filesystem::path &RunRoot,
                               const std::filesystem::path &OutputFile) const {
  const auto NativeLogPath = RunRoot / "knot-resolver.native.log";
  return runScriptedResolverMode(
      "knot-resolver", knotResolverBinaryPath(Config_, RunRoot),
      "缺少 knot-resolver 可执行文件", Config_.HarnessScriptPath,
      "缺少 knot-resolver replay harness", "--kresd-bin", "dump", OutputFile,
      "--kresd-log-path", NativeLogPath, RunRoot);
}

CommandResult
KnotResolverAdapter::flushCache(const std::filesystem::path &RunRoot) const {
  std::filesystem::remove_all(RunRoot);
  return {0, "", ""};
}

OracleArtifact
KnotResolverAdapter::parseOracle(const std::filesystem::path &OraclePath) const {
  return parseResolverOracleFile(OraclePath, "knot-resolver");
}

std::vector<std::filesystem::path>
KnotResolverAdapter::collectLogs(const std::filesystem::path &RunRoot) const {
  return collectResolverLogPair(RunRoot, "knot-resolver",
                                RunRoot / "knot-resolver.native.log");
}

ResolverRegistry
makeDefaultResolverRegistry(const std::filesystem::path &WorkspaceRoot) {
  ResolverRegistry Registry;
  Bind9AdapterConfig Bind9Config;
  Bind9Config.WorkspaceRoot = WorkspaceRoot;
  Bind9Config.ScriptPath =
      WorkspaceRoot / "named_experiment" / "run_named_afl_symcc.sh";
  Bind9Config.NamedConfTemplate = resolveEnvPathOrDefault(
      "BIND9_NAMED_CONF_TEMPLATE",
      WorkspaceRoot / "named_experiment" / "runtime" / "named.conf");
  Bind9Config.ResponseCorpusDir = resolveEnvPathOrDefault(
      "RESPONSE_CORPUS_DIR",
      WorkspaceRoot / "named_experiment" / "work" / "response_corpus");
  Bind9Config.SourceFallbackPath = std::nullopt;
  Bind9Config.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<Bind9ResolverAdapter>(std::move(Bind9Config)));

  UnboundAdapterConfig UnboundConfig;
  UnboundConfig.WorkspaceRoot = WorkspaceRoot;
  UnboundConfig.ResponseCorpusDir = resolveEnvPathOrDefault(
      "RESPONSE_CORPUS_DIR",
      WorkspaceRoot / "unbound_experiment" / "work_stateful" /
          "response_corpus");
  UnboundConfig.SourceFallbackPath = std::nullopt;
  UnboundConfig.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<UnboundResolverAdapter>(std::move(UnboundConfig)));

  DnsmasqAdapterConfig DnsmasqConfig;
  DnsmasqConfig.WorkspaceRoot = WorkspaceRoot;
  DnsmasqConfig.BuildJobs = 2;
  DnsmasqConfig.HarnessScriptPath = resolveEnvPathOrDefault(
      "DNSMASQ_HARNESS_SCRIPT",
      WorkspaceRoot / "tools" / "dnsmasq_replay_harness.py");
  DnsmasqConfig.SourceFallbackPath = std::nullopt;
  DnsmasqConfig.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<DnsmasqResolverAdapter>(std::move(DnsmasqConfig)));

  SmartdnsAdapterConfig SmartdnsConfig;
  SmartdnsConfig.WorkspaceRoot = WorkspaceRoot;
  SmartdnsConfig.BuildJobs = 2;
  SmartdnsConfig.HarnessScriptPath = resolveEnvPathOrDefault(
      "SMARTDNS_HARNESS_SCRIPT",
      WorkspaceRoot / "tools" / "smartdns_replay_harness.py");
  SmartdnsConfig.SourceFallbackPath = std::nullopt;
  SmartdnsConfig.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<SmartdnsResolverAdapter>(std::move(SmartdnsConfig)));

  MaradnsAdapterConfig MaradnsConfig;
  MaradnsConfig.WorkspaceRoot = WorkspaceRoot;
  MaradnsConfig.BuildJobs = 2;
  MaradnsConfig.HarnessScriptPath = resolveEnvPathOrDefault(
      "MARADNS_HARNESS_SCRIPT",
      WorkspaceRoot / "tools" / "maradns_replay_harness.py");
  MaradnsConfig.SourceFallbackPath = std::nullopt;
  MaradnsConfig.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<MaradnsResolverAdapter>(std::move(MaradnsConfig)));

  KnotResolverAdapterConfig KnotConfig;
  KnotConfig.WorkspaceRoot = WorkspaceRoot;
  KnotConfig.HarnessScriptPath = resolveEnvPathOrDefault(
      "KNOT_RESOLVER_HARNESS_SCRIPT",
      WorkspaceRoot / "tools" / "knot_resolver_replay_harness.py");
  KnotConfig.SourceFallbackPath = std::nullopt;
  KnotConfig.BinaryPathOverride = std::nullopt;
  Registry.registerAdapter(
      std::make_shared<KnotResolverAdapter>(std::move(KnotConfig)));

  return Registry;
}

} // namespace dnslab
