#pragma once

#include "dnslab_core/process.hpp"
#include "dnslab_core/resolver_adapter.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace dnslab {

struct Bind9AdapterConfig {
  std::filesystem::path WorkspaceRoot;
  std::filesystem::path ScriptPath;
  std::filesystem::path NamedConfTemplate;
  std::filesystem::path ResponseCorpusDir;
  std::string MutatorAddr = "127.0.0.1:55300";
  std::string TargetAddr = "127.0.0.1:55301";
  int ReplyTimeoutMs = 50;
  int SeedTimeoutSec = 5;
  std::optional<std::filesystem::path> SourceFallbackPath;
  std::optional<std::filesystem::path> BinaryPathOverride;
};

struct UnboundAdapterConfig {
  std::filesystem::path WorkspaceRoot;
  std::filesystem::path ResponseCorpusDir;
  int SeedTimeoutSec = 5;
  std::optional<std::filesystem::path> SourceFallbackPath;
  std::optional<std::filesystem::path> BinaryPathOverride;
};

struct DnsmasqAdapterConfig {
  std::filesystem::path WorkspaceRoot;
  int BuildJobs = 2;
  std::filesystem::path HarnessScriptPath;
  std::optional<std::filesystem::path> SourceFallbackPath;
  std::optional<std::filesystem::path> BinaryPathOverride;
};

struct SmartdnsAdapterConfig {
  std::filesystem::path WorkspaceRoot;
  int BuildJobs = 2;
  std::filesystem::path HarnessScriptPath;
  std::optional<std::filesystem::path> SourceFallbackPath;
  std::optional<std::filesystem::path> BinaryPathOverride;
};

struct MaradnsAdapterConfig {
  std::filesystem::path WorkspaceRoot;
  int BuildJobs = 2;
  std::filesystem::path HarnessScriptPath;
  std::optional<std::filesystem::path> SourceFallbackPath;
  std::optional<std::filesystem::path> BinaryPathOverride;
};

struct KnotResolverAdapterConfig {
  std::filesystem::path WorkspaceRoot;
  std::filesystem::path HarnessScriptPath;
  std::optional<std::filesystem::path> SourceFallbackPath;
  std::optional<std::filesystem::path> BinaryPathOverride;
};

class Bind9ResolverAdapter : public ResolverAdapter {
public:
  explicit Bind9ResolverAdapter(Bind9AdapterConfig Config);

  std::string name() const override;
  std::filesystem::path
  prepareSource(const std::filesystem::path &WorkspaceRoot,
                const std::string &Tag) const override;
  CommandResult applyPatch(const std::filesystem::path &SourceRoot,
                           const std::filesystem::path &PatchFile) const override;
  CommandResult build(const std::filesystem::path &SourceRoot,
                      const std::filesystem::path &BuildRoot) const override;
  CommandResult runSample(const RunSampleRequest &Request) const override;
  CommandResult dumpCache(const std::filesystem::path &RunRoot,
                          const std::filesystem::path &OutputFile) const override;
  CommandResult flushCache(const std::filesystem::path &RunRoot) const override;
  OracleArtifact
  parseOracle(const std::filesystem::path &OraclePath) const override;
  std::vector<std::filesystem::path>
  collectLogs(const std::filesystem::path &RunRoot) const override;

private:
  Bind9AdapterConfig Config_;
};

class UnboundResolverAdapter : public ResolverAdapter {
public:
  explicit UnboundResolverAdapter(UnboundAdapterConfig Config);

  std::string name() const override;
  std::filesystem::path
  prepareSource(const std::filesystem::path &WorkspaceRoot,
                const std::string &Tag) const override;
  CommandResult applyPatch(const std::filesystem::path &SourceRoot,
                           const std::filesystem::path &PatchFile) const override;
  CommandResult build(const std::filesystem::path &SourceRoot,
                      const std::filesystem::path &BuildRoot) const override;
  CommandResult runSample(const RunSampleRequest &Request) const override;
  CommandResult dumpCache(const std::filesystem::path &RunRoot,
                          const std::filesystem::path &OutputFile) const override;
  CommandResult flushCache(const std::filesystem::path &RunRoot) const override;
  OracleArtifact
  parseOracle(const std::filesystem::path &OraclePath) const override;
  std::vector<std::filesystem::path>
  collectLogs(const std::filesystem::path &RunRoot) const override;

private:
  UnboundAdapterConfig Config_;
};

class DnsmasqResolverAdapter : public ResolverAdapter {
public:
  explicit DnsmasqResolverAdapter(DnsmasqAdapterConfig Config);

  std::string name() const override;
  std::filesystem::path
  prepareSource(const std::filesystem::path &WorkspaceRoot,
                const std::string &Tag) const override;
  CommandResult applyPatch(const std::filesystem::path &SourceRoot,
                           const std::filesystem::path &PatchFile) const override;
  CommandResult build(const std::filesystem::path &SourceRoot,
                      const std::filesystem::path &BuildRoot) const override;
  CommandResult runSample(const RunSampleRequest &Request) const override;
  CommandResult dumpCache(const std::filesystem::path &RunRoot,
                          const std::filesystem::path &OutputFile) const override;
  CommandResult flushCache(const std::filesystem::path &RunRoot) const override;
  OracleArtifact
  parseOracle(const std::filesystem::path &OraclePath) const override;
  std::vector<std::filesystem::path>
  collectLogs(const std::filesystem::path &RunRoot) const override;

private:
  DnsmasqAdapterConfig Config_;
};

class SmartdnsResolverAdapter : public ResolverAdapter {
public:
  explicit SmartdnsResolverAdapter(SmartdnsAdapterConfig Config);

  std::string name() const override;
  std::filesystem::path
  prepareSource(const std::filesystem::path &WorkspaceRoot,
                const std::string &Tag) const override;
  CommandResult applyPatch(const std::filesystem::path &SourceRoot,
                           const std::filesystem::path &PatchFile) const override;
  CommandResult build(const std::filesystem::path &SourceRoot,
                      const std::filesystem::path &BuildRoot) const override;
  CommandResult runSample(const RunSampleRequest &Request) const override;
  CommandResult dumpCache(const std::filesystem::path &RunRoot,
                          const std::filesystem::path &OutputFile) const override;
  CommandResult flushCache(const std::filesystem::path &RunRoot) const override;
  OracleArtifact
  parseOracle(const std::filesystem::path &OraclePath) const override;
  std::vector<std::filesystem::path>
  collectLogs(const std::filesystem::path &RunRoot) const override;

private:
  SmartdnsAdapterConfig Config_;
};

class MaradnsResolverAdapter : public ResolverAdapter {
public:
  explicit MaradnsResolverAdapter(MaradnsAdapterConfig Config);

  std::string name() const override;
  std::filesystem::path
  prepareSource(const std::filesystem::path &WorkspaceRoot,
                const std::string &Tag) const override;
  CommandResult applyPatch(const std::filesystem::path &SourceRoot,
                           const std::filesystem::path &PatchFile) const override;
  CommandResult build(const std::filesystem::path &SourceRoot,
                      const std::filesystem::path &BuildRoot) const override;
  CommandResult runSample(const RunSampleRequest &Request) const override;
  CommandResult dumpCache(const std::filesystem::path &RunRoot,
                          const std::filesystem::path &OutputFile) const override;
  CommandResult flushCache(const std::filesystem::path &RunRoot) const override;
  OracleArtifact
  parseOracle(const std::filesystem::path &OraclePath) const override;
  std::vector<std::filesystem::path>
  collectLogs(const std::filesystem::path &RunRoot) const override;

private:
  MaradnsAdapterConfig Config_;
};

class KnotResolverAdapter : public ResolverAdapter {
public:
  explicit KnotResolverAdapter(KnotResolverAdapterConfig Config);

  std::string name() const override;
  std::filesystem::path
  prepareSource(const std::filesystem::path &WorkspaceRoot,
                const std::string &Tag) const override;
  CommandResult applyPatch(const std::filesystem::path &SourceRoot,
                           const std::filesystem::path &PatchFile) const override;
  CommandResult build(const std::filesystem::path &SourceRoot,
                      const std::filesystem::path &BuildRoot) const override;
  CommandResult runSample(const RunSampleRequest &Request) const override;
  CommandResult dumpCache(const std::filesystem::path &RunRoot,
                          const std::filesystem::path &OutputFile) const override;
  CommandResult flushCache(const std::filesystem::path &RunRoot) const override;
  OracleArtifact
  parseOracle(const std::filesystem::path &OraclePath) const override;
  std::vector<std::filesystem::path>
  collectLogs(const std::filesystem::path &RunRoot) const override;

private:
  KnotResolverAdapterConfig Config_;
};

ResolverRegistry makeDefaultResolverRegistry(
    const std::filesystem::path &WorkspaceRoot);

} // namespace dnslab
