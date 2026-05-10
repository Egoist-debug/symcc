#pragma once

#include "dnslab_core/json_value.hpp"

#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace dnslab {

struct CommandResult {
  int ExitCode = 0;
  std::string StdoutText;
  std::string StderrText;
};

struct RunSampleRequest {
  std::filesystem::path SourceRoot;
  std::filesystem::path BuildRoot;
  std::filesystem::path RunRoot;
  std::filesystem::path TranscriptPath;
  std::string SampleId;
  std::map<std::string, std::string> Environment;
};

struct OracleArtifact {
  std::string ResolverName;
  bool ParseOk = false;
  json::Value::Object Fields;
};

class ResolverAdapter {
public:
  virtual ~ResolverAdapter() = default;

  virtual std::string name() const = 0;
  virtual std::filesystem::path
  prepareSource(const std::filesystem::path &WorkspaceRoot,
                const std::string &Tag) const = 0;
  virtual CommandResult applyPatch(const std::filesystem::path &SourceRoot,
                                   const std::filesystem::path &PatchFile) const = 0;
  virtual CommandResult build(const std::filesystem::path &SourceRoot,
                              const std::filesystem::path &BuildRoot) const = 0;
  virtual CommandResult runSample(const RunSampleRequest &Request) const = 0;
  virtual CommandResult dumpCache(const std::filesystem::path &RunRoot,
                                  const std::filesystem::path &OutputFile) const = 0;
  virtual CommandResult flushCache(const std::filesystem::path &RunRoot) const = 0;
  virtual OracleArtifact
  parseOracle(const std::filesystem::path &OraclePath) const = 0;
  virtual std::vector<std::filesystem::path>
  collectLogs(const std::filesystem::path &RunRoot) const = 0;
};

class ResolverRegistry {
public:
  void registerAdapter(std::shared_ptr<ResolverAdapter> Adapter) {
    const std::string Name = Adapter ? Adapter->name() : "";
    if (Name.empty()) {
      throw std::invalid_argument("adapter name 不能为空");
    }
    Adapters_[Name] = std::move(Adapter);
  }

  const ResolverAdapter &require(const std::string &Name) const {
    const auto Found = Adapters_.find(Name);
    if (Found == Adapters_.end() || !Found->second) {
      throw std::out_of_range("未注册 resolver adapter: " + Name);
    }
    return *Found->second;
  }

  std::vector<std::string> names() const {
    std::vector<std::string> Output;
    Output.reserve(Adapters_.size());
    for (const auto &[Name, Adapter] : Adapters_) {
      if (Adapter) {
        Output.push_back(Name);
      }
    }
    return Output;
  }

private:
  std::unordered_map<std::string, std::shared_ptr<ResolverAdapter>> Adapters_;
};

inline std::filesystem::path patchPathFor(const std::filesystem::path &PatchRoot,
                                          const std::string &Purpose,
                                          const std::string &Resolver,
                                          const std::string &Tag) {
  return PatchRoot / Purpose / Resolver / (Tag + ".patch");
}

inline std::filesystem::path
defaultSubjectRoot(const std::filesystem::path &WorkspaceRoot,
                   const std::string &Resolver, const std::string &Tag) {
  return WorkspaceRoot / "experiments" / "subjects" / Resolver / Tag;
}

} // namespace dnslab
