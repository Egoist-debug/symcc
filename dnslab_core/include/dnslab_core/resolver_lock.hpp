#pragma once

#include "dnslab_core/json_value.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace dnslab {

struct ResolverManifestEntry {
  std::string Resolver;
  std::string RepoUrl;
  std::string DesiredTag;
  std::vector<std::string> CandidateTags;
  std::string Note;
};

enum class ResolverLockStatus {
  Locked,
  MissingDesiredTag,
  TagNotFound,
  GitFailure,
};

struct ResolverLockEntry {
  std::string Resolver;
  std::string RepoUrl;
  std::string DesiredTag;
  std::optional<std::string> ResolvedTag;
  std::optional<std::string> CommitSha;
  ResolverLockStatus Status = ResolverLockStatus::MissingDesiredTag;
  std::string Note;
};

struct ResolverLockFile {
  std::string GeneratedAt;
  std::string Generator;
  std::vector<ResolverLockEntry> Resolvers;
};

struct CommandOutput {
  int ExitCode = 0;
  std::string StdoutText;
  std::string StderrText;
};

using CommandRunner = std::function<CommandOutput(const std::vector<std::string> &)>;

std::string toString(ResolverLockStatus Input);
std::filesystem::path
defaultResolverLockFilePath(const std::filesystem::path &WorkspaceRoot);
std::vector<ResolverManifestEntry>
loadResolverManifestTsv(const std::filesystem::path &InputPath);
ResolverLockFile
loadResolverLockFileJson(const std::filesystem::path &InputPath);
ResolverLockFile
generateResolverLockFile(const std::vector<ResolverManifestEntry> &Manifest,
                         const CommandRunner &Runner);
std::optional<ResolverLockEntry>
findResolverLockEntry(const ResolverLockFile &Input, const std::string &Resolver);
std::optional<std::string>
resolveLockedTag(const ResolverLockFile &Input, const std::string &Resolver);
CommandOutput runCommand(const std::vector<std::string> &Arguments);
void writeResolverLockFile(const std::filesystem::path &OutputPath,
                           const ResolverLockFile &Input);

json::Value toJson(const ResolverLockEntry &Input);
json::Value toJson(const ResolverLockFile &Input);

} // namespace dnslab
