#include "dnslab_core/resolver_lock.hpp"
#include "dnslab_core/evidence_contract.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <sys/wait.h>
#include <unordered_map>

namespace dnslab {

namespace {

std::vector<std::string> split(const std::string &Input, char Delimiter) {
  std::vector<std::string> Output;
  std::string Current;
  std::istringstream Stream(Input);
  while (std::getline(Stream, Current, Delimiter)) {
    if (!Current.empty()) {
      Output.push_back(Current);
    }
  }
  return Output;
}

std::string trim(const std::string &Input) {
  const auto Begin = Input.find_first_not_of(" \t\r\n");
  if (Begin == std::string::npos) {
    return "";
  }
  const auto End = Input.find_last_not_of(" \t\r\n");
  return Input.substr(Begin, End - Begin + 1);
}

std::optional<std::string> parseQuotedJsonField(const std::string &Line,
                                                const std::string &Key) {
  const std::string Needle = "\"" + Key + "\":";
  const auto KeyPos = Line.find(Needle);
  if (KeyPos == std::string::npos) {
    return std::nullopt;
  }
  const auto QuoteBegin = Line.find('"', KeyPos + Needle.size());
  if (QuoteBegin == std::string::npos) {
    return std::nullopt;
  }
  const auto QuoteEnd = Line.find('"', QuoteBegin + 1);
  if (QuoteEnd == std::string::npos) {
    return std::nullopt;
  }
  return Line.substr(QuoteBegin + 1, QuoteEnd - QuoteBegin - 1);
}

std::optional<std::optional<std::string>>
parseNullableJsonField(const std::string &Line, const std::string &Key) {
  const std::string Needle = "\"" + Key + "\":";
  const auto KeyPos = Line.find(Needle);
  if (KeyPos == std::string::npos) {
    return std::nullopt;
  }
  const std::string Tail = trim(Line.substr(KeyPos + Needle.size()));
  if (Tail.rfind("null", 0) == 0) {
    return std::optional<std::string>();
  }
  const auto Parsed = parseQuotedJsonField(Line, Key);
  if (!Parsed.has_value()) {
    throw std::runtime_error("lock JSON 字段格式非法: " + Key);
  }
  return Parsed;
}

std::string shellQuote(const std::string &Input) {
  std::string Output = "'";
  for (const char Ch : Input) {
    if (Ch == '\'') {
      Output += "'\\''";
    } else {
      Output.push_back(Ch);
    }
  }
  Output += "'";
  return Output;
}

std::unordered_map<std::string, std::string>
parseLsRemoteTags(const std::string &StdoutText) {
  std::unordered_map<std::string, std::string> Output;
  std::istringstream Stream(StdoutText);
  std::string Line;
  while (std::getline(Stream, Line)) {
    if (Line.empty()) {
      continue;
    }
    const auto Tab = Line.find('\t');
    if (Tab == std::string::npos) {
      continue;
    }
    const std::string Sha = Line.substr(0, Tab);
    std::string Ref = Line.substr(Tab + 1);
    const std::string Prefix = "refs/tags/";
    if (Ref.rfind(Prefix, 0) != 0) {
      continue;
    }
    Ref = Ref.substr(Prefix.size());
    const bool Peeled =
        Ref.size() > 3 && Ref.compare(Ref.size() - 3, 3, "^{}") == 0;
    if (Peeled) {
      Ref = Ref.substr(0, Ref.size() - 3);
    }
    if (!Output.count(Ref) || Peeled) {
      Output[Ref] = Sha;
    }
  }
  return Output;
}

} // namespace

std::string toString(ResolverLockStatus Input) {
  switch (Input) {
  case ResolverLockStatus::Locked:
    return "locked";
  case ResolverLockStatus::MissingDesiredTag:
    return "missing_desired_tag";
  case ResolverLockStatus::TagNotFound:
    return "tag_not_found";
  case ResolverLockStatus::GitFailure:
    return "git_failure";
  }
  return "git_failure";
}

std::filesystem::path
defaultResolverLockFilePath(const std::filesystem::path &WorkspaceRoot) {
  return WorkspaceRoot / "experiments" / "resolvers.lock.json";
}

std::vector<ResolverManifestEntry>
loadResolverManifestTsv(const std::filesystem::path &InputPath) {
  std::ifstream Input(InputPath);
  if (!Input) {
    throw std::runtime_error("无法打开 manifest: " + InputPath.string());
  }

  std::string Header;
  if (!std::getline(Input, Header)) {
    return {};
  }

  std::vector<ResolverManifestEntry> Output;
  std::string Line;
  while (std::getline(Input, Line)) {
    if (Line.empty()) {
      continue;
    }
    const auto Columns = split(Line, '\t');
    if (Columns.size() < 5U) {
      throw std::runtime_error("manifest 行字段不足: " + Line);
    }
    ResolverManifestEntry Entry;
    Entry.Resolver = Columns[0];
    Entry.RepoUrl = Columns[1];
    Entry.DesiredTag = Columns[2];
    Entry.CandidateTags = split(Columns[3], ',');
    Entry.Note = Columns[4];
    Output.push_back(std::move(Entry));
  }
  return Output;
}

ResolverLockFile
loadResolverLockFileJson(const std::filesystem::path &InputPath) {
  std::ifstream Input(InputPath);
  if (!Input) {
    throw std::runtime_error("无法打开 lock 文件: " + InputPath.string());
  }

  ResolverLockFile Output;
  std::optional<ResolverLockEntry> Current;
  bool InResolversArray = false;
  std::string Line;
  while (std::getline(Input, Line)) {
    const std::string Stripped = trim(Line);
    if (Stripped.empty()) {
      continue;
    }

    if (const auto Value = parseQuotedJsonField(Stripped, "generated_at")) {
      Output.GeneratedAt = *Value;
      continue;
    }
    if (const auto Value = parseQuotedJsonField(Stripped, "generator")) {
      Output.Generator = *Value;
      continue;
    }
    if (Stripped == "\"resolvers\": [") {
      InResolversArray = true;
      continue;
    }
    if (InResolversArray && !Current.has_value() && Stripped == "{") {
      Current = ResolverLockEntry{};
      continue;
    }
    if (InResolversArray && (Stripped == "]" || Stripped == "],")) {
      InResolversArray = false;
      continue;
    }
    if (const auto Value = parseQuotedJsonField(Stripped, "resolver")) {
      if (!Current.has_value()) {
        Current = ResolverLockEntry{};
      }
      Current->Resolver = *Value;
      continue;
    }
    if (!Current.has_value()) {
      continue;
    }
    if (const auto Value = parseQuotedJsonField(Stripped, "repo_url")) {
      Current->RepoUrl = *Value;
      continue;
    }
    if (const auto Value = parseQuotedJsonField(Stripped, "desired_tag")) {
      Current->DesiredTag = *Value;
      continue;
    }
    if (const auto Value = parseNullableJsonField(Stripped, "resolved_tag")) {
      Current->ResolvedTag = *Value;
      continue;
    }
    if (const auto Value = parseNullableJsonField(Stripped, "commit_sha")) {
      Current->CommitSha = *Value;
      continue;
    }
    if (const auto Value = parseQuotedJsonField(Stripped, "status")) {
      if (*Value == "locked") {
        Current->Status = ResolverLockStatus::Locked;
      } else if (*Value == "missing_desired_tag") {
        Current->Status = ResolverLockStatus::MissingDesiredTag;
      } else if (*Value == "tag_not_found") {
        Current->Status = ResolverLockStatus::TagNotFound;
      } else if (*Value == "git_failure") {
        Current->Status = ResolverLockStatus::GitFailure;
      } else {
        throw std::runtime_error("未知 lock status: " + *Value);
      }
      continue;
    }
    if (const auto Value = parseQuotedJsonField(Stripped, "note")) {
      Current->Note = *Value;
      continue;
    }
    if (Stripped == "}" || Stripped == "},") {
      if (Current.has_value() && !Current->Resolver.empty()) {
        Output.Resolvers.push_back(*Current);
        Current.reset();
      }
    }
  }

  if (Current.has_value() && !Current->Resolver.empty()) {
    Output.Resolvers.push_back(*Current);
  }
  return Output;
}

ResolverLockFile
generateResolverLockFile(const std::vector<ResolverManifestEntry> &Manifest,
                         const CommandRunner &Runner) {
  ResolverLockFile Output;
  Output.GeneratedAt = utcTimestampNow();
  Output.Generator = "dnslabctl lock-generate";

  for (const auto &Entry : Manifest) {
    ResolverLockEntry Locked;
    Locked.Resolver = Entry.Resolver;
    Locked.RepoUrl = Entry.RepoUrl;
    Locked.DesiredTag = Entry.DesiredTag;
    Locked.Note = Entry.Note;

    if (Entry.DesiredTag.empty()) {
      Locked.Status = ResolverLockStatus::MissingDesiredTag;
      Output.Resolvers.push_back(std::move(Locked));
      continue;
    }

    const CommandOutput Command =
        Runner({"git", "ls-remote", "--tags", Entry.RepoUrl});
    if (Command.ExitCode != 0) {
      Locked.Status = ResolverLockStatus::GitFailure;
      Locked.Note += " | git ls-remote 失败: " + Command.StderrText;
      Output.Resolvers.push_back(std::move(Locked));
      continue;
    }

    const auto Tags = parseLsRemoteTags(Command.StdoutText);
    const auto Found = Tags.find(Entry.DesiredTag);
    if (Found == Tags.end()) {
      Locked.Status = ResolverLockStatus::TagNotFound;
      Output.Resolvers.push_back(std::move(Locked));
      continue;
    }

    Locked.Status = ResolverLockStatus::Locked;
    Locked.ResolvedTag = Entry.DesiredTag;
    Locked.CommitSha = Found->second;
    Output.Resolvers.push_back(std::move(Locked));
  }

  return Output;
}

std::optional<ResolverLockEntry>
findResolverLockEntry(const ResolverLockFile &Input, const std::string &Resolver) {
  for (const auto &Entry : Input.Resolvers) {
    if (Entry.Resolver == Resolver) {
      return Entry;
    }
  }
  return std::nullopt;
}

std::optional<std::string>
resolveLockedTag(const ResolverLockFile &Input, const std::string &Resolver) {
  const auto Entry = findResolverLockEntry(Input, Resolver);
  if (!Entry.has_value()) {
    return std::nullopt;
  }
  if (Entry->ResolvedTag.has_value() && !Entry->ResolvedTag->empty()) {
    return Entry->ResolvedTag;
  }
  if (!Entry->DesiredTag.empty()) {
    return Entry->DesiredTag;
  }
  return std::nullopt;
}

CommandOutput runCommand(const std::vector<std::string> &Arguments) {
  if (Arguments.empty()) {
    return {1, "", "empty command"};
  }

  std::ostringstream Command;
  for (size_t Index = 0; Index < Arguments.size(); ++Index) {
    if (Index != 0) {
      Command << ' ';
    }
    Command << shellQuote(Arguments[Index]);
  }
  Command << " 2>&1";

  FILE *Pipe = popen(Command.str().c_str(), "r");
  if (Pipe == nullptr) {
    return {1, "", "popen failed"};
  }

  std::string Output;
  char Buffer[4096];
  while (fgets(Buffer, sizeof(Buffer), Pipe) != nullptr) {
    Output += Buffer;
  }

  const int RawCode = pclose(Pipe);
  const int ExitCode = WIFEXITED(RawCode) ? WEXITSTATUS(RawCode) : RawCode;
  if (ExitCode == 0) {
    return {0, Output, ""};
  }
  return {ExitCode, "", Output};
}

void writeResolverLockFile(const std::filesystem::path &OutputPath,
                           const ResolverLockFile &Input) {
  std::filesystem::create_directories(OutputPath.parent_path());
  std::ofstream Output(OutputPath);
  if (!Output) {
    throw std::runtime_error("无法写入 lock 文件: " + OutputPath.string());
  }
  Output << toJson(Input).dump(2) << '\n';
}

json::Value toJson(const ResolverLockEntry &Input) {
  json::Value::Object Output;
  Output["resolver"] = Input.Resolver;
  Output["repo_url"] = Input.RepoUrl;
  Output["desired_tag"] = Input.DesiredTag;
  json::setOptional(Output, "resolved_tag", Input.ResolvedTag);
  json::setOptional(Output, "commit_sha", Input.CommitSha);
  Output["status"] = toString(Input.Status);
  Output["note"] = Input.Note;
  return Output;
}

json::Value toJson(const ResolverLockFile &Input) {
  json::Value::Object Output;
  Output["generated_at"] = Input.GeneratedAt;
  Output["generator"] = Input.Generator;
  json::Value::Array Resolvers;
  for (const auto &Entry : Input.Resolvers) {
    Resolvers.emplace_back(toJson(Entry));
  }
  Output["resolvers"] = Resolvers;
  return Output;
}

} // namespace dnslab
