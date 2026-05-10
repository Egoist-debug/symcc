#include "dnslab_core/oracle.hpp"

#include <sstream>
#include <unordered_map>

namespace dnslab {

namespace {

std::optional<bool> parseBoolToken(const std::optional<std::string> &Input) {
  if (!Input.has_value()) {
    return std::nullopt;
  }
  if (*Input == "0") {
    return false;
  }
  if (*Input == "1") {
    return true;
  }
  return std::nullopt;
}

std::string summaryScope(const std::string &StderrText,
                         const std::string &Resolver) {
  const std::string Marker = "===== " + Resolver + ".after =====";
  const auto Position = StderrText.rfind(Marker);
  if (Position == std::string::npos) {
    return StderrText;
  }
  return StderrText.substr(Position + Marker.size());
}

} // namespace

OracleSnapshot emptyOracle(const std::string &Resolver,
                           const std::string &Status) {
  OracleSnapshot Output;
  Output.Resolver = Resolver;
  Output.StderrParseStatus = Status;
  return Output;
}

OracleSnapshot parseOracleSummary(const std::optional<std::string> &StderrText,
                                  const std::string &Resolver) {
  if (!StderrText.has_value() || StderrText->empty()) {
    return emptyOracle(Resolver, "stderr_missing");
  }

  const std::string Scoped = summaryScope(*StderrText, Resolver);
  std::istringstream Stream(Scoped);
  std::string Line;
  std::string Body;
  while (std::getline(Stream, Line)) {
    const auto Marker = Line.find("ORACLE_SUMMARY");
    if (Marker != std::string::npos) {
      Body = Line.substr(Marker + std::string("ORACLE_SUMMARY").size());
    }
  }

  if (Body.empty()) {
    return emptyOracle(Resolver, "missing_summary");
  }

  std::unordered_map<std::string, std::string> Tokens;
  std::istringstream TokenStream(Body);
  std::string Chunk;
  while (TokenStream >> Chunk) {
    const auto Split = Chunk.find('=');
    if (Split == std::string::npos) {
      continue;
    }
    Tokens[Chunk.substr(0, Split)] = Chunk.substr(Split + 1);
  }

  OracleSnapshot Output = emptyOracle(Resolver, "ok");
  bool AllOk = true;
  const auto read = [&](const char *Key) -> std::optional<bool> {
    const auto It = Tokens.find(Key);
    if (It == Tokens.end()) {
      AllOk = false;
      return std::nullopt;
    }
    const auto Parsed = parseBoolToken(It->second);
    if (!Parsed.has_value()) {
      AllOk = false;
    }
    return Parsed;
  };

  Output.ParseOk = read("parse_ok");
  Output.ResolverFetchStarted = read("resolver_fetch_started");
  Output.ResponseAccepted = read("response_accepted");
  Output.SecondQueryHit = read("second_query_hit");
  Output.CacheEntryCreated = read("cache_entry_created");
  Output.Timeout = read("timeout");

  if (!AllOk) {
    Output.StderrParseStatus = "missing_summary";
  }
  return Output;
}

json::Value toJson(const OracleSnapshot &Input) {
  json::Value::Object Output;
  json::setOptional(Output, Input.Resolver + ".parse_ok", Input.ParseOk);
  json::setOptional(Output, Input.Resolver + ".resolver_fetch_started",
                    Input.ResolverFetchStarted);
  json::setOptional(Output, Input.Resolver + ".response_accepted",
                    Input.ResponseAccepted);
  json::setOptional(Output, Input.Resolver + ".second_query_hit",
                    Input.SecondQueryHit);
  json::setOptional(Output, Input.Resolver + ".cache_entry_created",
                    Input.CacheEntryCreated);
  json::setOptional(Output, Input.Resolver + ".timeout", Input.Timeout);
  Output[Input.Resolver + ".stderr_parse_status"] = Input.StderrParseStatus;
  return Output;
}

} // namespace dnslab
