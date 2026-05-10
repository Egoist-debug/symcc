#pragma once

#include "dnslab_core/json_value.hpp"

#include <optional>
#include <string>

namespace dnslab {

struct OracleSnapshot {
  std::string Resolver;
  std::string StderrParseStatus;
  std::optional<bool> ParseOk;
  std::optional<bool> ResolverFetchStarted;
  std::optional<bool> ResponseAccepted;
  std::optional<bool> SecondQueryHit;
  std::optional<bool> CacheEntryCreated;
  std::optional<bool> Timeout;
};

OracleSnapshot emptyOracle(const std::string &Resolver,
                           const std::string &Status);
OracleSnapshot parseOracleSummary(const std::optional<std::string> &StderrText,
                                  const std::string &Resolver);
json::Value toJson(const OracleSnapshot &Input);

} // namespace dnslab
