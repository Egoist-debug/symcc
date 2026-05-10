#include "dnslab_core/oracle.hpp"

#include <cassert>

int main() {
  const std::string Stderr =
      "noise\n===== bind9.after =====\nORACLE_SUMMARY parse_ok=1 "
      "resolver_fetch_started=1 response_accepted=0 second_query_hit=1 "
      "cache_entry_created=0 timeout=0\n";

  const auto Parsed =
      dnslab::parseOracleSummary(std::optional<std::string>(Stderr), "bind9");
  assert(Parsed.StderrParseStatus == "ok");
  assert(Parsed.ParseOk.has_value() && *Parsed.ParseOk);
  assert(Parsed.ResponseAccepted.has_value() && !*Parsed.ResponseAccepted);
  assert(Parsed.SecondQueryHit.has_value() && *Parsed.SecondQueryHit);

  const auto Missing =
      dnslab::parseOracleSummary(std::optional<std::string>(""), "unbound");
  assert(Missing.StderrParseStatus == "stderr_missing");

  const auto Json = dnslab::toJson(Parsed).dump(2);
  assert(Json.find("\"bind9.parse_ok\": true") != std::string::npos);
  return 0;
}
