#include "dnslab_core/oracle.hpp"

// 独立编译和 release 构建都必须执行断言。
#ifdef NDEBUG
#undef NDEBUG
#endif
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
  assert(!Parsed.FakeReplyDispatched.has_value());

  const auto Missing =
      dnslab::parseOracleSummary(std::optional<std::string>(""), "unbound");
  assert(Missing.StderrParseStatus == "stderr_missing");
  assert(!Missing.FakeReplyDispatched.has_value());
  assert(dnslab::toJson(Missing).dump(0).find(
             "\"unbound.fake_reply_dispatched\":null") != std::string::npos);

  const auto Json = dnslab::toJson(Parsed).dump(2);
  assert(Json.find("\"bind9.parse_ok\": true") != std::string::npos);

  const struct {
    const char *Token;
    std::optional<bool> Dispatched;
    const char *JsonValue;
  } Cases[] = {
      {"", std::nullopt, "null"},
      {" fake_reply_dispatched=0", false, "false"},
      {" fake_reply_dispatched=1", true, "true"},
      {" fake_reply_dispatched=2", std::nullopt, "null"},
      {" fake_reply_dispatched=true", std::nullopt, "null"},
      {" fake_reply_dispatched=false", std::nullopt, "null"},
      {" fake_reply_dispatched=", std::nullopt, "null"},
  };
  for (const std::string Resolver : {"bind9", "unbound"}) {
    for (const bool Accepted : {false, true}) {
      for (const auto &Case : Cases) {
        const auto Summary =
            "ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 "
            "response_accepted=" +
            std::string(Accepted ? "1" : "0") +
            " second_query_hit=0 cache_entry_created=0 timeout=0" + Case.Token;
        const auto Snapshot = dnslab::parseOracleSummary(Summary, Resolver);
        assert(Snapshot.StderrParseStatus == "ok");
        assert(Snapshot.ResponseAccepted == Accepted);
        assert(Snapshot.FakeReplyDispatched == Case.Dispatched);
        const auto Output = dnslab::toJson(Snapshot);
        assert(std::get<dnslab::json::Value::Object>(Output.storage()).size() ==
               8);
        assert(Output.dump(0).find("\"" + Resolver +
                                   ".fake_reply_dispatched\":" +
                                   Case.JsonValue) != std::string::npos);
      }
    }
  }

  const auto MissingSummary = dnslab::parseOracleSummary("noise\n", "bind9");
  assert(MissingSummary.StderrParseStatus == "missing_summary");
  assert(!MissingSummary.FakeReplyDispatched.has_value());
  assert(dnslab::toJson(MissingSummary).dump(0).find(
             "\"bind9.fake_reply_dispatched\":null") != std::string::npos);

  const auto Partial = dnslab::parseOracleSummary(
      "ORACLE_SUMMARY parse_ok=1 fake_reply_dispatched=1", "bind9");
  assert(Partial.StderrParseStatus == "missing_summary");
  assert(Partial.FakeReplyDispatched == true);
  assert(dnslab::toJson(Partial).dump(0).find(
             "\"bind9.fake_reply_dispatched\":true") != std::string::npos);
  return 0;
}
