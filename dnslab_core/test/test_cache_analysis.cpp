#include "dnslab_core/cache_analysis.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>

namespace {

std::filesystem::path writeTempFile(const std::string &Name,
                                    const std::string &Content) {
  const auto Path = std::filesystem::temp_directory_path() / Name;
  std::ofstream Output(Path);
  Output << Content;
  return Path;
}

void require(bool Condition, const char *Message) {
  if (Condition) {
    return;
  }
  std::fprintf(stderr, "%s\n", Message);
  std::abort();
}

} // namespace

int main() {
  const auto BindPath = writeTempFile(
      "dnslab_bind_cache.txt",
      "; Cache dump of view '_default'\n"
      "example.com. 300 IN A 192.0.2.1\n"
      "; SERVFAIL cache\n"
      "; bad.example/A [ttl 5]\n");

  const auto UnboundPath = writeTempFile(
      "dnslab_unbound_cache.txt",
      "START_RRSET_CACHE\n"
      "example.com. 300 IN A 192.0.2.2\n"
      "END_RRSET_CACHE\n"
      "START_MSG_CACHE\n"
      "msg example.com. IN A NOERROR 1 300 0 1 0 0 0 ok\n"
      "EOF\n");
  const auto DnsmasqPath = writeTempFile(
      "dnslab_dnsmasq_cache.txt",
      "May 10 05:49:01 dnsmasq[250875]: Host                           Address                                  Flags      Expires                  Source\n"
      "May 10 05:49:01 dnsmasq[250875]: ------------------------------ ---------------------------------------- ---------- ------------------------ ------------\n"
      "May 10 05:49:01 dnsmasq[250875]: bind                                                                    !F I    C\n"
      "May 10 05:49:01 dnsmasq[250875]: example.com                    1.2.3.4                                  4F         Sun May 10 05:50:01 2026\n"
      "May 10 05:49:02 dnsmasq[250875]: exiting on receipt of SIGTERM\n");
  const auto SmartdnsPath = std::filesystem::temp_directory_path() / "dnslab_smartdns_cache.bin";
  {
    std::ofstream Output(SmartdnsPath, std::ios::binary);
    const std::string Domain = "example.com";
    const std::string Version = "cache ver 1.3";
    const std::uint64_t FileMagic = 0x6548634163536E44ULL;
    const std::uint32_t RecordMagic = 0x64526352U;
    const std::uint32_t DataMagic = 0x61546144U;
    std::uint32_t CacheNumber = 1;
    char VersionBytes[32] = {0};
    std::memcpy(VersionBytes, Version.data(), Version.size());
    Output.write(reinterpret_cast<const char *>(&FileMagic), sizeof(FileMagic));
    Output.write(VersionBytes, sizeof(VersionBytes));
    Output.write(reinterpret_cast<const char *>(&CacheNumber), sizeof(CacheNumber));
    char HeaderPadding[4] = {0};
    Output.write(HeaderPadding, sizeof(HeaderPadding));

    Output.write(reinterpret_cast<const char *>(&RecordMagic), sizeof(RecordMagic));
    Output.write(HeaderPadding, sizeof(HeaderPadding));
    char Info[344] = {0};
    std::memcpy(Info, Domain.data(), Domain.size());
    const std::int32_t Qtype = 1;
    const std::uint32_t QueryFlag = 0;
    const std::int32_t Ttl = 600;
    const std::int32_t Rcode = 0;
    const std::int32_t Hitnum = 6;
    const std::int32_t Speed = -1;
    const std::int64_t InsertTime = 111;
    const std::int64_t ReplaceTime = 222;
    std::memcpy(Info + 256, &Qtype, sizeof(Qtype));
    std::memcpy(Info + 292, &QueryFlag, sizeof(QueryFlag));
    std::memcpy(Info + 296, &Ttl, sizeof(Ttl));
    std::memcpy(Info + 300, &Rcode, sizeof(Rcode));
    std::memcpy(Info + 304, &Hitnum, sizeof(Hitnum));
    std::memcpy(Info + 308, &Speed, sizeof(Speed));
    std::memcpy(Info + 328, &InsertTime, sizeof(InsertTime));
    std::memcpy(Info + 336, &ReplaceTime, sizeof(ReplaceTime));
    Output.write(Info, sizeof(Info));

    const std::uint8_t Packet[] = {
        0x56, 0x78, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x02, 0x58, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
    };
    const std::int32_t Ref = 1;
    const std::int64_t PacketSize = sizeof(Packet);
    Output.write(reinterpret_cast<const char *>(&Ref), sizeof(Ref));
    Output.write(HeaderPadding, sizeof(HeaderPadding));
    Output.write(reinterpret_cast<const char *>(&PacketSize), sizeof(PacketSize));
    Output.write(reinterpret_cast<const char *>(&DataMagic), sizeof(DataMagic));
    Output.write(HeaderPadding, sizeof(HeaderPadding));
    Output.write(reinterpret_cast<const char *>(Packet), sizeof(Packet));
  }

  const auto BindRows = dnslab::parseCacheDump("bind9", BindPath);
  const auto UnboundRows = dnslab::parseCacheDump("unbound", UnboundPath);
  const auto DnsmasqRows = dnslab::parseCacheDump("dnsmasq", DnsmasqPath);
  const auto SmartdnsRows = dnslab::parseCacheDump("smartdns", SmartdnsPath);
  const auto MaradnsPath = writeTempFile(
      "dnslab_maradns_cache.txt",
      "MARADNS_CACHE_DUMP\n"
      "Fetching \\007example\\003com\\000\\000\\001 from cache\n");
  const auto MaradnsRows = dnslab::parseCacheDump("maradns", MaradnsPath);
  const auto KnotPath = writeTempFile(
      "dnslab_knot_cache.txt",
      "KNOT_RESOLVER_CACHE_DUMP\n"
      "CACHE_ENTRY\texample.com\tA\t_\n");
  const auto KnotRows = dnslab::parseCacheDump("knot-resolver", KnotPath);
  require(!BindRows.empty(), "Bind cache 解析为空");
  require(!UnboundRows.empty(), "Unbound cache 解析为空");
  require(!DnsmasqRows.empty(), "dnsmasq cache 解析为空");
  require(!SmartdnsRows.empty(), "SmartDNS cache 解析为空");
  require(!MaradnsRows.empty(), "MaraDNS cache 解析为空");
  require(!KnotRows.empty(), "Knot cache 解析为空");
  require(DnsmasqRows[0].Resolver == "dnsmasq", "dnsmasq resolver 名不匹配");
  require(DnsmasqRows[0].QName == "example.com", "dnsmasq qname 不匹配");
  require(SmartdnsRows[0].Resolver == "smartdns",
          "smartdns resolver 名不匹配");
  require(SmartdnsRows[0].QName == "example.com", "smartdns qname 不匹配");
  require(MaradnsRows[0].Resolver == "maradns",
          "maradns resolver 名不匹配");
  require(MaradnsRows[0].QName == "example.com", "maradns qname 不匹配");
  require(KnotRows[0].Resolver == "knot-resolver",
          "knot resolver 名不匹配");
  require(KnotRows[0].QName == "example.com", "knot qname 不匹配");

  const auto Diff =
      dnslab::buildCacheDiff("sample-1", BindRows, {}, UnboundRows, UnboundRows, true);
  require(Diff.Bind9.HasCacheDiff, "Bind9 cache diff 未命中");
  require(!Diff.Unbound.HasCacheDiff, "Unbound cache diff 误报");
  require(Diff.DiffDetected, "pairwise cache diff 应识别为 resolver 差异");

  // F1 回归验证: 三种成对场景
  // 1. 相同 RR: bind9 与 unbound 各自添加完全相同的 RR (仅 resolver/view/section 不同)
  std::vector<dnslab::CacheRecord> PairBindSame = {
      {"bind9", "_default", "example.com.", "IN", "A", "answer", "positive", "300", "192.0.2.1", ""},
  };
  std::vector<dnslab::CacheRecord> PairUnboundSame = {
      {"unbound", "", "example.com.", "IN", "A", "", "positive", "300", "192.0.2.1", ""},
  };
  const auto DiffSame = dnslab::buildCacheDiff(
      "pair-same", {}, PairBindSame, {}, PairUnboundSame, true);
  require(DiffSame.Bind9.HasCacheDiff, "Bind9 自身应有 cache 变更");
  require(DiffSame.Unbound.HasCacheDiff, "Unbound 自身应有 cache 变更");
  require(!DiffSame.DiffDetected, "相同 RR 不应被误报为跨 resolver 差异 (F1)");
  require(DiffSame.ResolverDifferences.empty(), "相同 RR 不应产生 ResolverDifferences");

  // 2. 仅 TTL 不同: TTL 差异不应升级为语义差异
  std::vector<dnslab::CacheRecord> PairUnboundTTLDiff = {
      {"unbound", "", "example.com.", "IN", "A", "", "positive", "60", "192.0.2.1", ""},
  };
  const auto DiffTTL = dnslab::buildCacheDiff(
      "pair-ttl", {}, PairBindSame, {}, PairUnboundTTLDiff, true);
  require(!DiffTTL.DiffDetected, "仅 TTL 不同不应判定为跨 resolver 差异");

  // 3. 真实 RDATA 不同: 192.0.2.1 vs 192.0.2.2 必须判定为差异
  std::vector<dnslab::CacheRecord> PairUnboundRDataDiff = {
      {"unbound", "", "example.com.", "IN", "A", "", "positive", "300", "192.0.2.2", ""},
  };
  const auto DiffRData = dnslab::buildCacheDiff(
      "pair-rdata", {}, PairBindSame, {}, PairUnboundRDataDiff, true);
  require(DiffRData.DiffDetected, "真实 RDATA 不同必须识别为差异");
  require(!DiffRData.ResolverDifferences.empty(), "真实 RDATA 不同必须记录 ResolverDifferences");

  std::map<std::string, std::vector<dnslab::CacheRecord>> MultiBefore = {
      {"bind9", BindRows},
      {"unbound", UnboundRows},
      {"dnsmasq", DnsmasqRows},
  };
  std::map<std::string, std::vector<dnslab::CacheRecord>> MultiAfter = {
      {"bind9", BindRows},
      {"unbound", UnboundRows},
      {"dnsmasq", {}},
  };
  const auto MultiDiff = dnslab::buildCacheDiff("sample-2", MultiBefore, MultiAfter,
                                                true, "unbound");
  require(MultiDiff.ExecutedResolvers.size() == 3U,
          "multi resolver cache diff 未保留全部 resolver");
  require(MultiDiff.DiffDetected, "multi resolver cache diff 未标记差异");
  require(!MultiDiff.ResolverDifferences.empty(),
          "multi resolver cache diff 未记录 pair 差异");

  dnslab::json::Value::Object Oracle;
  Oracle["bind9.stderr_parse_status"] = "ok";
  Oracle["unbound.stderr_parse_status"] = "ok";
  Oracle["bind9.parse_ok"] = true;
  Oracle["unbound.parse_ok"] = true;
  Oracle["bind9.resolver_fetch_started"] = true;
  Oracle["unbound.resolver_fetch_started"] = true;
  Oracle["bind9.response_accepted"] = true;
  Oracle["unbound.response_accepted"] = false;
  Oracle["bind9.second_query_hit"] = false;
  Oracle["unbound.second_query_hit"] = true;
  Oracle["bind9.cache_entry_created"] = true;
  Oracle["unbound.cache_entry_created"] = false;
  Oracle["bind9.timeout"] = false;
  Oracle["unbound.timeout"] = false;

  dnslab::StateFingerprint Fingerprint;
  Fingerprint.SchemaVersion = dnslab::kSchemaVersion;
  Fingerprint.GeneratedAt = dnslab::utcTimestampNow();
  Fingerprint.SampleId = "sample-1";

  const auto Triage =
      dnslab::buildTriageRecord("sample-1", Oracle, Diff, Fingerprint, std::nullopt);
  require(Triage.Status == "completed_oracle_diff", "Triage status 不匹配");
  require(Triage.AnalysisState == "included",
          "Triage analysis_state 不匹配");
  require(Triage.OracleAuditCandidate, "Triage 未标为 oracle audit candidate");

  std::map<std::string, dnslab::json::Value::Object> OracleByResolver;
  OracleByResolver["bind9"] = {
      {"bind9.stderr_parse_status", "ok"},
      {"bind9.parse_ok", true},
      {"bind9.resolver_fetch_started", true},
      {"bind9.response_accepted", true},
      {"bind9.second_query_hit", false},
      {"bind9.cache_entry_created", true},
      {"bind9.timeout", false},
  };
  OracleByResolver["unbound"] = {
      {"unbound.stderr_parse_status", "ok"},
      {"unbound.parse_ok", true},
      {"unbound.resolver_fetch_started", true},
      {"unbound.response_accepted", true},
      {"unbound.second_query_hit", false},
      {"unbound.cache_entry_created", true},
      {"unbound.timeout", false},
  };
  OracleByResolver["dnsmasq"] = {
      {"dnsmasq.stderr_parse_status", "ok"},
      {"dnsmasq.parse_ok", true},
      {"dnsmasq.resolver_fetch_started", true},
      {"dnsmasq.response_accepted", false},
      {"dnsmasq.second_query_hit", true},
      {"dnsmasq.cache_entry_created", false},
      {"dnsmasq.timeout", false},
  };
  const auto MultiTriage = dnslab::buildTriageRecord(
      "sample-2", OracleByResolver, MultiDiff, Fingerprint, std::nullopt);
  require(MultiTriage.DiffDetected, "multi resolver triage 未标记差异");
  require(MultiTriage.ExecutedResolvers.size() == 3U,
          "multi resolver triage 未保留 resolver 列表");
  require(!MultiTriage.ResolverDifferences.empty(),
          "multi resolver triage 未记录 resolver_diffs");

  dnslab::FailureEvidence MissingExecutable;
  MissingExecutable.Kind = "replay_error";
  MissingExecutable.Reason = "missing_executable";
  MissingExecutable.ExitCode = 3;
  MissingExecutable.Stage = "unbound.preflight";
  MissingExecutable.Resolver = "unbound";
  MissingExecutable.ProcessStarted = false;
  const auto FailedTriage = dnslab::buildTriageRecord(
      "sample-2", OracleByResolver, MultiDiff, Fingerprint,
      MissingExecutable);
  require(FailedTriage.Status == "failed_replay",
          "显式 replay failure 未优先生成 failed_replay");
  require(FailedTriage.DiffClass == "replay_incomplete",
          "replay failure diff_class 不匹配");
  require(FailedTriage.AnalysisState == "excluded",
          "missing executable analysis_state 不匹配");
  require(FailedTriage.FailureBucketPrimary == "infra_artifact_failure",
          "missing executable primary taxonomy 不匹配");
  require(FailedTriage.FailureBucketDetail == "replay_missing_executable",
          "missing executable detail taxonomy 不匹配");
  require(FailedTriage.ExcludeReason ==
              std::optional<std::string>("infra_failure"),
          "missing executable exclude_reason 不匹配");
  require(std::find(FailedTriage.FilterLabels.begin(),
                    FailedTriage.FilterLabels.end(), "oracle_missing") !=
              FailedTriage.FilterLabels.end(),
          "replay failure 缺少 oracle_missing label");
  require(std::find(FailedTriage.FilterLabels.begin(),
                    FailedTriage.FilterLabels.end(),
                    "replay_missing_executable") !=
              FailedTriage.FilterLabels.end(),
          "replay failure 缺少 reason label");

  auto TimeoutFailure = MissingExecutable;
  TimeoutFailure.Reason = "timeout";
  TimeoutFailure.ExitCode = 4;
  TimeoutFailure.ProcessStarted = true;
  const auto TimeoutTriage = dnslab::buildTriageRecord(
      "sample-2", OracleByResolver, MultiDiff, Fingerprint, TimeoutFailure);
  require(TimeoutTriage.AnalysisState == "unknown",
          "timeout analysis_state 不匹配");
  require(TimeoutTriage.FailureBucketPrimary == "target_runtime_failure",
          "timeout primary taxonomy 不匹配");
  require(TimeoutTriage.FailureBucketDetail == "replay_timeout",
          "timeout detail taxonomy 不匹配");
  require(TimeoutTriage.SemanticOutcome == "runtime_or_parse_failure",
          "timeout semantic_outcome 不匹配");

  const std::map<std::string, dnslab::json::Value::Object> MissingOracle;
  const auto LegacyTriage = dnslab::buildTriageRecord(
      "legacy-sample", MissingOracle, MultiDiff, Fingerprint, std::nullopt);
  require(LegacyTriage.Status == "failed_replay",
          "缺失 oracle 未生成 failed_replay");
  require(LegacyTriage.DiffClass == "replay_incomplete",
          "缺失 oracle diff_class 不匹配");
  require(std::find(LegacyTriage.FilterLabels.begin(),
                    LegacyTriage.FilterLabels.end(), "oracle_missing") !=
              LegacyTriage.FilterLabels.end(),
          "缺失 oracle 未生成 oracle_missing label");
  require(std::find(LegacyTriage.FilterLabels.begin(),
                    LegacyTriage.FilterLabels.end(),
                    "replay_subprocess_failed") ==
              LegacyTriage.FilterLabels.end(),
          "无 failure evidence 时不应生成 replay reason label");

  std::filesystem::remove(BindPath);
  std::filesystem::remove(UnboundPath);
  std::filesystem::remove(DnsmasqPath);
  std::filesystem::remove(SmartdnsPath);
  std::filesystem::remove(MaradnsPath);
  std::filesystem::remove(KnotPath);
  return 0;
}
