#include "dnslab_core/cache_analysis.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace {

std::filesystem::path writeTempFile(const std::string &Name,
                                    const std::string &Content) {
  const auto Path = std::filesystem::temp_directory_path() / Name;
  std::ofstream Output(Path);
  Output << Content;
  return Path;
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
  assert(!BindRows.empty());
  assert(!UnboundRows.empty());
  assert(!DnsmasqRows.empty());
  assert(!SmartdnsRows.empty());
  assert(!MaradnsRows.empty());
  assert(DnsmasqRows[0].Resolver == "dnsmasq");
  assert(DnsmasqRows[0].QName == "example.com");
  assert(SmartdnsRows[0].Resolver == "smartdns");
  assert(SmartdnsRows[0].QName == "example.com");
  assert(MaradnsRows[0].Resolver == "maradns");
  assert(MaradnsRows[0].QName == "example.com");

  const auto Diff =
      dnslab::buildCacheDiff("sample-1", BindRows, {}, UnboundRows, UnboundRows, true);
  assert(Diff.Bind9.HasCacheDiff);
  assert(!Diff.Unbound.HasCacheDiff);

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
  assert(Triage.Status == "completed_oracle_diff");
  assert(Triage.AnalysisState == "included");
  assert(Triage.OracleAuditCandidate);

  std::filesystem::remove(BindPath);
  std::filesystem::remove(UnboundPath);
  std::filesystem::remove(DnsmasqPath);
  std::filesystem::remove(SmartdnsPath);
  std::filesystem::remove(MaradnsPath);
  return 0;
}
