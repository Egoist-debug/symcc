#include "dnslab_core/concrete_adapters.hpp"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace {

std::filesystem::path makeTempDir(const std::string &Name) {
  const auto Dir = std::filesystem::temp_directory_path() / Name;
  std::filesystem::remove_all(Dir);
  std::filesystem::create_directories(Dir);
  return Dir;
}

void writeExecutable(const std::filesystem::path &Path, const std::string &Body) {
  std::filesystem::create_directories(Path.parent_path());
  std::ofstream Output(Path);
  Output << Body;
  Output.close();
  std::filesystem::permissions(
      Path,
      std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write |
          std::filesystem::perms::group_exec | std::filesystem::perms::group_read,
      std::filesystem::perm_options::add);
}

void require(bool Condition, const char *Message) {
  if (Condition) {
    return;
  }
  std::fprintf(stderr, "%s\n", Message);
  std::abort();
}

} // namespace

#undef assert
#define assert(Expr) require((Expr), #Expr)

int main() {
  const auto Root = makeTempDir("dnslab_concrete_adapter_test");
  const auto Bind9Binary = Root / "bind9-afl" / "bin" / "named" / ".libs" / "named";
  const auto UnboundBinary = Root / "unbound-afl" / ".libs" / "unbound-fuzzme";
  const auto DnsmasqSource = Root / "dnsmasq-source";
  const auto DnsmasqBuild = Root / "dnsmasq-build";
  const auto DnsmasqBinary = DnsmasqBuild / "dnsmasq";
  const auto DnsmasqHarness = Root / "dnsmasq-harness.py";
  const auto SmartdnsSource = Root / "smartdns-source";
  const auto SmartdnsBuild = Root / "smartdns-build";
  const auto SmartdnsHarness = Root / "smartdns-harness.py";
  const auto MaradnsSource = Root / "maradns-source";
  const auto MaradnsBuild = Root / "maradns-build";
  const auto MaradnsHarness = Root / "maradns-harness.py";
  const auto KnotBinary = Root / "knot-build" / "daemon" / "kresd";
  const auto KnotHarness = Root / "knot-harness.py";
  const auto Sample = Root / "sample.bin";
  const auto ResponseCorpus = Root / "response_corpus";
  const auto NamedTemplate = Root / "named.conf.in";
  const auto RunRoot = Root / "run";

  std::filesystem::create_directories(ResponseCorpus);
  std::ofstream(Sample) << "DST1";
  std::ofstream(NamedTemplate) << "directory \"__RUNTIME_STATE_DIR__\";\n";

  writeExecutable(
      Bind9Binary,
      "#!/bin/sh\n"
      "printf 'ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 "
      "response_accepted=1 second_query_hit=0 cache_entry_created=1 timeout=0\\n' >&2\n"
      "printf 'bind9-cache\\n' > \"$NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH\"\n");

  writeExecutable(
      UnboundBinary,
      "#!/bin/sh\n"
      "printf 'ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 "
      "response_accepted=1 second_query_hit=1 cache_entry_created=0 timeout=0\\n' >&2\n"
      "printf 'unbound-cache\\n' > \"$UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH\"\n");

  std::filesystem::create_directories(DnsmasqSource);
  {
    std::ofstream Makefile(DnsmasqSource / "Makefile");
    Makefile << "BUILDDIR ?= .\n"
                "all:\n"
                "\tmkdir -p $(BUILDDIR)\n"
                "\tprintf '#!/bin/sh\\nexit 0\\n' > $(BUILDDIR)/dnsmasq\n"
                "\tchmod +x $(BUILDDIR)/dnsmasq\n";
  }
  {
    std::ofstream Harness(DnsmasqHarness);
    Harness << "#!/usr/bin/env python3\n"
               "import argparse\n"
               "from pathlib import Path\n"
               "parser = argparse.ArgumentParser()\n"
               "parser.add_argument('--mode', required=True)\n"
               "parser.add_argument('--cache-dump-path', required=True)\n"
               "parser.add_argument('--dnsmasq-stderr-path', required=True)\n"
               "parser.add_argument('--transcript')\n"
               "parser.add_argument('--dnsmasq-bin')\n"
               "args = parser.parse_args()\n"
               "Path(args.cache_dump_path).write_text('dnsmasq-cache\\n', encoding='utf-8')\n"
               "Path(args.dnsmasq_stderr_path).write_text('dnsmasq-native\\n', encoding='utf-8')\n"
               "print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')\n";
  }
  std::filesystem::permissions(
      DnsmasqHarness,
      std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write |
          std::filesystem::perms::group_exec | std::filesystem::perms::group_read,
      std::filesystem::perm_options::add);
  std::filesystem::create_directories(SmartdnsSource / "src");
  {
    std::ofstream Makefile(SmartdnsSource / "src" / "Makefile");
    Makefile << "all:\n"
                "\tprintf '#!/bin/sh\\nexit 0\\n' > smartdns\n"
                "\tchmod +x smartdns\n";
  }
  {
    std::ofstream Harness(SmartdnsHarness);
    Harness << "#!/usr/bin/env python3\n"
               "import argparse\n"
               "from pathlib import Path\n"
               "p=argparse.ArgumentParser();\n"
               "p.add_argument('--mode', required=True);\n"
               "p.add_argument('--cache-dump-path', required=True);\n"
               "p.add_argument('--smartdns-log-path', required=True);\n"
               "p.add_argument('--transcript');\n"
               "p.add_argument('--smartdns-bin');\n"
               "a=p.parse_args();\n"
               "Path(a.cache_dump_path).write_bytes(b'X' * 64)\n"
               "Path(a.smartdns_log_path).write_text('smartdns-native\\n', encoding='utf-8')\n"
               "print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')\n";
  }
  std::filesystem::permissions(
      SmartdnsHarness,
      std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write |
          std::filesystem::perms::group_exec | std::filesystem::perms::group_read,
      std::filesystem::perm_options::add);
  std::filesystem::create_directories(MaradnsSource / "deadwood-github" / "src");
  {
    std::ofstream Makefile(MaradnsSource / "deadwood-github" / "src" / "Makefile");
    Makefile << "version.h:\n"
                "\tprintf '/* version */\\n' > version.h\n"
                "all:\n"
                "\tprintf '#!/bin/sh\\nexit 0\\n' > Deadwood\n"
                "\tchmod +x Deadwood\n";
  }
  {
    std::ofstream Harness(MaradnsHarness);
    Harness << "#!/usr/bin/env python3\n"
               "import argparse\n"
               "from pathlib import Path\n"
               "p=argparse.ArgumentParser();\n"
               "p.add_argument('--mode', required=True);\n"
               "p.add_argument('--cache-dump-path', required=True);\n"
               "p.add_argument('--maradns-log-path', required=True);\n"
               "p.add_argument('--transcript');\n"
               "p.add_argument('--deadwood-bin');\n"
               "a=p.parse_args();\n"
               "Path(a.cache_dump_path).write_text('MARADNS_CACHE_DUMP\\nCACHE_ENTRY\\texample.com\\tA\\t_\\n', encoding='utf-8')\n"
               "Path(a.maradns_log_path).write_text('maradns-native\\n', encoding='utf-8')\n"
               "print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')\n";
  }
  std::filesystem::permissions(
      MaradnsHarness,
      std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write |
          std::filesystem::perms::group_exec | std::filesystem::perms::group_read,
      std::filesystem::perm_options::add);
  writeExecutable(KnotBinary, "#!/bin/sh\nexit 0\n");
  {
    std::ofstream Harness(KnotHarness);
    Harness << "#!/usr/bin/env python3\n"
               "import argparse\n"
               "from pathlib import Path\n"
               "p=argparse.ArgumentParser();\n"
               "p.add_argument('--kresd-bin', required=True);\n"
               "p.add_argument('--mode', required=True);\n"
               "p.add_argument('--cache-dump-path', required=True);\n"
               "p.add_argument('--kresd-log-path', required=True);\n"
               "p.add_argument('--transcript');\n"
               "a=p.parse_args();\n"
               "Path(a.cache_dump_path).write_text('KNOT_RESOLVER_CACHE_DUMP\\nCACHE_ENTRY\\texample.com\\tA\\t_\\n', encoding='utf-8')\n"
               "Path(a.kresd_log_path).write_text('knot-native\\n', encoding='utf-8')\n"
               "print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')\n";
  }
  std::filesystem::permissions(
      KnotHarness,
      std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write |
          std::filesystem::perms::group_exec | std::filesystem::perms::group_read,
      std::filesystem::perm_options::add);

  dnslab::Bind9ResolverAdapter Bind9(dnslab::Bind9AdapterConfig{
      Root, Root / "unused.sh", NamedTemplate, ResponseCorpus,
      "127.0.0.1:55300", "127.0.0.1:55301", 50, 5, std::nullopt, Bind9Binary});

  dnslab::UnboundResolverAdapter Unbound(dnslab::UnboundAdapterConfig{
      Root, ResponseCorpus, 5, std::nullopt, UnboundBinary});
  dnslab::DnsmasqResolverAdapter Dnsmasq(dnslab::DnsmasqAdapterConfig{
      Root, 2, DnsmasqHarness, DnsmasqSource, DnsmasqBinary});
  dnslab::SmartdnsResolverAdapter Smartdns(dnslab::SmartdnsAdapterConfig{
      Root, 2, SmartdnsHarness, SmartdnsSource, std::nullopt});
  dnslab::MaradnsResolverAdapter Maradns(dnslab::MaradnsAdapterConfig{
      Root, 2, MaradnsHarness, MaradnsSource, std::nullopt});
  dnslab::KnotResolverAdapter Knot(dnslab::KnotResolverAdapterConfig{
      Root, KnotHarness, std::nullopt, KnotBinary});

  const auto Bind9Before = RunRoot / "bind9.before.cache.txt";
  const auto Bind9Dump = Bind9.dumpCache(RunRoot, Bind9Before);
  assert(Bind9Dump.ExitCode == 0);
  assert(std::filesystem::exists(Bind9Before));

  const auto UnboundBefore = RunRoot / "unbound.before.cache.txt";
  const auto UnboundDump = Unbound.dumpCache(RunRoot, UnboundBefore);
  assert(UnboundDump.ExitCode == 0);
  assert(std::filesystem::exists(UnboundBefore));

  dnslab::RunSampleRequest Request{Root, Root, RunRoot, Sample, "sample-1", {}};
  const auto Bind9Run = Bind9.runSample(Request);
  assert(Bind9Run.ExitCode == 0);
  assert(std::filesystem::exists(RunRoot / "bind9.after.cache.txt"));

  const auto UnboundRun = Unbound.runSample(Request);
  assert(UnboundRun.ExitCode == 0);
  assert(std::filesystem::exists(RunRoot / "unbound.after.cache.txt"));

  const auto Bind9Oracle = Bind9.parseOracle(RunRoot / "bind9.stderr");
  assert(Bind9Oracle.ParseOk);
  const auto UnboundOracle = Unbound.parseOracle(RunRoot / "unbound.stderr");
  assert(UnboundOracle.ParseOk);

  const auto DnsmasqBuildResult = Dnsmasq.build(DnsmasqSource, DnsmasqBuild);
  assert(DnsmasqBuildResult.ExitCode == 0);
  assert(std::filesystem::exists(DnsmasqBinary));

  dnslab::RunSampleRequest DnsmasqRequest{
      Root, DnsmasqBuild, RunRoot, Sample, "sample-1", {}};
  const auto DnsmasqRun = Dnsmasq.runSample(DnsmasqRequest);
  assert(DnsmasqRun.ExitCode == 0);
  assert(std::filesystem::exists(RunRoot / "dnsmasq.after.cache.txt"));
  const auto DnsmasqOracle = Dnsmasq.parseOracle(RunRoot / "dnsmasq.stderr");
  assert(DnsmasqOracle.ParseOk);

  const auto DnsmasqBefore = RunRoot / "dnsmasq.before.cache.txt";
  const auto DnsmasqDump = Dnsmasq.dumpCache(RunRoot, DnsmasqBefore);
  assert(DnsmasqDump.ExitCode == 0);
  assert(std::filesystem::exists(DnsmasqBefore));

  const auto SmartdnsBuildResult = Smartdns.build(SmartdnsSource, SmartdnsBuild);
  assert(SmartdnsBuildResult.ExitCode == 0);
  assert(std::filesystem::exists(SmartdnsBuild / "smartdns-build" / "src" / "smartdns"));
  ::setenv("DNSLAB_SMARTDNS_BUILD_ROOT", SmartdnsBuild.c_str(), 1);

  dnslab::RunSampleRequest SmartdnsRequest{
      Root, SmartdnsBuild, RunRoot, Sample, "sample-1", {}};
  const auto SmartdnsRun = Smartdns.runSample(SmartdnsRequest);
  assert(SmartdnsRun.ExitCode == 0);
  assert(std::filesystem::exists(RunRoot / "smartdns.after.cache.txt"));
  assert(std::filesystem::exists(RunRoot / "smartdns.native.log"));
  const auto SmartdnsOracle = Smartdns.parseOracle(RunRoot / "smartdns.stderr");
  assert(SmartdnsOracle.ParseOk);

  const auto SmartdnsBefore = RunRoot / "smartdns.before.cache.txt";
  const auto SmartdnsDump = Smartdns.dumpCache(RunRoot, SmartdnsBefore);
  assert(SmartdnsDump.ExitCode == 0);
  assert(std::filesystem::exists(SmartdnsBefore));
  assert(std::filesystem::exists(RunRoot / "smartdns.native.log"));

  const auto MaradnsBuildResult = Maradns.build(MaradnsSource, MaradnsBuild);
  assert(MaradnsBuildResult.ExitCode == 0);
  assert(std::filesystem::exists(MaradnsBuild / "deadwood-build" / "deadwood-github" / "src" / "Deadwood"));
  ::setenv("DNSLAB_MARADNS_BUILD_ROOT", MaradnsBuild.c_str(), 1);
  dnslab::RunSampleRequest MaradnsRequest{
      Root, MaradnsBuild, RunRoot, Sample, "sample-1", {}};
  const auto MaradnsRun = Maradns.runSample(MaradnsRequest);
  assert(MaradnsRun.ExitCode == 0);
  assert(std::filesystem::exists(RunRoot / "maradns.after.cache.txt"));
  assert(std::filesystem::exists(RunRoot / "maradns.native.log"));
  const auto MaradnsOracle = Maradns.parseOracle(RunRoot / "maradns.stderr");
  assert(MaradnsOracle.ParseOk);
  const auto MaradnsBefore = RunRoot / "maradns.before.cache.txt";
  const auto MaradnsDump = Maradns.dumpCache(RunRoot, MaradnsBefore);
  assert(MaradnsDump.ExitCode == 0);
  assert(std::filesystem::exists(MaradnsBefore));
  assert(std::filesystem::exists(RunRoot / "maradns.native.log"));

  const auto KnotBefore = RunRoot / "knot-resolver.before.cache.txt";
  const auto KnotDump = Knot.dumpCache(RunRoot, KnotBefore);
  assert(KnotDump.ExitCode == 0);
  assert(std::filesystem::exists(KnotBefore));
  dnslab::RunSampleRequest KnotRequest{
      Root, Root, RunRoot, Sample, "sample-1", {}};
  const auto KnotRun = Knot.runSample(KnotRequest);
  assert(KnotRun.ExitCode == 0);
  assert(std::filesystem::exists(RunRoot / "knot-resolver.after.cache.txt"));
  const auto KnotOracle = Knot.parseOracle(RunRoot / "knot-resolver.stderr");
  assert(KnotOracle.ParseOk);

  const auto Registry = dnslab::makeDefaultResolverRegistry(Root);
  const auto Names = Registry.names();
  assert(Names.size() == 6U);
  assert(std::find(Names.begin(), Names.end(), "bind9") != Names.end());
  assert(std::find(Names.begin(), Names.end(), "unbound") != Names.end());
  assert(std::find(Names.begin(), Names.end(), "maradns") != Names.end());
  assert(std::find(Names.begin(), Names.end(), "dnsmasq") != Names.end());
  assert(std::find(Names.begin(), Names.end(), "smartdns") != Names.end());
  assert(std::find(Names.begin(), Names.end(), "knot-resolver") != Names.end());

  std::filesystem::remove_all(Root);
  return 0;
}
