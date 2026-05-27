#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

void require(bool Condition, const std::string &Message) {
  if (Condition) {
    return;
  }
  std::fprintf(stderr, "%s\n", Message.c_str());
  std::abort();
}

std::filesystem::path makeTempDir(const std::string &Name) {
  const auto Dir = std::filesystem::temp_directory_path() / Name;
  std::filesystem::remove_all(Dir);
  std::filesystem::create_directories(Dir);
  return Dir;
}

void writeTextFile(const std::filesystem::path &Path, const std::string &Content) {
  std::filesystem::create_directories(Path.parent_path());
  std::ofstream Output(Path);
  Output << Content;
}

void writeExecutable(const std::filesystem::path &Path, const std::string &Body) {
  writeTextFile(Path, Body);
  std::filesystem::permissions(
      Path,
      std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write |
          std::filesystem::perms::group_exec | std::filesystem::perms::group_read,
      std::filesystem::perm_options::add);
}

std::string readTextFile(const std::filesystem::path &Path) {
  std::ifstream Input(Path);
  std::ostringstream Buffer;
  Buffer << Input.rdbuf();
  return Buffer.str();
}

std::string quote(const std::filesystem::path &Path) {
  return "'" + Path.string() + "'";
}

std::filesystem::path firstCaseStudy(const std::filesystem::path &CaseStudyDir) {
  for (const auto &Entry : std::filesystem::directory_iterator(CaseStudyDir)) {
    if (Entry.is_regular_file() && Entry.path().extension() == ".md") {
      return Entry.path();
    }
  }
  return {};
}

void writeDst1Sample(const std::filesystem::path &Path) {
  const std::vector<std::uint8_t> Query = {
      0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
      'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
      0x00, 0x00, 0x01, 0x00, 0x01,
  };
  const std::vector<std::uint8_t> Response = {
      0x56, 0x78, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
      'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
      0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00,
      0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00,
      0x04, 0x01, 0x02, 0x03, 0x04,
  };
  const std::vector<std::uint8_t> PostCheck = Query;

  std::vector<std::uint8_t> Wire = {'D', 'S', 'T', '1', 0x01, 0x02};
  const auto QuerySize = static_cast<std::uint16_t>(Query.size());
  const auto ResponseSize = static_cast<std::uint16_t>(Response.size());
  Wire.push_back(static_cast<std::uint8_t>(QuerySize & 0xFFU));
  Wire.push_back(static_cast<std::uint8_t>((QuerySize >> 8) & 0xFFU));
  Wire.push_back(static_cast<std::uint8_t>(ResponseSize & 0xFFU));
  Wire.push_back(static_cast<std::uint8_t>((ResponseSize >> 8) & 0xFFU));
  Wire.insert(Wire.end(), Query.begin(), Query.end());
  Wire.insert(Wire.end(), Response.begin(), Response.end());
  Wire.insert(Wire.end(), PostCheck.begin(), PostCheck.end());

  std::filesystem::create_directories(Path.parent_path());
  std::ofstream Output(Path, std::ios::binary);
  Output.write(reinterpret_cast<const char *>(Wire.data()),
               static_cast<std::streamsize>(Wire.size()));
}

} // namespace

int main() {
  const auto Root = makeTempDir("dnslab_batch_secondary_test");
  const auto BindBuildRoot = Root / "bind-build";
  const auto BindBinary =
      BindBuildRoot / "bind9-afl" / "bin" / "named" / ".libs" / "named";
  const auto KnotBuildRoot = Root / "knot-build";
  const auto KnotBinary = KnotBuildRoot / "knot-build" / "daemon" / "kresd";
  const auto KnotHarness = Root / "knot-harness.py";
  const auto ResponseCorpusDir = Root / "response-corpus";
  const auto SampleDir = Root / "samples";
  const auto RunRoot = Root / "run";
  const auto StdoutPath = Root / "batch.stdout.json";
  const auto ProjectRoot = std::filesystem::current_path();

  writeExecutable(
      BindBinary,
      "#!/bin/sh\n"
      "printf 'ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 "
      "response_accepted=1 second_query_hit=0 cache_entry_created=1 timeout=0\\n' >&2\n"
      "printf 'bind9-after\\n' > \"$NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH\"\n");
  writeExecutable(KnotBinary, "#!/bin/sh\nexit 0\n");
  writeTextFile(
      KnotHarness,
      "#!/usr/bin/env python3\n"
      "import argparse\n"
      "from pathlib import Path\n"
      "p=argparse.ArgumentParser()\n"
      "p.add_argument('--kresd-bin', required=True)\n"
      "p.add_argument('--mode', required=True)\n"
      "p.add_argument('--cache-dump-path', required=True)\n"
      "p.add_argument('--kresd-log-path', required=True)\n"
      "p.add_argument('--transcript')\n"
      "a=p.parse_args()\n"
      "cache_path = Path(a.cache_dump_path)\n"
      "cache_path.parent.mkdir(parents=True, exist_ok=True)\n"
      "if a.mode == 'run':\n"
      "    cache_path.write_text('KNOT_RESOLVER_CACHE_DUMP\\nCACHE_ENTRY\\texample.com\\tA\\t_\\n', encoding='utf-8')\n"
      "    print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')\n"
      "else:\n"
      "    cache_path.write_text('KNOT_RESOLVER_CACHE_DUMP\\n', encoding='utf-8')\n"
      "    print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=0 response_accepted=0 second_query_hit=0 cache_entry_created=0 timeout=0')\n"
      "Path(a.kresd_log_path).write_text('knot-native\\n', encoding='utf-8')\n");
  std::filesystem::permissions(
      KnotHarness,
      std::filesystem::perms::owner_exec | std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write |
          std::filesystem::perms::group_exec | std::filesystem::perms::group_read,
      std::filesystem::perm_options::add);

  writeDst1Sample(SampleDir / "sample-1.dst1");
  std::filesystem::create_directories(ResponseCorpusDir);

  ::setenv("KNOT_RESOLVER_HARNESS_SCRIPT", KnotHarness.c_str(), 1);
  ::setenv("RESPONSE_CORPUS_DIR", ResponseCorpusDir.c_str(), 1);
  const std::string Command =
      "./build/linux/x86_64/release/dnslabctl batch-sync-replay --sample-dir " +
      quote(SampleDir) + " --run-root " + quote(RunRoot) +
      " --bind9-build-root " + quote(BindBuildRoot) +
      " --secondary-resolver knot-resolver --secondary-build-root " +
      quote(KnotBuildRoot) + " --resolvers bind9,knot-resolver > " +
      quote(StdoutPath);
  const int RawCode = std::system(Command.c_str());
  require(RawCode == 0, "batch-sync-replay 命令执行失败");

  const auto SummaryText = readTextFile(RunRoot / "summary.json");
  const auto OracleAuditText = readTextFile(RunRoot / "oracle_audit.tsv");
  const auto IndexText = readTextFile(RunRoot / "case_studies" / "index.tsv");
  const auto StdoutText = readTextFile(StdoutPath);
  const auto CaseStudyPath = firstCaseStudy(RunRoot / "case_studies");
  require(!CaseStudyPath.empty(), "未生成 case study 文件");
  const auto CaseStudyText = readTextFile(CaseStudyPath);

  require(SummaryText.find(
              "\"compatibility_secondary_resolver\": \"knot-resolver\"") !=
              std::string::npos,
          "summary.json 未记录 compatibility_secondary_resolver");
  require(SummaryText.find("\"executed_resolvers\": [") != std::string::npos,
          "summary.json 未记录 executed_resolvers");
  require(StdoutText.find("\"sample_count\": 1") != std::string::npos,
          "stdout 未输出正确 sample_count");
  require(OracleAuditText.find("executed_resolvers\tskipped_resolvers_json\t"
                               "diff_detected\tresolver_diffs_json") !=
              std::string::npos,
          "oracle_audit.tsv 未切到多 resolver 表头");
  require(OracleAuditText.find("knot-resolver.response_accepted") ==
              std::string::npos,
          "oracle_audit.tsv 仍残留旧 secondary 列");
  require(IndexText.find("\texecuted_resolvers\tdiff_detected\tresolver_diffs_json") !=
              std::string::npos,
          "case_studies/index.tsv 未切到多 resolver 表头");
  require(IndexText.find("--resolvers bind9,knot-resolver") !=
              std::string::npos,
          "case_studies/index.tsv 未写入多 resolver replay 命令");
  require(CaseStudyText.find("- executed_resolvers: bind9,knot-resolver") !=
              std::string::npos,
          "case study 未写入 executed_resolvers");
  require(CaseStudyText.find("- resolver_diffs_json: ") !=
              std::string::npos,
          "case study 未写入 resolver_diffs_json");
  require(CaseStudyText.find("- knot-resolver_before_cache: ") !=
              std::string::npos,
          "case study 未写入 knot-resolver cache 标签");
  require(CaseStudyText.find("- knot-resolver_logs:") != std::string::npos,
          "case study 未写入 knot-resolver 日志标签");

  std::filesystem::remove_all(Root);
  (void)ProjectRoot;
  return 0;
}
