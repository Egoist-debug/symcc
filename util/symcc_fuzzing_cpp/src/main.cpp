#include "afl.hpp"
#include "symcc.hpp"
#include "testcase.hpp"
#include "util.hpp"

#include <chrono>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <thread>
#include <optional>
#include <unordered_map>
#include <unordered_set>

using namespace symcc_fuzzing;

static const std::uint64_t kStatsIntervalSec = 60;
static const std::uint64_t kDefaultFrontierReloadSec = 15;
static const std::uint64_t kDefaultFrontierRetryLimit = 1;
static const int kTextManifestPriorityTier = 1;

enum class FrontierSource {
  CoverageFirstOnly,
  TextManifest,
  JsonManifest,
};

static std::string frontier_source_name(FrontierSource source) {
  switch (source) {
    case FrontierSource::CoverageFirstOnly:
      return "coverage-first only";
    case FrontierSource::TextManifest:
      return "text manifest";
    case FrontierSource::JsonManifest:
      return "semantic JSON manifest";
  }
  return "unknown";
}

struct JsonValue {
  enum class Type {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
  };

  Type type = Type::Null;
  bool bool_value = false;
  long long number_value = 0;
  std::string string_value;
  std::vector<JsonValue> array_value;
  std::map<std::string, JsonValue> object_value;
};

class JsonParser {
 public:
  explicit JsonParser(const std::string& input) : input_(input) {}

  JsonValue parse() {
    auto value = parse_value();
    skip_ws();
    if (pos_ != input_.size()) {
      fail("unexpected trailing characters");
    }
    return value;
  }

 private:
  const std::string& input_;
  std::size_t pos_ = 0;

  static void append_utf8(std::string& out, std::uint32_t code_point) {
    if (code_point <= 0x7F) {
      out.push_back(static_cast<char>(code_point));
      return;
    }
    if (code_point <= 0x7FF) {
      out.push_back(static_cast<char>(0xC0U | ((code_point >> 6) & 0x1FU)));
      out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
      return;
    }
    if (code_point <= 0xFFFF) {
      out.push_back(static_cast<char>(0xE0U | ((code_point >> 12) & 0x0FU)));
      out.push_back(static_cast<char>(0x80U | ((code_point >> 6) & 0x3FU)));
      out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
      return;
    }
    out.push_back(static_cast<char>(0xF0U | ((code_point >> 18) & 0x07U)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 12) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 6) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  }

  [[noreturn]] void fail(const std::string& reason) const {
    throw std::runtime_error("semantic frontier JSON parse error at byte " +
                             std::to_string(pos_) + ": " + reason);
  }

  void skip_ws() {
    while (pos_ < input_.size() &&
           std::isspace(static_cast<unsigned char>(input_[pos_]))) {
      ++pos_;
    }
  }

  bool consume_if(char expected) {
    skip_ws();
    if (pos_ < input_.size() && input_[pos_] == expected) {
      ++pos_;
      return true;
    }
    return false;
  }

  void expect(char expected) {
    if (!consume_if(expected)) {
      fail(std::string("expected '") + expected + "'");
    }
  }

  void expect_literal(const std::string& literal) {
    skip_ws();
    if (input_.compare(pos_, literal.size(), literal) != 0) {
      fail("expected '" + literal + "'");
    }
    pos_ += literal.size();
  }

  std::string parse_string_literal() {
    skip_ws();
    if (pos_ >= input_.size() || input_[pos_] != '"') {
      fail("expected string");
    }

    ++pos_;
    std::string out;
    while (pos_ < input_.size()) {
      const char c = input_[pos_++];
      if (c == '"') {
        return out;
      }
      if (c != '\\') {
        out.push_back(c);
        continue;
      }

      if (pos_ >= input_.size()) {
        fail("unfinished escape sequence");
      }
      const char escaped = input_[pos_++];
      switch (escaped) {
        case '"':
        case '\\':
        case '/':
          out.push_back(escaped);
          break;
        case 'b':
          out.push_back('\b');
          break;
        case 'f':
          out.push_back('\f');
          break;
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case 'u': {
          if (pos_ + 4 > input_.size()) {
            fail("incomplete unicode escape");
          }
          std::uint32_t code_point = 0;
          for (int i = 0; i < 4; ++i) {
            const char hex = input_[pos_++];
            code_point <<= 4;
            if (hex >= '0' && hex <= '9') {
              code_point |= static_cast<std::uint32_t>(hex - '0');
            } else if (hex >= 'a' && hex <= 'f') {
              code_point |= static_cast<std::uint32_t>(10 + (hex - 'a'));
            } else if (hex >= 'A' && hex <= 'F') {
              code_point |= static_cast<std::uint32_t>(10 + (hex - 'A'));
            } else {
              fail("invalid unicode escape");
            }
          }
          append_utf8(out, code_point);
          break;
        }
        default:
          fail(std::string("unsupported escape sequence: \\") + escaped);
      }
    }
    fail("unterminated string literal");
  }

  JsonValue parse_number() {
    skip_ws();
    const auto start = pos_;
    if (pos_ < input_.size() && input_[pos_] == '-') ++pos_;
    if (pos_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
      fail("invalid number");
    }
    while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
      ++pos_;
    }
    if (pos_ < input_.size() && (input_[pos_] == '.' || input_[pos_] == 'e' || input_[pos_] == 'E')) {
      fail("floating-point numbers are not supported in this manifest");
    }

    JsonValue value;
    value.type = JsonValue::Type::Number;
    try {
      value.number_value = std::stoll(input_.substr(start, pos_ - start));
    } catch (const std::exception&) {
      fail("number is out of range");
    }
    return value;
  }

  JsonValue parse_array() {
    expect('[');
    JsonValue value;
    value.type = JsonValue::Type::Array;
    skip_ws();
    if (consume_if(']')) {
      return value;
    }

    while (true) {
      value.array_value.push_back(parse_value());
      skip_ws();
      if (consume_if(']')) {
        break;
      }
      expect(',');
    }
    return value;
  }

  JsonValue parse_object() {
    expect('{');
    JsonValue value;
    value.type = JsonValue::Type::Object;
    skip_ws();
    if (consume_if('}')) {
      return value;
    }

    while (true) {
      const auto key = parse_string_literal();
      skip_ws();
      expect(':');
      auto inserted = value.object_value.emplace(key, parse_value());
      if (!inserted.second) {
        fail("duplicate object key '" + key + "'");
      }
      skip_ws();
      if (consume_if('}')) {
        break;
      }
      expect(',');
    }
    return value;
  }

  JsonValue parse_value() {
    skip_ws();
    if (pos_ >= input_.size()) {
      fail("unexpected end of input");
    }

    const char c = input_[pos_];
    if (c == '{') return parse_object();
    if (c == '[') return parse_array();
    if (c == '"') {
      JsonValue value;
      value.type = JsonValue::Type::String;
      value.string_value = parse_string_literal();
      return value;
    }
    if (c == 't') {
      expect_literal("true");
      JsonValue value;
      value.type = JsonValue::Type::Bool;
      value.bool_value = true;
      return value;
    }
    if (c == 'f') {
      expect_literal("false");
      JsonValue value;
      value.type = JsonValue::Type::Bool;
      value.bool_value = false;
      return value;
    }
    if (c == 'n') {
      expect_literal("null");
      JsonValue value;
      value.type = JsonValue::Type::Null;
      return value;
    }
    if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
      return parse_number();
    }
    fail(std::string("unexpected character '") + c + "'");
  }
};

static std::string json_type_name(JsonValue::Type type) {
  switch (type) {
    case JsonValue::Type::Null:
      return "null";
    case JsonValue::Type::Bool:
      return "bool";
    case JsonValue::Type::Number:
      return "number";
    case JsonValue::Type::String:
      return "string";
    case JsonValue::Type::Array:
      return "array";
    case JsonValue::Type::Object:
      return "object";
  }
  return "unknown";
}

static const JsonValue& require_json_field(
    const std::map<std::string, JsonValue>& object,
    const std::string& field,
    const std::string& context) {
  const auto it = object.find(field);
  if (it == object.end()) {
    throw std::runtime_error("semantic frontier JSON contract error: missing field '" +
                             field + "' in " + context);
  }
  return it->second;
}

static void require_exact_json_fields(
    const std::map<std::string, JsonValue>& object,
    const std::unordered_set<std::string>& expected_fields,
    const std::string& context) {
  if (object.size() != expected_fields.size()) {
    throw std::runtime_error("semantic frontier JSON contract error: unexpected field count in " +
                             context);
  }
  for (const auto& [key, _] : object) {
    if (expected_fields.find(key) == expected_fields.end()) {
      throw std::runtime_error("semantic frontier JSON contract error: unexpected field '" +
                               key + "' in " + context);
    }
  }
}

static const std::map<std::string, JsonValue>& require_json_object(
    const JsonValue& value,
    const std::string& context) {
  if (value.type != JsonValue::Type::Object) {
    throw std::runtime_error("semantic frontier JSON contract error: " + context +
                             " must be an object, got " + json_type_name(value.type));
  }
  return value.object_value;
}

static const std::vector<JsonValue>& require_json_array(
    const JsonValue& value,
    const std::string& context) {
  if (value.type != JsonValue::Type::Array) {
    throw std::runtime_error("semantic frontier JSON contract error: " + context +
                             " must be an array, got " + json_type_name(value.type));
  }
  return value.array_value;
}

static std::string require_json_string(
    const JsonValue& value,
    const std::string& context) {
  if (value.type != JsonValue::Type::String) {
    throw std::runtime_error("semantic frontier JSON contract error: " + context +
                             " must be a string, got " + json_type_name(value.type));
  }
  return value.string_value;
}

static long long require_json_integer(
    const JsonValue& value,
    const std::string& context) {
  if (value.type != JsonValue::Type::Number) {
    throw std::runtime_error("semantic frontier JSON contract error: " + context +
                             " must be a number, got " + json_type_name(value.type));
  }
  return value.number_value;
}

static bool require_json_bool(
    const JsonValue& value,
    const std::string& context) {
  if (value.type != JsonValue::Type::Bool) {
    throw std::runtime_error("semantic frontier JSON contract error: " + context +
                             " must be a bool, got " + json_type_name(value.type));
  }
  return value.bool_value;
}

using SemanticTierMap = std::unordered_map<std::string, int>;

struct SemanticFrontierSnapshot {
  FrontierSource source = FrontierSource::CoverageFirstOnly;
  SemanticTierMap tiers;
  std::size_t entry_count = 0;
  std::string applied_at;
  std::string manifest_generated_at;
};

struct SemanticFrontierLoadResult {
  bool success = false;
  SemanticFrontierSnapshot snapshot;
  std::string reason;
};

struct SemanticFrontierManager {
  std::optional<std::filesystem::path> json_manifest_path;
  std::optional<std::filesystem::path> text_manifest_path;
  std::uint64_t reload_interval_sec = kDefaultFrontierReloadSec;
  std::uint64_t retry_limit = kDefaultFrontierRetryLimit;
  std::uint64_t last_reload_check_ms = 0;
  std::optional<std::filesystem::file_time_type> json_manifest_mtime;
  std::optional<std::filesystem::file_time_type> text_manifest_mtime;
  SemanticFrontierSnapshot snapshot;
  bool initialized = false;
};

struct CLI {
  std::string fuzzer_name;
  std::filesystem::path output_dir;
  std::string name;
  bool verbose = false;
  bool stdin_is_filename = false;  // -f: stdin 传入文件名而不是数据
  std::vector<std::string> command;
  std::vector<std::string> afl_target;  // AFL 编译的程序，用于 afl-showmap
  std::optional<std::filesystem::path> response_tail_dir;
  std::string response_tail_placeholder = "@@RESP_TAIL@@";
  std::optional<std::string> response_tail_env;
};

static void usage() {
  std::cerr
      << "Usage: symcc_fuzzing_helper -a <fuzzer_name> -o <afl_output_dir> -n <symcc_name> [-v] [-t <afl_prog>] -- <symcc_program> [args...]\n"
      << "\n"
      << "Options:\n"
      << "  -a <name>    Name of the AFL fuzzer instance\n"
      << "  -o <dir>     AFL output directory\n"
      << "  -n <name>    Name for this SymCC instance\n"
      << "  -v           Verbose output\n"
      << "  -t <prog>    AFL-compiled target for afl-showmap (default: same as SymCC target)\n"
      << "  -r <dir>     Optional response-tail corpus directory\n"
      << "  -p <token>   Response-tail placeholder token in target args (default: @@RESP_TAIL@@)\n"
      << "  -e <name>    Optional env var name to pass response-tail sample path\n"
      << "  @@           Use @@ in command for file input mode\n";
}

static CLI parse_args(int argc, char** argv) {
  CLI o;
  int i = 1;
  while (i < argc) {
    std::string a = argv[i];
    if (a == "-a" && i + 1 < argc) {
      o.fuzzer_name = argv[++i];
    } else if (a == "-o" && i + 1 < argc) {
      o.output_dir = argv[++i];
    } else if (a == "-n" && i + 1 < argc) {
      o.name = argv[++i];
    } else if (a == "-v") {
      o.verbose = true;
    } else if (a == "-t" && i + 1 < argc) {
      // AFL target 可以包含参数，用逗号分隔
      std::string target_str = argv[++i];
      std::istringstream iss(target_str);
      std::string token;
      while (std::getline(iss, token, ',')) {
        if (!token.empty()) o.afl_target.push_back(token);
      }
    } else if (a == "-r" && i + 1 < argc) {
      o.response_tail_dir = std::filesystem::path(argv[++i]);
    } else if (a == "-p" && i + 1 < argc) {
      o.response_tail_placeholder = argv[++i];
      if (o.response_tail_placeholder.empty()) {
        usage();
        throw std::runtime_error("-p requires a non-empty placeholder token");
      }
    } else if (a == "-e" && i + 1 < argc) {
      o.response_tail_env = argv[++i];
      if (o.response_tail_env->empty()) {
        usage();
        throw std::runtime_error("-e requires a non-empty environment variable name");
      }
    } else if (a == "-h" || a == "--help") {
      usage();
      std::exit(0);
    } else if (a == "--") {
      ++i;
      break;
    } else if (!a.empty() && a[0] == '-') {
      usage();
      throw std::runtime_error("Unknown option: " + a);
    } else {
      break;
    }
    ++i;
  }

  for (; i < argc; ++i) o.command.push_back(argv[i]);
  if (o.fuzzer_name.empty() || o.output_dir.empty() || o.name.empty() || o.command.empty()) {
    usage();
    throw std::runtime_error("Missing required arguments");
  }
  return o;
}

struct Stats {
  std::uint64_t ok_count = 0;
  std::uint64_t ok_time_ms = 0;
  std::optional<std::uint64_t> solver_time_us;
  std::uint64_t fail_count = 0;
  std::uint64_t fail_time_ms = 0;
  std::uint64_t high_value_candidates = 0;
  std::uint64_t high_value_processed = 0;
  std::uint64_t high_value_new_coverage = 0;
  std::uint64_t high_value_new_interesting = 0;

  void add(const SymCCResult& r) {
    if (r.killed) {
      fail_count += 1;
      fail_time_ms += r.elapsed_ms;
    } else {
      ok_count += 1;
      ok_time_ms += r.elapsed_ms;
      if (r.solver_time_us) {
        solver_time_us = solver_time_us ? (*solver_time_us + *r.solver_time_us) : r.solver_time_us;
      }
    }
  }

  void log(std::ostream& out) const {
    out << "Successful executions: " << ok_count << "\n";
    out << "Time in successful executions: " << ok_time_ms << "ms\n";
    if (ok_count) out << "Avg time per successful execution: " << (ok_time_ms / ok_count) << "ms\n";
    if (solver_time_us) {
      out << "Solver time (successful executions): " << (*solver_time_us / 1000ULL) << "ms\n";
      if (ok_time_ms) {
        const double share = (static_cast<double>(*solver_time_us) / 1000.0) / static_cast<double>(ok_time_ms) * 100.0;
        out << "Solver time share (successful executions): " << share << "% (-> " << (100.0 - share) << "% in execution)\n";
        out << "Avg solver time per successful execution: " << ((*solver_time_us / 1000ULL) / ok_count) << "ms\n";
      }
    }
    out << "Failed executions: " << fail_count << "\n";
    out << "Time spent on failed executions: " << fail_time_ms << "ms\n";
    if (fail_count) out << "Avg time in failed executions: " << (fail_time_ms / fail_count) << "ms\n";
    out << "high_value_candidates: " << high_value_candidates << "\n";
    out << "high_value_processed: " << high_value_processed << "\n";
    out << "high_value_new_coverage: " << high_value_new_coverage << "\n";
    out << "high_value_new_interesting: " << high_value_new_interesting << "\n";
    out << "--------------------------------------------------------------------------------\n";
  }
};

struct State {
  AflMap current_bitmap;
  struct ProcessedTestcaseMetadata {
    std::string canonical_path_key;
    int highest_consumed_tier = 0;
    std::uint64_t retry_count = 0;
    bool processed = false;
  };

  std::unordered_map<std::string, ProcessedTestcaseMetadata> processed_files;
  TestcaseDir queue;
  TestcaseDir hangs;
  TestcaseDir crashes;
  Stats stats;
  std::uint64_t last_stats_ms = 0;
  std::ofstream stats_file;
  std::uint64_t response_tail_pick_count = 0;
};

static State init_state(const std::filesystem::path& symcc_dir) {
  std::error_code ec;
  if (!std::filesystem::create_directory(symcc_dir, ec)) {
    if (ec) throw std::runtime_error("Failed to create SymCC directory: " + symcc_dir.string());
  }
  State s{
      {},
      {},
      TestcaseDir::create(symcc_dir / "queue"),
      TestcaseDir::create(symcc_dir / "hangs"),
      TestcaseDir::create(symcc_dir / "crashes"),
      {},
      now_ms(),
      std::ofstream(symcc_dir / "stats"),
      0};
  if (!s.stats_file) throw std::runtime_error("Failed to open stats file");
  return s;
}

static bool has_response_tail_placeholder(const std::vector<std::string>& command,
                                          const std::string& placeholder) {
  return std::find(command.begin(), command.end(), placeholder) != command.end();
}

static std::optional<std::filesystem::path> pick_response_tail_sample(
    const std::optional<std::filesystem::path>& response_tail_dir,
    std::uint64_t pick_count) {
  if (!response_tail_dir.has_value()) return std::nullopt;

  std::vector<std::filesystem::path> candidates;
  std::error_code ec;
  for (auto it = std::filesystem::directory_iterator(*response_tail_dir, ec);
       !ec && it != std::filesystem::directory_iterator();
       it.increment(ec)) {
    if (!it->is_regular_file()) continue;
    candidates.push_back(it->path());
  }

  if (candidates.empty()) return std::nullopt;

  std::sort(candidates.begin(), candidates.end());
  const auto idx = static_cast<std::size_t>(pick_count % candidates.size());
  return candidates[idx];
}

static std::optional<std::filesystem::file_time_type> read_manifest_mtime(
    const std::optional<std::filesystem::path>& manifest_path) {
  if (!manifest_path.has_value()) return std::nullopt;

  std::error_code ec;
  if (!std::filesystem::exists(*manifest_path, ec) || ec) return std::nullopt;

  const auto mtime = std::filesystem::last_write_time(*manifest_path, ec);
  if (ec) return std::nullopt;
  return mtime;
}

static std::string join_frontier_reasons(const std::vector<std::string>& reasons) {
  std::ostringstream out;
  bool first = true;
  for (const auto& reason : reasons) {
    if (reason.empty()) continue;
    if (!first) out << "; ";
    out << reason;
    first = false;
  }
  return first ? std::string("no additional reason") : out.str();
}

static std::string utc_timestamp_now() {
  const auto now = std::chrono::system_clock::now();
  const auto now_time = std::chrono::system_clock::to_time_t(now);
  std::tm utc_tm{};
#if defined(_WIN32)
  gmtime_s(&utc_tm, &now_time);
#else
  gmtime_r(&now_time, &utc_tm);
#endif

  std::ostringstream out;
  out << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
  return out.str();
}

static std::string format_frontier_snapshot_state(const SemanticFrontierSnapshot& snapshot) {
  std::ostringstream out;
  out << "source=" << frontier_source_name(snapshot.source)
      << ", applied_at=" << (snapshot.applied_at.empty() ? std::string("<unknown>")
                                                           : snapshot.applied_at)
      << ", current_entries=" << snapshot.entry_count;
  if (!snapshot.manifest_generated_at.empty()) {
    out << ", manifest_generated_at=" << snapshot.manifest_generated_at;
  }
  return out.str();
}

static void log_frontier_snapshot_event(const Logger& log,
                                        const std::string& action,
                                        const SemanticFrontierSnapshot& snapshot,
                                        const std::string& reason) {
  log.info(action + " semantic frontier snapshot from " + frontier_source_name(snapshot.source) +
           " (entries=" + std::to_string(snapshot.entry_count) + ", reason=" + reason + ")");
  log.info("Semantic frontier snapshot state: " + format_frontier_snapshot_state(snapshot));
}

static void log_frontier_keep_event(const Logger& log,
                                    const SemanticFrontierSnapshot& snapshot,
                                    const std::string& reason) {
  log.warn("Kept last-known-good semantic frontier snapshot from " +
           frontier_source_name(snapshot.source) + " (entries=" +
           std::to_string(snapshot.entry_count) + ", reason=" + reason + ")");
  log.warn("Semantic frontier snapshot state preserved: " +
           format_frontier_snapshot_state(snapshot));
}

static SemanticFrontierLoadResult load_text_frontier_snapshot(
    const std::optional<std::filesystem::path>& manifest_path) {
  SemanticFrontierLoadResult result;
  if (!manifest_path.has_value()) {
    result.reason = "SYMCC_HIGH_VALUE_MANIFEST not set";
    return result;
  }

  std::ifstream in(*manifest_path);
  if (!in) {
    result.reason = "cannot read text manifest at " + manifest_path->string();
    return result;
  }

  SemanticFrontierSnapshot snapshot;
  snapshot.source = FrontierSource::TextManifest;
  const auto base_dir = std::optional<std::filesystem::path>(manifest_path->parent_path());

  std::string line;
  while (std::getline(in, line)) {
    line = trim(std::move(line));
    if (line.empty() || line[0] == '#') continue;
    const auto key = canonicalize_testcase_path(std::filesystem::path(line), base_dir);
    auto& stored_tier = snapshot.tiers[key];
    stored_tier = std::max(stored_tier, kTextManifestPriorityTier);
  }

  snapshot.entry_count = snapshot.tiers.size();
  snapshot.applied_at = utc_timestamp_now();
  result.success = true;
  result.snapshot = std::move(snapshot);
  result.reason = "loaded text manifest at " + manifest_path->string();
  return result;
}

static SemanticFrontierLoadResult load_json_frontier_snapshot(
    const std::optional<std::filesystem::path>& manifest_path) {
  SemanticFrontierLoadResult result;
  if (!manifest_path.has_value()) {
    result.reason = "SYMCC_SEMANTIC_FRONTIER_MANIFEST not set";
    return result;
  }

  std::ifstream in(*manifest_path);
  if (!in) {
    result.reason = "cannot read semantic JSON manifest at " + manifest_path->string();
    return result;
  }

  std::ostringstream buffer;
  buffer << in.rdbuf();

  try {
    const auto payload = JsonParser(buffer.str()).parse();
    const auto& root_object = require_json_object(payload, "semantic frontier manifest");
    require_exact_json_fields(root_object,
                              {"contract_name", "contract_version", "generated_at", "root", "entries"},
                              "semantic frontier manifest");

    const auto contract_name =
        require_json_string(require_json_field(root_object, "contract_name", "semantic frontier manifest"),
                            "semantic frontier manifest.contract_name");
    if (contract_name != "semantic_frontier_manifest") {
      throw std::runtime_error("semantic frontier JSON contract error: contract_name must be 'semantic_frontier_manifest'");
    }

    const auto contract_version =
        require_json_integer(require_json_field(root_object, "contract_version", "semantic frontier manifest"),
                             "semantic frontier manifest.contract_version");
    if (contract_version != 1) {
      throw std::runtime_error("semantic frontier JSON contract error: contract_version must be 1");
    }

    const auto generated_at = require_json_string(
        require_json_field(root_object, "generated_at", "semantic frontier manifest"),
        "semantic frontier manifest.generated_at");

    const auto manifest_root =
        require_json_string(require_json_field(root_object, "root", "semantic frontier manifest"),
                            "semantic frontier manifest.root");
    const auto entries =
        require_json_array(require_json_field(root_object, "entries", "semantic frontier manifest"),
                           "semantic frontier manifest.entries");

    SemanticFrontierSnapshot snapshot;
    snapshot.source = FrontierSource::JsonManifest;
    const auto default_base_dir = std::optional<std::filesystem::path>(manifest_path->parent_path());
    const auto root_base_dir = manifest_root.empty()
                                   ? default_base_dir
                                   : std::optional<std::filesystem::path>(std::filesystem::path(manifest_root));

    for (std::size_t index = 0; index < entries.size(); ++index) {
      const auto entry_context = "semantic frontier manifest.entries[" + std::to_string(index) + "]";
      const auto& entry = require_json_object(entries[index], entry_context);
      require_exact_json_fields(entry,
                                {"sample_path", "sample_id", "analysis_state", "semantic_outcome",
                                 "oracle_audit_candidate", "needs_manual_review", "priority_tier"},
                                entry_context);

      const auto sample_path =
          require_json_string(require_json_field(entry, "sample_path", entry_context),
                              entry_context + ".sample_path");
      (void)require_json_string(require_json_field(entry, "sample_id", entry_context),
                                entry_context + ".sample_id");
      (void)require_json_string(require_json_field(entry, "analysis_state", entry_context),
                                entry_context + ".analysis_state");
      (void)require_json_string(require_json_field(entry, "semantic_outcome", entry_context),
                                entry_context + ".semantic_outcome");
      (void)require_json_bool(require_json_field(entry, "oracle_audit_candidate", entry_context),
                              entry_context + ".oracle_audit_candidate");
      (void)require_json_bool(require_json_field(entry, "needs_manual_review", entry_context),
                              entry_context + ".needs_manual_review");
      const auto priority_tier =
          require_json_integer(require_json_field(entry, "priority_tier", entry_context),
                               entry_context + ".priority_tier");
      if (priority_tier < 0 || priority_tier > 3) {
        throw std::runtime_error("semantic frontier JSON contract error: priority_tier must be within [0, 3]");
      }

      const auto key = canonicalize_testcase_path(std::filesystem::path(sample_path), root_base_dir);
      auto& stored_tier = snapshot.tiers[key];
      stored_tier = std::max(stored_tier, static_cast<int>(priority_tier));
    }

    snapshot.entry_count = snapshot.tiers.size();
    snapshot.applied_at = utc_timestamp_now();
    snapshot.manifest_generated_at = generated_at;
    result.success = true;
    result.snapshot = std::move(snapshot);
    result.reason = "loaded semantic JSON manifest at " + manifest_path->string();
    return result;
  } catch (const std::exception& e) {
    result.reason = e.what();
    return result;
  }
}

static std::uint64_t load_frontier_reload_sec(const Logger& log) {
  if (const char* reload_env = std::getenv("SYMCC_FRONTIER_RELOAD_SEC")) {
    const auto reload_value = trim(reload_env);
    if (!reload_value.empty()) {
      try {
        return static_cast<std::uint64_t>(std::stoull(reload_value));
      } catch (const std::exception&) {
        log.warn("Invalid SYMCC_FRONTIER_RELOAD_SEC='" + reload_value +
                 "'; fallback to default 15 seconds");
      }
    }
  }
  return kDefaultFrontierReloadSec;
}

static std::uint64_t load_frontier_retry_limit(const Logger& log) {
  if (const char* retry_env = std::getenv("SYMCC_FRONTIER_RETRY_LIMIT")) {
    const auto retry_value = trim(retry_env);
    if (!retry_value.empty()) {
      try {
        return static_cast<std::uint64_t>(std::stoull(retry_value));
      } catch (const std::exception&) {
        log.warn("Invalid SYMCC_FRONTIER_RETRY_LIMIT='" + retry_value +
                 "'; fallback to default 1");
      }
    }
  }
  return kDefaultFrontierRetryLimit;
}

static int semantic_tier_for_path(const SemanticTierMap& semantic_tiers,
                                  const std::string& canonical_path_key) {
  const auto it = semantic_tiers.find(canonical_path_key);
  return it == semantic_tiers.end() ? 0 : it->second;
}

static bool should_allow_semantic_revisit(const State::ProcessedTestcaseMetadata& metadata,
                                          int semantic_tier,
                                          std::uint64_t retry_limit) {
  return metadata.processed && semantic_tier > metadata.highest_consumed_tier &&
         metadata.retry_count < retry_limit;
}

static std::unordered_set<std::string> build_effective_seen_set(
    const State& state,
    const SemanticFrontierSnapshot& snapshot,
    std::uint64_t retry_limit) {
  std::unordered_set<std::string> effective_seen;
  effective_seen.reserve(state.processed_files.size());

  for (const auto& [canonical_path_key, metadata] : state.processed_files) {
    if (!metadata.processed) continue;

    const auto semantic_tier = semantic_tier_for_path(snapshot.tiers, canonical_path_key);
    if (should_allow_semantic_revisit(metadata, semantic_tier, retry_limit)) continue;
    effective_seen.insert(canonical_path_key);
  }

  return effective_seen;
}

static void record_processed_testcase(State& state,
                                      const std::filesystem::path& request_sample,
                                      int consumed_semantic_tier,
                                      bool consumed_retry_budget) {
  const auto canonical_path_key = canonicalize_testcase_path(request_sample);
  auto [it, inserted] = state.processed_files.try_emplace(canonical_path_key);
  auto& metadata = it->second;
  if (inserted || metadata.canonical_path_key.empty()) {
    metadata.canonical_path_key = canonical_path_key;
  }
  metadata.processed = true;
  metadata.highest_consumed_tier = std::max(metadata.highest_consumed_tier, consumed_semantic_tier);
  if (consumed_retry_budget) {
    metadata.retry_count += 1;
  }
}

static void maybe_reload_frontier_manifest(SemanticFrontierManager& frontier,
                                           const Logger& log) {
  const auto now = now_ms();
  const auto json_mtime = read_manifest_mtime(frontier.json_manifest_path);
  const auto text_mtime = read_manifest_mtime(frontier.text_manifest_path);

  bool should_attempt = !frontier.initialized;
  if (!should_attempt) {
    const auto interval_ms = frontier.reload_interval_sec * 1000ULL;
    const bool interval_elapsed = frontier.reload_interval_sec == 0 ||
                                  (now - frontier.last_reload_check_ms) >= interval_ms;
    const bool manifest_changed = json_mtime != frontier.json_manifest_mtime ||
                                  text_mtime != frontier.text_manifest_mtime;
    should_attempt = interval_elapsed && manifest_changed;
  }
  if (!should_attempt) return;

  const bool initial_load = !frontier.initialized;
  frontier.initialized = true;
  frontier.last_reload_check_ms = now;
  frontier.json_manifest_mtime = json_mtime;
  frontier.text_manifest_mtime = text_mtime;

  std::vector<std::string> reasons;
  const auto json_result = load_json_frontier_snapshot(frontier.json_manifest_path);
  if (json_result.success) {
    frontier.snapshot = json_result.snapshot;
    log_frontier_snapshot_event(log, initial_load ? "Loaded" : "Reloaded", frontier.snapshot,
                                initial_load ? "initial load via semantic JSON manifest"
                                             : "manifest mtime changed");
    return;
  }
  reasons.push_back("semantic JSON fallback: " + json_result.reason);

  if (!initial_load && frontier.snapshot.source == FrontierSource::JsonManifest) {
    log_frontier_keep_event(log, frontier.snapshot, join_frontier_reasons(reasons));
    return;
  }

  const auto text_result = load_text_frontier_snapshot(frontier.text_manifest_path);
  if (text_result.success) {
    frontier.snapshot = text_result.snapshot;
    log_frontier_snapshot_event(log, initial_load ? "Loaded" : "Reloaded", frontier.snapshot,
                                join_frontier_reasons(reasons));
    return;
  }
  reasons.push_back("text manifest fallback: " + text_result.reason);

  if (!initial_load && frontier.snapshot.source == FrontierSource::TextManifest) {
    log_frontier_keep_event(log, frontier.snapshot, join_frontier_reasons(reasons));
    return;
  }

  frontier.snapshot = SemanticFrontierSnapshot{};
  frontier.snapshot.applied_at = utc_timestamp_now();
  log_frontier_snapshot_event(log, initial_load ? "Loaded" : "Reloaded", frontier.snapshot,
                              join_frontier_reasons(reasons));
}

enum class TestcaseResult { Uninteresting, New, Hang, Crash };

// 从父测试用例文件名提取 ID (格式: id:NNNNNN,...)
static std::string extract_parent_id(const std::filesystem::path& parent) {
  auto name = parent.filename().string();
  // 格式: id:NNNNNN,...
  if (name.rfind("id:", 0) == 0 && name.size() >= 9) {
    return name.substr(3, 6);
  }
  return "000000";
}

static TestcaseResult process_new_testcase(const std::filesystem::path& testcase,
                                           const std::filesystem::path& parent,
                                           const std::filesystem::path& tmp_dir,
                                           const std::optional<std::filesystem::path>& response_tail_sample,
                                           const AflConfig& afl,
                                           State& state,
                                           const Logger& log) {
  // log.debug("Processing test case " + testcase.string());
  // 每个测试用例使用不同的 bitmap 文件避免冲突
  const auto testcase_bitmap_path = tmp_dir / ("bitmap_" + testcase.filename().string());
  
  AflShowmapResult r;
  try {
    r = afl.run_showmap(testcase_bitmap_path, testcase, response_tail_sample);
  } catch (const std::exception& e) {
    log.warn("afl-showmap failed: " + std::string(e.what()));
    return TestcaseResult::Uninteresting;
  }

  if (r.kind == AflShowmapResult::Kind::Success && r.bitmap.has_value()) {
    const bool interesting = state.current_bitmap.merge(*r.bitmap);
    if (interesting) {
      // log.debug("Test case provides new coverage!");
      // 复制到 SymCC 队列
      try {
        copy_testcase(testcase, state.queue, parent);
      } catch (...) {}
      
      // 关键：复制到 AFL 队列让 AFL 继续 fuzz
      const auto src_id = extract_parent_id(parent);
      try {
        afl.copy_to_afl_queue(testcase, src_id);
      } catch (const std::exception& e) {
        log.warn("Failed to copy to AFL queue: " + std::string(e.what()));
      }
      return TestcaseResult::New;
    }
    return TestcaseResult::Uninteresting;
  }
  if (r.kind == AflShowmapResult::Kind::Hang) {
    log.info("Ignoring new test case " + testcase.string() + " because afl-showmap timed out on it");
    return TestcaseResult::Hang;
  }

  // Crash
  log.info("Test case " + testcase.string() + " crashes afl-showmap; archiving");
  try {
    copy_testcase(testcase, state.crashes, parent);
    // 崩溃用例也放入 AFL 队列
    const auto src_id = extract_parent_id(parent);
    afl.copy_to_afl_queue(testcase, src_id);
  } catch (const std::exception& e) {
    log.warn("Failed to archive crash: " + std::string(e.what()));
  }
  return TestcaseResult::Crash;
}

static void test_input(const SymCCInput& input,
                       const SymCC& symcc,
                       const AflConfig& afl,
                       State& state,
                       const Logger& log,
                       bool request_is_high_value,
                       int consumed_semantic_tier,
                       bool consumed_retry_budget) {
  log.info("Running SymCC on request sample " + input.request_sample.string());
  if (input.response_tail_sample.has_value()) {
    log.info("Using response-tail sample " + input.response_tail_sample->string());
  }

  const auto tmp_dir = create_temp_dir("symcc_fuzzing");
  const auto output_dir = tmp_dir / "output";

  std::uint64_t num_interesting = 0;
  std::uint64_t num_total = 0;
  std::uint64_t num_new_coverage = 0;

  SymCCResult res;
  try {
    res = symcc.run(input, output_dir);
  } catch (const std::exception& e) {
    log.error("SymCC execution failed: " + std::string(e.what()));
    record_processed_testcase(state, input.request_sample, consumed_semantic_tier,
                              consumed_retry_budget);
    // 清理临时目录
    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);
    return;
  }

  for (const auto& new_test : res.test_cases) {
    const auto tr = process_new_testcase(new_test, input.request_sample, tmp_dir,
                                         input.response_tail_sample, afl, state, log);
    num_total += 1;
    if (tr == TestcaseResult::New) {
      num_new_coverage += 1;
      num_interesting += 1;
    }
    if (tr == TestcaseResult::Crash) {
      num_interesting += 1;
    }
  }
  log.info("Generated " + std::to_string(num_total) + " test cases, copied " + std::to_string(num_interesting) + " to AFL queue");

  if (res.killed) {
    log.info("The target process was killed (probably timeout/OOM); archiving to " + state.hangs.path.string());
    try {
      copy_testcase(input.request_sample, state.hangs, input.request_sample);
    } catch (...) {}
  }
  record_processed_testcase(state, input.request_sample, consumed_semantic_tier,
                            consumed_retry_budget);
  state.stats.add(res);
  if (request_is_high_value) {
    state.stats.high_value_new_coverage += num_new_coverage;
    state.stats.high_value_new_interesting += num_interesting;
  }

  // 清理临时目录
  std::error_code ec;
  std::filesystem::remove_all(tmp_dir, ec);
}

int main(int argc, char** argv) {
  try {
    auto options = parse_args(argc, argv);
    Logger log{options.verbose};

    log.info("SymCC Fuzzing Helper (C++ version) starting...");
    log.info("AFL fuzzer: " + options.fuzzer_name);
    log.info("Output dir: " + options.output_dir.string());

    // 检查用户指定的目标程序是否存在
    if (!options.command.empty()) {
      std::filesystem::path target_bin = options.command[0];
      if (!std::filesystem::exists(target_bin)) {
        log.error("Target program does not exist: " + target_bin.string());
        log.error("Please provide the path to SymCC-compiled binary!");
        return 1;
      }
      log.info("Target binary: " + target_bin.string());
    }

    if (!std::filesystem::is_directory(options.output_dir)) {
      log.error("The directory " + options.output_dir.string() + " does not exist!");
      return 1;
    }

    // AFL 目录结构: output_dir / name / fuzzer_name
    const auto fuzzer_dir = options.output_dir / options.name / options.fuzzer_name;
    auto afl_queue = fuzzer_dir / "queue";
    if (!std::filesystem::is_directory(afl_queue)) {
      log.error("The AFL queue " + afl_queue.string() + " does not exist!");
      return 1;
    }

    // SymCC 输出目录: output_dir / name / symcc_name
    const auto symcc_dir = options.output_dir / options.name / (options.name + "_symcc");
    if (std::filesystem::is_directory(symcc_dir)) {
      log.error(symcc_dir.string() + " already exists; resuming is not supported");
      return 1;
    }

    if (options.response_tail_dir.has_value() && !std::filesystem::is_directory(*options.response_tail_dir)) {
      log.error("Response-tail corpus directory does not exist: " + options.response_tail_dir->string());
      return 1;
    }
    if (options.response_tail_dir.has_value()) {
      std::error_code ec;
      std::filesystem::directory_iterator it(*options.response_tail_dir, ec);
      if (ec || it == std::filesystem::directory_iterator()) {
        log.error("Response-tail corpus directory is empty or unreadable: " + options.response_tail_dir->string());
        return 1;
      }
      const bool has_placeholder = has_response_tail_placeholder(options.command, options.response_tail_placeholder);
      if (!has_placeholder && !options.response_tail_env.has_value()) {
        log.error("Response-tail corpus requires either placeholder token in command (-p) or env mapping (-e)");
        return 1;
      }
    } else if (options.response_tail_env.has_value()) {
      log.error("-e requires -r <response_tail_dir>");
      return 1;
    }

    auto symcc = SymCC::make(symcc_dir, options.command, options.stdin_is_filename,
                             options.response_tail_placeholder, options.response_tail_env);
    // log.debug("SymCC config: use_stdin=" + std::string(symcc.use_standard_input ? "yes" : "no") +
    //           ", stdin_is_filename=" + std::string(symcc.stdin_is_filename ? "yes" : "no"));
    
    // 如果用户没指定 AFL target，默认使用和 SymCC 相同的命令
    std::vector<std::string> afl_target = options.afl_target;
    if (afl_target.empty()) {
      // 警告：fuzzer_stats 中的 target 可能与 SymCC 测试的 target 不同
      log.warn("No AFL target specified (-t), will use target from fuzzer_stats");
      log.warn("If afl-showmap times out, specify AFL-compiled target with -t <path>");
    } else {
      log.info("Using custom AFL target: " + afl_target[0]);
    }
    
    auto afl = AflConfig::load_from_fuzzer_output(fuzzer_dir, afl_target);
    afl.response_tail_placeholder = options.response_tail_placeholder;
    afl.response_tail_env = options.response_tail_env;
    log.info("AFL++ map size: " + std::to_string(afl.map_size));
    // log.debug("AFL showmap: " + afl.showmap_path.string());
    // log.debug("Target command: " + (afl.target_command.empty() ? "(empty)" : afl.target_command[0]));
    
    State state = init_state(symcc_dir);
    log.info("SymCC directory created: " + symcc_dir.string());

    SemanticFrontierManager frontier;

    if (const char* manifest_env = std::getenv("SYMCC_HIGH_VALUE_MANIFEST")) {
      std::string manifest_value = trim(manifest_env);
      if (!manifest_value.empty()) {
        frontier.text_manifest_path = std::filesystem::path(manifest_value);
        log.info("SYMCC_HIGH_VALUE_MANIFEST set: " + frontier.text_manifest_path->string());
      }
    }
    if (const char* semantic_env = std::getenv("SYMCC_SEMANTIC_FRONTIER_MANIFEST")) {
      std::string semantic_value = trim(semantic_env);
      if (!semantic_value.empty()) {
        frontier.json_manifest_path = std::filesystem::path(semantic_value);
        log.info("SYMCC_SEMANTIC_FRONTIER_MANIFEST set: " + frontier.json_manifest_path->string());
      }
    }
    frontier.reload_interval_sec = load_frontier_reload_sec(log);
    frontier.retry_limit = load_frontier_retry_limit(log);
    log.info("SYMCC_FRONTIER_RELOAD_SEC effective value: " +
             std::to_string(frontier.reload_interval_sec));
    log.info("SYMCC_FRONTIER_RETRY_LIMIT effective value: " +
             std::to_string(frontier.retry_limit));
    maybe_reload_frontier_manifest(frontier, log);

    while (true) {
      maybe_reload_frontier_manifest(frontier, log);

      bool picked_high_value = false;
      std::uint64_t high_value_candidates = 0;
      int picked_semantic_tier = 0;
      const auto effective_seen =
          build_effective_seen_set(state, frontier.snapshot, frontier.retry_limit);
      auto next = afl.best_new_testcase(effective_seen,
                                        frontier.snapshot.tiers.empty() ? nullptr : &frontier.snapshot.tiers,
                                        &picked_high_value,
                                        &high_value_candidates,
                                        &picked_semantic_tier);
      state.stats.high_value_candidates += high_value_candidates;
      if (!next.has_value()) {
        // log.debug("Waiting for new test cases...");
        std::this_thread::sleep_for(std::chrono::seconds(5));
      } else {
        if (picked_high_value) {
          state.stats.high_value_processed += 1;
          log.info("Picked high-value request sample from " +
                   frontier_source_name(frontier.snapshot.source) + " (tier=" +
                   std::to_string(picked_semantic_tier) + "): " + next->string());
        }
        const auto canonical_path_key = canonicalize_testcase_path(*next);
        bool consumed_retry_budget = false;
        if (const auto it = state.processed_files.find(canonical_path_key);
            it != state.processed_files.end()) {
          const auto& metadata = it->second;
          consumed_retry_budget =
              should_allow_semantic_revisit(metadata, picked_semantic_tier, frontier.retry_limit);
          if (consumed_retry_budget) {
            log.info("Allowing semantic frontier revisit for request sample " + next->string() +
                     " after strict tier promotion (" +
                     std::to_string(metadata.highest_consumed_tier) + " -> " +
                     std::to_string(picked_semantic_tier) + ", retry " +
                     std::to_string(metadata.retry_count + 1) + "/" +
                     std::to_string(frontier.retry_limit) + ")");
          }
        }
        SymCCInput symcc_input;
        symcc_input.request_sample = *next;
        symcc_input.response_tail_sample =
            pick_response_tail_sample(options.response_tail_dir, state.response_tail_pick_count);
        if (symcc_input.response_tail_sample.has_value()) {
          state.response_tail_pick_count += 1;
        }
        test_input(symcc_input, symcc, afl, state, log, picked_high_value,
                   picked_semantic_tier, consumed_retry_budget);
      }

      const auto now = now_ms();
      if ((now - state.last_stats_ms) > kStatsIntervalSec * 1000ULL) {
        state.stats.log(state.stats_file);
        state.stats_file.flush();
        state.last_stats_ms = now;
        
        // 控制台输出简要统计
        log.info("Stats: ok=" + std::to_string(state.stats.ok_count) +
                 " fail=" + std::to_string(state.stats.fail_count) +
                 " high_value_processed=" + std::to_string(state.stats.high_value_processed) +
                 " high_value_new_coverage=" + std::to_string(state.stats.high_value_new_coverage) +
                 " high_value_new_interesting=" + std::to_string(state.stats.high_value_new_interesting) +
                  " processed=" + std::to_string(state.processed_files.size()));
      }
    }
  } catch (const std::exception& e) {
    std::cerr << "Fatal: " << e.what() << "\n";
    return 1;
  }
}
