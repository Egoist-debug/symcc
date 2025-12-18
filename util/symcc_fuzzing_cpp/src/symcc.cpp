#include "symcc.hpp"

#include "process.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <regex>
#include <stdexcept>

namespace symcc_fuzzing {

static std::vector<std::string> insert_input_file(const std::vector<std::string>& cmd,
                                                  const std::filesystem::path& input_file) {
  std::vector<std::string> out = cmd;
  for (auto& s : out) {
    if (s == "@@") {
      s = input_file.string();
      break;
    }
  }
  return out;
}

static std::optional<std::uint64_t> parse_solver_time_us(const std::string& stderr_out) {
  // Match Rust logic: look for lines starting with "[STAT] SMT:" and parse
  // "solving_time": <num>
  static const std::regex re("\\\"solving_time\\\"\\s*:\\s*(\\d+)");

  // Scan from the end to mimic rsplit.
  std::size_t pos = stderr_out.size();
  while (pos > 0) {
    auto nl = stderr_out.rfind('\n', pos - 1);
    auto start = (nl == std::string::npos) ? 0 : (nl + 1);
    auto line = stderr_out.substr(start, pos - start);
    auto trimmed = line;
    // cheap trim-left
    while (!trimmed.empty() && (trimmed[0] == ' ' || trimmed[0] == '\t')) trimmed.erase(trimmed.begin());
    if (trimmed.rfind("[STAT] SMT:", 0) == 0) {
      std::smatch m;
      if (std::regex_search(trimmed, m, re)) {
        try {
          return static_cast<std::uint64_t>(std::stoull(m[1]));
        } catch (...) {
          return std::nullopt;
        }
      }
    }
    if (nl == std::string::npos) break;
    pos = nl;
  }
  return std::nullopt;
}

SymCC SymCC::make(const std::filesystem::path& symcc_dir,
                  const std::vector<std::string>& command_line) {
  SymCC s;
  s.input_file = symcc_dir / ".cur_input";
  s.bitmap_file = symcc_dir / "bitmap";
  s.use_standard_input = (std::find(command_line.begin(), command_line.end(), "@@") == command_line.end());
  s.command = insert_input_file(command_line, s.input_file);
  return s;
}

SymCCResult SymCC::run(const std::filesystem::path& input,
                       const std::filesystem::path& output_dir) const {
  std::error_code ec;
  std::filesystem::copy_file(input, input_file, std::filesystem::copy_options::overwrite_existing, ec);
  if (ec) throw std::runtime_error("Failed to copy input to workbench: " + ec.message());

  std::filesystem::create_directory(output_dir, ec);
  if (ec) throw std::runtime_error("Failed to create SymCC output dir: " + ec.message());

  std::vector<std::string> argv;
  argv.push_back("timeout");
  argv.insert(argv.end(), {"-k", "5", "90"});
  argv.insert(argv.end(), command.begin(), command.end());

  std::map<std::string, std::string> env;
  env["SYMCC_ENABLE_LINEARIZATION"] = "1";
  env["SYMCC_AFL_COVERAGE_MAP"] = bitmap_file.string();
  env["SYMCC_OUTPUT_DIR"] = output_dir.string();
  if (!use_standard_input) {
    env["SYMCC_INPUT_FILE"] = input_file.string();
  }

  const auto start = std::chrono::steady_clock::now();
  const std::optional<std::filesystem::path> stdin_path = use_standard_input ? std::make_optional(input_file) : std::nullopt;
  auto pr = run_process(argv, env, stdin_path, true);
  const auto end = std::chrono::steady_clock::now();
  const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

  bool killed = false;
  if (pr.signaled) {
    killed = true;
  } else {
    // timeout uses 124 for timeout; also treat SIGKILL (137) / SIGTERM (143) as killed-ish.
    if (pr.exit_code == 124 || pr.exit_code == 137 || pr.exit_code == 143) killed = true;
  }

  std::vector<std::filesystem::path> tests;
  for (auto it = std::filesystem::directory_iterator(output_dir, ec);
       !ec && it != std::filesystem::directory_iterator();
       it.increment(ec)) {
    tests.push_back(it->path());
  }

  SymCCResult r;
  r.test_cases = std::move(tests);
  r.killed = killed;
  r.elapsed_ms = static_cast<std::uint64_t>(elapsed_ms);
  r.solver_time_us = parse_solver_time_us(pr.stderr_output);
  if (r.solver_time_us && *r.solver_time_us > r.elapsed_ms * 1000ULL) {
    r.solver_time_us.reset();
  }
  return r;
}

}  // namespace symcc_fuzzing
