#include "symcc.hpp"

#include "process.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
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

static std::vector<std::string> insert_response_tail_file(const std::vector<std::string>& cmd,
                                                          const std::string& placeholder,
                                                          const std::filesystem::path& response_tail_file) {
  std::vector<std::string> out = cmd;
  for (auto& s : out) {
    if (s == placeholder) {
      s = response_tail_file.string();
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
                  const std::vector<std::string>& command_line,
                  bool stdin_is_filename,
                  const std::string& response_tail_placeholder,
                  const std::optional<std::string>& response_tail_env) {
  SymCC s;
  s.input_file = symcc_dir / ".cur_input";
  s.response_tail_file = symcc_dir / ".cur_response_tail";
  s.bitmap_file = symcc_dir / "bitmap";
  s.stdin_is_filename = stdin_is_filename;
  s.response_tail_placeholder = response_tail_placeholder;
  s.response_tail_env = response_tail_env;
  // 没有 @@ 就是 stdin 模式
  s.use_standard_input = (std::find(command_line.begin(), command_line.end(), "@@") == command_line.end());
  s.requires_response_tail_sample =
      (std::find(command_line.begin(), command_line.end(), s.response_tail_placeholder) != command_line.end()) ||
      s.response_tail_env.has_value();
  s.command = insert_input_file(command_line, s.input_file);
  s.command = insert_response_tail_file(s.command, s.response_tail_placeholder, s.response_tail_file);
  return s;
}

SymCCResult SymCC::run(const SymCCInput& input,
                       const std::filesystem::path& output_dir) const {
  std::error_code ec;
  std::filesystem::copy_file(input.request_sample, input_file, std::filesystem::copy_options::overwrite_existing, ec);
  if (ec) throw std::runtime_error("Failed to copy input to workbench: " + ec.message());

  if (input.response_tail_sample.has_value()) {
    ec.clear();
    std::filesystem::copy_file(*input.response_tail_sample, response_tail_file,
                               std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) throw std::runtime_error("Failed to copy response-tail input to workbench: " + ec.message());
  }

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
  // 只有文件输入模式(有@@)才设置 SYMCC_INPUT_FILE
  // stdin 模式下不设置，让 SymCC 自动把 stdin 数据符号化
  if (!use_standard_input) {
    env["SYMCC_INPUT_FILE"] = input_file.string();
  }
  if (response_tail_env.has_value() && input.response_tail_sample.has_value()) {
    env[*response_tail_env] = response_tail_file.string();
  }
  
  // 继承并扩展 LD_LIBRARY_PATH，确保能找到 libsymcc-rt.so
  std::string ld_path;
  if (const char* existing = std::getenv("LD_LIBRARY_PATH")) {
    ld_path = existing;
  }
  if (!ld_path.empty()) ld_path += ":";
  ld_path += "/home/ubuntu/symcc/build/linux/x86_64/release";
  env["LD_LIBRARY_PATH"] = ld_path;

  // Debug: 打印执行命令
//   std::cerr << "[DEBUG] SymCC command: ";
//   for (const auto& a : argv) std::cerr << a << " ";
//   std::cerr << "\n";
//   std::cerr << "[DEBUG] SYMCC_OUTPUT_DIR=" << output_dir.string() << "\n";
//   std::cerr << "[DEBUG] SYMCC_INPUT_FILE=" << input_file.string() << "\n";
//   std::cerr << "[DEBUG] use_stdin=" << (use_standard_input ? "yes" : "no") << "\n";

  const auto start = std::chrono::steady_clock::now();
  
  // stdin 模式：传入数据内容；文件模式：不传 stdin
  std::optional<std::filesystem::path> stdin_path;
  if (use_standard_input) {
    stdin_path = input_file;  // 直接把数据内容传入 stdin
  }

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
