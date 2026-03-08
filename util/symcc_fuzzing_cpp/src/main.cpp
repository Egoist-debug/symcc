#include "afl.hpp"
#include "symcc.hpp"
#include "testcase.hpp"
#include "util.hpp"

#include <chrono>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <optional>
#include <unordered_set>

using namespace symcc_fuzzing;

static const std::uint64_t kStatsIntervalSec = 60;

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
    out << "--------------------------------------------------------------------------------\n";
  }
};

struct State {
  AflMap current_bitmap;
  std::unordered_set<std::string> processed_files;
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
                       const Logger& log) {
  log.info("Running SymCC on request sample " + input.request_sample.string());
  if (input.response_tail_sample.has_value()) {
    log.info("Using response-tail sample " + input.response_tail_sample->string());
  }

  const auto tmp_dir = create_temp_dir("symcc_fuzzing");
  const auto output_dir = tmp_dir / "output";

  std::uint64_t num_interesting = 0;
  std::uint64_t num_total = 0;

  SymCCResult res;
  try {
    res = symcc.run(input, output_dir);
  } catch (const std::exception& e) {
    log.error("SymCC execution failed: " + std::string(e.what()));
    state.processed_files.insert(input.request_sample.string());
    // 清理临时目录
    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);
    return;
  }

  for (const auto& new_test : res.test_cases) {
    const auto tr = process_new_testcase(new_test, input.request_sample, tmp_dir,
                                         input.response_tail_sample, afl, state, log);
    num_total += 1;
    if (tr == TestcaseResult::New) num_interesting += 1;
  }
  log.info("Generated " + std::to_string(num_total) + " test cases, copied " + std::to_string(num_interesting) + " to AFL queue");

  if (res.killed) {
    log.info("The target process was killed (probably timeout/OOM); archiving to " + state.hangs.path.string());
    try {
      copy_testcase(input.request_sample, state.hangs, input.request_sample);
    } catch (...) {}
  }
  state.processed_files.insert(input.request_sample.string());
  state.stats.add(res);

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

    while (true) {
      auto next = afl.best_new_testcase(state.processed_files);
      if (!next.has_value()) {
        // log.debug("Waiting for new test cases...");
        std::this_thread::sleep_for(std::chrono::seconds(5));
      } else {
        SymCCInput symcc_input;
        symcc_input.request_sample = *next;
        symcc_input.response_tail_sample =
            pick_response_tail_sample(options.response_tail_dir, state.response_tail_pick_count);
        if (symcc_input.response_tail_sample.has_value()) {
          state.response_tail_pick_count += 1;
        }
        test_input(symcc_input, symcc, afl, state, log);
      }

      const auto now = now_ms();
      if ((now - state.last_stats_ms) > kStatsIntervalSec * 1000ULL) {
        state.stats.log(state.stats_file);
        state.stats_file.flush();
        state.last_stats_ms = now;
        
        // 控制台输出简要统计
        log.info("Stats: ok=" + std::to_string(state.stats.ok_count) +
                 " fail=" + std::to_string(state.stats.fail_count) +
                 " processed=" + std::to_string(state.processed_files.size()));
      }
    }
  } catch (const std::exception& e) {
    std::cerr << "Fatal: " << e.what() << "\n";
    return 1;
  }
}
