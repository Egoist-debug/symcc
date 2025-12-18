#include "afl.hpp"
#include "symcc.hpp"
#include "testcase.hpp"
#include "util.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <unordered_set>

using namespace symcc_fuzzing;

static const std::uint64_t kStatsIntervalSec = 60;

struct CLI {
  std::string fuzzer_name;
  std::filesystem::path output_dir;
  std::string name;
  bool verbose = false;
  std::vector<std::string> command;
};

static void usage() {
  std::cerr
      << "Usage: symcc_fuzzing_helper -a <fuzzer_name> -o <afl_output_dir> -n <symcc_name> [-v] -- <program> [args...]\n";
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
      std::ofstream(symcc_dir / "stats")};
  if (!s.stats_file) throw std::runtime_error("Failed to open stats file");
  return s;
}

enum class TestcaseResult { Uninteresting, New, Hang, Crash };

static TestcaseResult process_new_testcase(const std::filesystem::path& testcase,
                                           const std::filesystem::path& parent,
                                           const std::filesystem::path& tmp_dir,
                                           const AflConfig& afl,
                                           State& state,
                                           const Logger& log) {
  log.debug("Processing test case " + testcase.string());
  const auto testcase_bitmap_path = tmp_dir / "testcase_bitmap";
  auto r = afl.run_showmap(testcase_bitmap_path, testcase);

  if (r.kind == AflShowmapResult::Kind::Success) {
    const bool interesting = state.current_bitmap.merge(*r.bitmap);
    if (interesting) {
      copy_testcase(testcase, state.queue, parent);
      return TestcaseResult::New;
    }
    return TestcaseResult::Uninteresting;
  }
  if (r.kind == AflShowmapResult::Kind::Hang) {
    log.info("Ignoring new test case " + testcase.string() + " because afl-showmap timed out on it");
    return TestcaseResult::Hang;
  }

  log.info("Test case " + testcase.string() + " crashes afl-showmap; archiving");
  copy_testcase(testcase, state.crashes, parent);
  copy_testcase(testcase, state.queue, parent);
  return TestcaseResult::Crash;
}

static void test_input(const std::filesystem::path& input,
                       const SymCC& symcc,
                       const AflConfig& afl,
                       State& state,
                       const Logger& log) {
  log.info("Running on input " + input.string());

  const auto tmp_dir = create_temp_dir("symcc_fuzzing");
  const auto output_dir = tmp_dir / "output";

  std::uint64_t num_interesting = 0;
  std::uint64_t num_total = 0;

  auto res = symcc.run(input, output_dir);
  for (const auto& new_test : res.test_cases) {
    const auto tr = process_new_testcase(new_test, input, tmp_dir, afl, state, log);
    num_total += 1;
    if (tr == TestcaseResult::New) num_interesting += 1;
  }
  log.info("Generated " + std::to_string(num_total) + " test cases (" + std::to_string(num_interesting) + " new)");

  if (res.killed) {
    log.info("The target process was killed (probably timeout/OOM); archiving to " + state.hangs.path.string());
    copy_testcase(input, state.hangs, input);
  }
  state.processed_files.insert(input.string());
  state.stats.add(res);
}

int main(int argc, char** argv) {
  try {
    auto options = parse_args(argc, argv);
    Logger log{options.verbose};

    if (!std::filesystem::is_directory(options.output_dir)) {
      log.error("The directory " + options.output_dir.string() + " does not exist!");
      return 0;
    }

    auto afl_queue = options.output_dir / options.fuzzer_name / "queue";
    if (!std::filesystem::is_directory(afl_queue)) {
      log.error("The AFL queue " + afl_queue.string() + " does not exist!");
      return 0;
    }

    const auto symcc_dir = options.output_dir / options.name;
    if (std::filesystem::is_directory(symcc_dir)) {
      log.error(symcc_dir.string() + " already exists; resuming is not supported");
      return 0;
    }

    auto symcc = SymCC::make(symcc_dir, options.command);
    auto afl = AflConfig::load_from_fuzzer_output(options.output_dir / options.fuzzer_name);
    State state = init_state(symcc_dir);

    log.debug("AFL++ map size detected: " + std::to_string(afl.map_size));

    while (true) {
      auto next = afl.best_new_testcase(state.processed_files);
      if (!next.has_value()) {
        log.debug("Waiting for new test cases...");
        std::this_thread::sleep_for(std::chrono::seconds(5));
      } else {
        test_input(*next, symcc, afl, state, log);
      }

      const auto now = now_ms();
      if ((now - state.last_stats_ms) > kStatsIntervalSec * 1000ULL) {
        state.stats.log(state.stats_file);
        state.stats_file.flush();
        state.last_stats_ms = now;
      }
    }
  } catch (const std::exception& e) {
    std::cerr << "Fatal: " << e.what() << "\n";
    return 1;
  }
}
