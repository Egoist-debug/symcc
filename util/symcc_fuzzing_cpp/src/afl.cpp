#include "afl.hpp"

#include "process.hpp"
#include "testcase.hpp"
#include "util.hpp"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>

namespace symcc_fuzzing {

static std::size_t parse_map_size_from_fuzzer_stats(const std::filesystem::path& stats_path) {
  std::ifstream in(stats_path);
  if (!in) return 65536;
  std::string line;
  while (std::getline(in, line)) {
    // AFL++ variants sometimes use different keys; accept a few.
    auto pos = line.find(':');
    if (pos == std::string::npos) continue;
    auto key = trim(line.substr(0, pos));
    auto val = trim(line.substr(pos + 1));
    if (key == "map_size" || key == "afl_map_size" || key == "real_map_size") {
      try {
        auto n = static_cast<std::size_t>(std::stoul(val));
        if (n >= 64 && n <= (1u << 29)) {
          // AFL++ rounds to 64 bytes.
          if (n % 64) n = (((n >> 6) + 1) << 6);
          return n;
        }
      } catch (...) {
        continue;
      }
    }
  }
  // Fall back to environment (AFL++ uses AFL_MAP_SIZE or AFL_MAPSIZE)
  if (const char* ms = std::getenv("AFL_MAP_SIZE")) {
    try {
      auto n = static_cast<std::size_t>(std::stoul(ms));
      if (n >= 64 && n <= (1u << 29)) {
        if (n % 64) n = (((n >> 6) + 1) << 6);
        return n;
      }
    } catch (...) {
    }
  }
  if (const char* ms = std::getenv("AFL_MAPSIZE")) {
    try {
      auto n = static_cast<std::size_t>(std::stoul(ms));
      if (n >= 64 && n <= (1u << 29)) {
        if (n % 64) n = (((n >> 6) + 1) << 6);
        return n;
      }
    } catch (...) {
    }
  }
  return 65536;
}

bool AflMap::merge(const std::vector<std::uint8_t>& other_raw) {
  std::vector<std::uint8_t> other = other_raw;
  normalize_in_place(other);

  if (!data_.has_value()) {
    data_ = std::move(other);
    return true;
  }

  // If AFL++ map size changes (e.g. AFL_MAP_SIZE), be resilient.
  if (data_->size() != other.size()) {
    const auto old_size = data_->size();
    const auto new_size = other.size();
    data_->resize(std::max(old_size, new_size), 0);
    other.resize(data_->size(), 0);
  }

  bool interesting = false;
  for (std::size_t i = 0; i < data_->size(); ++i) {
    auto& known = (*data_)[i];
    const auto nw = other[i];
    const auto merged = static_cast<std::uint8_t>(known | nw);
    if (merged != known) {
      known = merged;
      interesting = true;
    }
  }
  return interesting;
}

std::uint8_t AflMap::classify_hitcount(std::uint8_t v) {
  // AFL++ hitcount buckets (compatible with AFL's count_class_lookup8 idea)
  // Turn raw hitcount into a bit that represents the bucket.
  if (v == 0) return 0;
  if (v == 1) return 1;
  if (v == 2) return 2;
  if (v == 3) return 4;
  if (v <= 7) return 8;
  if (v <= 15) return 16;
  if (v <= 31) return 32;
  if (v <= 127) return 64;
  return 128;
}

void AflMap::normalize_in_place(std::vector<std::uint8_t>& v) {
  for (auto& b : v) b = classify_hitcount(b);
}

static std::string read_file_as_string(const std::filesystem::path& p) {
  std::ifstream in(p);
  if (!in) throw std::runtime_error("Failed to open " + p.string());
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

AflConfig AflConfig::load_from_fuzzer_output(const std::filesystem::path& fuzzer_output_dir,
                                             const std::vector<std::string>& custom_target) {
  const auto stats_path = fuzzer_output_dir / "fuzzer_stats";
  const auto afl_stats = read_file_as_string(stats_path);

  std::string cmdline;
  {
    std::istringstream iss(afl_stats);
    std::string line;
    while (std::getline(iss, line)) {
      if (line.rfind("command_line", 0) == 0) {
        auto pos = line.find(':');
        if (pos != std::string::npos) cmdline = trim(line.substr(pos + 1));
        break;
      }
    }
  }
  if (cmdline.empty()) throw std::runtime_error("fuzzer_stats does not contain command_line");

  const auto afl_command = split_whitespace(cmdline);
  if (afl_command.empty()) throw std::runtime_error("Unexpected empty AFL command line");

  std::vector<std::string> target_command;
  
  // 如果用户指定了自定义 target，使用它；否则从 fuzzer_stats 解析
  if (!custom_target.empty()) {
    target_command = custom_target;
  } else {
    bool seen_sep = false;
    for (const auto& tok : afl_command) {
      if (!seen_sep) {
        if (tok == "--") {
          seen_sep = true;
          // 不把 "--" 放入 target_command
        }
      } else {
        target_command.push_back(tok);
      }
    }
    if (target_command.empty()) {
      throw std::runtime_error("Cannot locate '--' separator or target command in command_line from fuzzer_stats");
    }
  }

  // 查找 afl-showmap：优先使用 AFL 二进制目录，否则用系统 PATH
  std::filesystem::path afl_bin = afl_command[0];
  std::filesystem::path afl_bin_dir = afl_bin.parent_path();
  
  std::filesystem::path showmap_path;
  if (!afl_bin_dir.empty() && afl_bin_dir != ".") {
    showmap_path = afl_bin_dir / "afl-showmap";
  }
  // 如果路径不存在或为空，尝试常见位置
  if (showmap_path.empty() || !std::filesystem::exists(showmap_path)) {
    if (std::filesystem::exists("/usr/local/bin/afl-showmap")) {
      showmap_path = "/usr/local/bin/afl-showmap";
    } else if (std::filesystem::exists("/usr/bin/afl-showmap")) {
      showmap_path = "/usr/bin/afl-showmap";
    } else {
      // 最后尝试 PATH
      showmap_path = "afl-showmap";
    }
  }

  AflConfig cfg;
  cfg.showmap_path = showmap_path;
  cfg.target_command = std::move(target_command);
  cfg.use_standard_input = (std::find(cfg.target_command.begin(), cfg.target_command.end(), "@@") == cfg.target_command.end());
  cfg.use_qemu_mode = (std::find(afl_command.begin(), afl_command.end(), "-Q") != afl_command.end());
  cfg.queue_dir = fuzzer_output_dir / "queue";
  cfg.fuzzer_output_dir = fuzzer_output_dir;
  cfg.map_size = parse_map_size_from_fuzzer_stats(stats_path);
  return cfg;
}

std::optional<std::filesystem::path> AflConfig::best_new_testcase(
    const std::unordered_set<std::string>& seen) const {
  std::optional<std::filesystem::path> best;
  std::optional<TestcaseScore> best_score;

  std::error_code ec;
  for (auto it = std::filesystem::directory_iterator(queue_dir, ec);
       !ec && it != std::filesystem::directory_iterator();
       it.increment(ec)) {
    const auto p = it->path();
    if (!it->is_regular_file()) continue;
    const auto key = p.string();
    if (seen.find(key) != seen.end()) continue;

    auto sc = score_testcase(p);
    if (!best.has_value() || sc > *best_score) {
      best = p;
      best_score = sc;
    }
  }

  return best;
}

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

static std::vector<std::uint8_t> read_binary(const std::filesystem::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) throw std::runtime_error("Failed to read bitmap file: " + p.string());
  std::vector<std::uint8_t> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return buf;
}

AflShowmapResult AflConfig::run_showmap(const std::filesystem::path& bitmap_out,
                                       const std::filesystem::path& testcase) const {
  std::vector<std::string> argv;
  argv.push_back(showmap_path.string());
  if (use_qemu_mode) argv.push_back("-Q");
  argv.insert(argv.end(), {"-t", "5000", "-m", "none", "-b", "-o", bitmap_out.string()});

  const auto target = insert_input_file(target_command, testcase);
  argv.insert(argv.end(), target.begin(), target.end());

  std::map<std::string, std::string> env;
  // Ensure AFL++ tools use the same map size.
  env["AFL_MAP_SIZE"] = std::to_string(map_size);
  env["AFL_MAPSIZE"] = std::to_string(map_size);

  // 工作目录设置为 output 目录的父目录（即 AFL 主目录）
  // 这样相对路径（如 ./dist/sbin/named）能正确解析
  auto working_dir = fuzzer_output_dir.parent_path();

  const std::optional<std::filesystem::path> stdin_file = use_standard_input ? std::make_optional(testcase) : std::nullopt;
  auto pr = run_process(argv, env, stdin_file, false, working_dir);

  if (pr.exit_code == 0) {
    auto bmp = read_binary(bitmap_out);
    return {AflShowmapResult::Kind::Success, std::move(bmp)};
  }
  if (pr.exit_code == 1) {
    return {AflShowmapResult::Kind::Hang, std::nullopt};
  }
  if (pr.exit_code == 2) {
    return {AflShowmapResult::Kind::Crash, std::nullopt};
  }
  throw std::runtime_error("Unexpected return code from afl-showmap: " + std::to_string(pr.exit_code));
}

void AflConfig::copy_to_afl_queue(const std::filesystem::path& testcase,
                                  const std::string& src_id) const {
  // 生成唯一文件名，放入 AFL 队列
  // 格式: id:NNNNNN,src:XXXXXX,symcc
  static std::atomic<std::uint64_t> counter{0};
  
  std::ostringstream name;
  name << "id:" << std::setw(6) << std::setfill('0') << counter.fetch_add(1);
  name << ",src:" << src_id << ",symcc";
  
  auto dst = queue_dir / name.str();
  std::error_code ec;
  std::filesystem::copy_file(testcase, dst, std::filesystem::copy_options::overwrite_existing, ec);
  if (ec) {
    // 非致命错误，只记录日志
    // throw std::runtime_error("Failed to copy to AFL queue: " + ec.message());
  }
}

}  // namespace symcc_fuzzing
