#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace symcc_fuzzing {

struct AflShowmapResult {
  enum class Kind {
    Success,
    Hang,
    Crash,
  };

  Kind kind;
  std::optional<std::vector<std::uint8_t>> bitmap;
};

class AflMap {
 public:
  AflMap() = default;

  bool empty() const { return !data_.has_value(); }
  std::size_t size() const { return data_ ? data_->size() : 0; }

  // Merge another map into this map. Returns true if the merge produced
  // new information (as defined by AFL++ hitcount bucketing).
  bool merge(const std::vector<std::uint8_t>& other);

  const std::optional<std::vector<std::uint8_t>>& data() const { return data_; }

 private:
  // Normalize AFL/AFL++ raw hitcounts into buckets, as AFL++ does for
  // "new bits" detection.
  static std::uint8_t classify_hitcount(std::uint8_t v);
  static void normalize_in_place(std::vector<std::uint8_t>& v);

  std::optional<std::vector<std::uint8_t>> data_;
};

struct AflConfig {
  std::filesystem::path showmap_path;
  std::vector<std::string> target_command;  // target program and args (without "--")
  bool use_standard_input = false;
  bool use_qemu_mode = false;
  std::filesystem::path queue_dir;
  std::filesystem::path fuzzer_output_dir;  // AFL output directory for this fuzzer
  std::string response_tail_placeholder = "@@RESP_TAIL@@";
  std::optional<std::string> response_tail_env;

  // AFL++ map size handling.
  std::size_t map_size = 65536;

  static AflConfig load_from_fuzzer_output(const std::filesystem::path& fuzzer_output_dir,
                                           const std::vector<std::string>& custom_target = {});
  std::optional<std::filesystem::path> best_new_testcase(
      const std::unordered_set<std::string>& seen) const;

  AflShowmapResult run_showmap(const std::filesystem::path& bitmap_out,
                              const std::filesystem::path& testcase,
                              const std::optional<std::filesystem::path>& response_tail_sample =
                                  std::nullopt) const;
  
  // 将新测试用例复制到 AFL 队列中，让 AFL 也能使用
  void copy_to_afl_queue(const std::filesystem::path& testcase, 
                         const std::string& src_id) const;
};

}  // namespace symcc_fuzzing
