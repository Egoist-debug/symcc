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
  std::vector<std::string> target_command;  // includes "--" separator
  bool use_standard_input = false;
  bool use_qemu_mode = false;
  std::filesystem::path queue_dir;

  // AFL++ map size handling.
  std::size_t map_size = 65536;

  static AflConfig load_from_fuzzer_output(const std::filesystem::path& fuzzer_output_dir);
  std::optional<std::filesystem::path> best_new_testcase(
      const std::unordered_set<std::string>& seen) const;

  AflShowmapResult run_showmap(const std::filesystem::path& bitmap_out,
                              const std::filesystem::path& testcase) const;
};

}  // namespace symcc_fuzzing
