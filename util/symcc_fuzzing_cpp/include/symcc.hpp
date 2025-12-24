#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace symcc_fuzzing {

struct SymCCResult {
  std::vector<std::filesystem::path> test_cases;
  bool killed = false;
  std::uint64_t elapsed_ms = 0;
  std::optional<std::uint64_t> solver_time_us;
};

struct SymCC {
  bool use_standard_input = false;
  bool stdin_is_filename = false;  // stdin 传入的是文件名而不是数据
  std::filesystem::path bitmap_file;
  std::filesystem::path input_file;
  std::vector<std::string> command;

  static SymCC make(const std::filesystem::path& symcc_dir,
                    const std::vector<std::string>& command_line,
                    bool stdin_is_filename = false);

  SymCCResult run(const std::filesystem::path& input,
                  const std::filesystem::path& output_dir) const;
};

}  // namespace symcc_fuzzing
