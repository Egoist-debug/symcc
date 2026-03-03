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

struct SymCCInput {
  std::filesystem::path request_sample;
  std::optional<std::filesystem::path> response_tail_sample;
};

struct SymCC {
  bool use_standard_input = false;
  bool stdin_is_filename = false;  // stdin 传入的是文件名而不是数据
  std::filesystem::path bitmap_file;
  std::filesystem::path input_file;
  std::filesystem::path response_tail_file;
  std::string response_tail_placeholder = "@@RESP_TAIL@@";
  std::optional<std::string> response_tail_env;
  bool requires_response_tail_sample = false;
  std::vector<std::string> command;

  static SymCC make(const std::filesystem::path& symcc_dir,
                    const std::vector<std::string>& command_line,
                    bool stdin_is_filename = false,
                    const std::string& response_tail_placeholder = "@@RESP_TAIL@@",
                    const std::optional<std::string>& response_tail_env = std::nullopt);

  SymCCResult run(const SymCCInput& input,
                  const std::filesystem::path& output_dir) const;
};

}  // namespace symcc_fuzzing
