#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace symcc_fuzzing {

struct ProcessResult {
  int exit_code = -1;          // valid if exited normally
  bool signaled = false;       // true if terminated by signal
  int term_signal = 0;         // valid if signaled
  std::string stderr_output;   // captured stderr (optional)
};

// Run a process with optional stdin redirected from a file and with stdout
// redirected to /dev/null. If capture_stderr is true, stderr is captured.
// If working_dir is set, the process will run in that directory.
ProcessResult run_process(const std::vector<std::string>& argv,
                          const std::map<std::string, std::string>& extra_env,
                          const std::optional<std::filesystem::path>& stdin_file,
                          bool capture_stderr,
                          const std::optional<std::filesystem::path>& working_dir = std::nullopt);

}  // namespace symcc_fuzzing
