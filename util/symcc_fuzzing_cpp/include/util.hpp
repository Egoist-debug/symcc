#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace symcc_fuzzing {

struct Logger {
  bool verbose = false;
  void info(const std::string& s) const;
  void warn(const std::string& s) const;
  void error(const std::string& s) const;
  void debug(const std::string& s) const;
};

std::string trim(std::string s);
std::vector<std::string> split_whitespace(const std::string& s);

std::filesystem::path create_temp_dir(const std::string& prefix);
std::uint64_t now_ms();

}  // namespace symcc_fuzzing
