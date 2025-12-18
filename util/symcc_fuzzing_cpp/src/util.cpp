#include "util.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>

namespace symcc_fuzzing {

void Logger::info(const std::string& s) const { std::cerr << "[INFO] " << s << "\n"; }
void Logger::warn(const std::string& s) const { std::cerr << "[WARN] " << s << "\n"; }
void Logger::error(const std::string& s) const { std::cerr << "[ERROR] " << s << "\n"; }
void Logger::debug(const std::string& s) const {
  if (verbose) std::cerr << "[DEBUG] " << s << "\n";
}

std::string trim(std::string s) {
  auto is_space = [](unsigned char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; };
  while (!s.empty() && is_space(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
  while (!s.empty() && is_space(static_cast<unsigned char>(s.back()))) s.pop_back();
  return s;
}

std::vector<std::string> split_whitespace(const std::string& s) {
  std::istringstream iss(s);
  std::vector<std::string> out;
  for (std::string tok; iss >> tok;) out.push_back(tok);
  return out;
}

std::uint64_t now_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::filesystem::path create_temp_dir(const std::string& prefix) {
  auto base = std::filesystem::temp_directory_path();
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<std::uint64_t> dist;

  for (int i = 0; i < 64; ++i) {
    std::ostringstream name;
    name << prefix << "_" << std::hex << dist(gen);
    auto p = base / name.str();
    std::error_code ec;
    if (std::filesystem::create_directory(p, ec)) return p;
  }

  throw std::runtime_error("Failed to create a temporary directory");
}

}  // namespace symcc_fuzzing
