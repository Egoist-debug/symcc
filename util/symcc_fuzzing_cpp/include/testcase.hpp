#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace symcc_fuzzing {

std::string canonicalize_testcase_path(
    const std::filesystem::path& p,
    const std::optional<std::filesystem::path>& base_dir = std::nullopt);

struct TestcaseDir {
  std::filesystem::path path;
  std::uint64_t next_id = 0;

  static TestcaseDir create(const std::filesystem::path& p);
};

// Copy testcase into target_dir using name derived from parent.
void copy_testcase(const std::filesystem::path& testcase,
                   TestcaseDir& target_dir,
                   const std::filesystem::path& parent);

// Score function: higher is better.
struct TestcaseScore {
  int semantic_tier = 0;
  bool new_coverage = false;
  bool derived_from_seed = false;
  long long neg_file_size = -(1LL << 62);
  std::string base_name;

  // Lexicographical comparison, matching Rust's derived Ord on the same fields.
  bool operator<(const TestcaseScore& o) const {
    if (semantic_tier != o.semantic_tier) return semantic_tier < o.semantic_tier;
    if (new_coverage != o.new_coverage) return new_coverage < o.new_coverage;
    if (derived_from_seed != o.derived_from_seed) return derived_from_seed < o.derived_from_seed;
    if (neg_file_size != o.neg_file_size) return neg_file_size < o.neg_file_size;
    return base_name < o.base_name;
  }
  bool operator>(const TestcaseScore& o) const { return o < *this; }
};

TestcaseScore score_testcase(const std::filesystem::path& p, int semantic_tier = 0);

}  // namespace symcc_fuzzing
