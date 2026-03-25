#include "testcase.hpp"

#include <filesystem>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace symcc_fuzzing {

std::string canonicalize_testcase_path(
    const std::filesystem::path& p,
    const std::optional<std::filesystem::path>& base_dir) {
  std::filesystem::path candidate = p;
  if (candidate.is_relative() && base_dir.has_value()) {
    candidate = *base_dir / candidate;
  }

  std::error_code ec;
  const auto abs = std::filesystem::absolute(candidate, ec);
  if (ec) return candidate.lexically_normal().string();

  const auto normalized = std::filesystem::weakly_canonical(abs, ec);
  if (ec) return abs.lexically_normal().string();
  return normalized.string();
}

TestcaseDir TestcaseDir::create(const std::filesystem::path& p) {
  std::error_code ec;
  if (!std::filesystem::create_directory(p, ec)) {
    if (ec) throw std::runtime_error("Failed to create directory: " + p.string());
  }
  TestcaseDir d;
  d.path = p;
  d.next_id = 0;
  return d;
}

static std::string filename(const std::filesystem::path& p) {
  return p.filename().string();
}

void copy_testcase(const std::filesystem::path& testcase,
                   TestcaseDir& target_dir,
                   const std::filesystem::path& parent) {
  const auto orig_name = filename(parent);
  if (orig_name.rfind("id:", 0) != 0 || orig_name.size() < 9) {
    throw std::runtime_error("Parent testcase name does not start with id: " + orig_name);
  }
  const std::string orig_id = orig_name.substr(3, 6);

  std::ostringstream new_name;
  new_name << "id:";
  new_name << std::setw(6) << std::setfill('0') << target_dir.next_id;
  new_name << ",src:" << orig_id;

  auto dst = target_dir.path / new_name.str();
  std::error_code ec;
  std::filesystem::copy_file(testcase, dst, std::filesystem::copy_options::overwrite_existing, ec);
  if (ec) {
    throw std::runtime_error("Failed to copy testcase to " + dst.string() + ": " + ec.message());
  }
  target_dir.next_id += 1;
}

TestcaseScore score_testcase(const std::filesystem::path& p, int semantic_tier) {
  TestcaseScore s;
  s.semantic_tier = semantic_tier;
  std::error_code ec;
  auto sz = std::filesystem::file_size(p, ec);
  if (ec) return s;

  const auto name = filename(p);
  s.base_name = name;
  s.new_coverage = name.size() >= 4 && name.rfind("+cov") == name.size() - 4;
  s.derived_from_seed = (name.find("orig:") != std::string::npos);
  s.neg_file_size = -static_cast<long long>(sz);
  return s;
}

}  // namespace symcc_fuzzing
