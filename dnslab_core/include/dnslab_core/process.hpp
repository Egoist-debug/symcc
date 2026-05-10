#pragma once

#include "dnslab_core/resolver_adapter.hpp"

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace dnslab {

struct ProcessRequest {
  std::vector<std::string> Arguments;
  std::optional<std::filesystem::path> WorkingDirectory;
  std::map<std::string, std::string> Environment;
  std::optional<std::filesystem::path> StdinFile;
};

CommandResult runProcess(const ProcessRequest &Request);

} // namespace dnslab
