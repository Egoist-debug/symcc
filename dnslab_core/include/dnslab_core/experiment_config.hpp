#pragma once

#include <map>
#include <string>

namespace dnslab {

struct AblationConfig {
  bool Mutator = false;
  bool CacheDelta = true;
  bool Triage = true;
  bool Symcc = true;

  std::string variantName() const;
  std::map<std::string, std::string> status() const;
};

int resolveSeedTimeoutSec();
AblationConfig resolveAblationConfig();

} // namespace dnslab
