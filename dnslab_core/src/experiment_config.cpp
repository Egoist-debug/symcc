#include "dnslab_core/experiment_config.hpp"

#include <cstdlib>
#include <sstream>
#include <stdexcept>

namespace dnslab {

namespace {

bool resolveToggle(const char *Name, bool DefaultValue) {
  const char *Value = std::getenv(Name);
  return Value == nullptr ? DefaultValue : std::string(Value) == "1";
}

std::string statusValue(bool Enabled) { return Enabled ? "on" : "off"; }

} // namespace

std::string AblationConfig::variantName() const {
  if (Mutator && CacheDelta && Triage && Symcc) {
    return "full_stack";
  }
  if (Mutator && CacheDelta && Triage && !Symcc) {
    return "afl_only";
  }
  if (!Mutator && CacheDelta && Triage && Symcc) {
    return "no_mutator";
  }
  if (Mutator && !CacheDelta && Triage && Symcc) {
    return "no_cache_delta";
  }

  std::ostringstream Output;
  Output << "custom-"
         << "mutator-" << statusValue(Mutator) << "-"
         << "cache-delta-" << statusValue(CacheDelta) << "-"
         << "triage-" << statusValue(Triage) << "-"
         << "symcc-" << statusValue(Symcc);
  return Output.str();
}

std::map<std::string, std::string> AblationConfig::status() const {
  return {{"mutator", statusValue(Mutator)},
          {"cache-delta", statusValue(CacheDelta)},
          {"triage", statusValue(Triage)},
          {"symcc", statusValue(Symcc)}};
}

int resolveSeedTimeoutSec() {
  const char *Value = std::getenv("SEED_TIMEOUT_SEC");
  if (Value == nullptr || *Value == '\0') {
    return 5;
  }
  try {
    const int Parsed = std::stoi(Value);
    if (Parsed > 0) {
      return Parsed;
    }
  } catch (const std::exception &) {
  }
  throw std::runtime_error("SEED_TIMEOUT_SEC 必须是正整数");
}

int resolveRepeatCount() {
  const char *Value = std::getenv("FOLLOW_DIFF_REPEAT_COUNT");
  if (Value == nullptr || *Value == '\0') {
    return 1;
  }
  try {
    const int Parsed = std::stoi(Value);
    if (Parsed > 0) {
      return Parsed;
    }
  } catch (const std::exception &) {
  }
  throw std::runtime_error("FOLLOW_DIFF_REPEAT_COUNT 必须是正整数");
}

AblationConfig resolveAblationConfig() {
  AblationConfig Output;
  Output.Mutator = resolveToggle("ENABLE_DST1_MUTATOR", false);
  Output.CacheDelta = resolveToggle("ENABLE_CACHE_DELTA", true);
  Output.Triage = resolveToggle("ENABLE_TRIAGE", true);
  Output.Symcc = resolveToggle("ENABLE_SYMCC", true);
  return Output;
}

} // namespace dnslab
