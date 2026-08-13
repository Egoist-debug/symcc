#include "dnslab_core/experiment_config.hpp"

#include <cstdlib>
#include <stdexcept>
#include <string>

namespace {

void clearEnvironment() {
  ::unsetenv("SEED_TIMEOUT_SEC");
  ::unsetenv("FOLLOW_DIFF_REPEAT_COUNT");
  ::unsetenv("ENABLE_DST1_MUTATOR");
  ::unsetenv("ENABLE_CACHE_DELTA");
  ::unsetenv("ENABLE_TRIAGE");
  ::unsetenv("ENABLE_SYMCC");
}

void require(bool Condition, const std::string &Message) {
  if (!Condition) {
    throw std::runtime_error(Message);
  }
}

} // namespace

int main() {
  clearEnvironment();
  require(dnslab::resolveSeedTimeoutSec() == 5, "default timeout mismatch");

  auto Config = dnslab::resolveAblationConfig();
  require(Config.variantName() == "no_mutator", "default variant mismatch");
  require(Config.status().at("mutator") == "off",
          "default mutator status mismatch");
  require(Config.status().at("cache-delta") == "on",
          "default cache-delta status mismatch");

  ::setenv("ENABLE_DST1_MUTATOR", "1", 1);
  Config = dnslab::resolveAblationConfig();
  require(Config.variantName() == "full_stack", "full variant mismatch");

  ::setenv("ENABLE_SYMCC", "0", 1);
  Config = dnslab::resolveAblationConfig();
  require(Config.variantName() == "afl_only", "AFL-only variant mismatch");

  ::setenv("ENABLE_SYMCC", "1", 1);
  ::setenv("ENABLE_CACHE_DELTA", "0", 1);
  Config = dnslab::resolveAblationConfig();
  require(Config.variantName() == "no_cache_delta",
          "no-cache-delta variant mismatch");

  ::setenv("ENABLE_TRIAGE", "0", 1);
  Config = dnslab::resolveAblationConfig();
  require(Config.variantName() ==
              "custom-mutator-on-cache-delta-off-triage-off-symcc-on",
          "custom variant mismatch");

  ::setenv("SEED_TIMEOUT_SEC", "7", 1);
  require(dnslab::resolveSeedTimeoutSec() == 7,
          "configured timeout mismatch");
  ::setenv("SEED_TIMEOUT_SEC", "invalid", 1);
  bool InvalidTimeoutRejected = false;
  try {
    (void)dnslab::resolveSeedTimeoutSec();
  } catch (const std::runtime_error &) {
    InvalidTimeoutRejected = true;
  }
  require(InvalidTimeoutRejected, "invalid timeout was accepted");

  require(dnslab::resolveRepeatCount() == 1, "default repeat count mismatch");
  ::setenv("FOLLOW_DIFF_REPEAT_COUNT", "5", 1);
  require(dnslab::resolveRepeatCount() == 5,
          "configured repeat count mismatch");
  ::setenv("FOLLOW_DIFF_REPEAT_COUNT", "0", 1);
  bool InvalidRepeatRejected = false;
  try {
    (void)dnslab::resolveRepeatCount();
  } catch (const std::runtime_error &) {
    InvalidRepeatRejected = true;
  }
  require(InvalidRepeatRejected, "invalid repeat count was accepted");

  clearEnvironment();
  return 0;
}
