// PlaceholderEngine.h - Placeholder technique implementation
//
// This file is part of the SymCC gen_input tool.
//
// Implements the placeholder technique from:
// "Generating Inputs for Grammar Mining using Dynamic Symbolic Execution"
// (Pointner et al., 2025)
//
// The technique works by:
// 1. Appending an invalid placeholder character ('~') to a valid prefix
// 2. Running symbolic execution to capture rejection constraints
// 3. Negating the rejection constraints to find valid next characters
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GENINPUT_PLACEHOLDERENGINE_H
#define GENINPUT_PLACEHOLDERENGINE_H

#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ConstraintManager.h"
#include "InputPrefix.h"

namespace geninput {

/// Callback invoked when symbolic execution hits a branch.
/// Returns the constraint expression and whether the branch was taken.
using BranchCallback = std::function<void(z3::expr, bool, uintptr_t)>;

/// Callback invoked when a function is called.
using CallCallback = std::function<void(const std::string &, uintptr_t)>;

/// Callback invoked when a function returns.
using RetCallback = std::function<void(uintptr_t)>;

/// Configuration for the placeholder engine.
struct PlaceholderConfig {
  uint8_t PlaceholderChar = '~';   // Character to use as placeholder
  bool OnlyPrintable = true;       // Only generate printable characters
  size_t MaxInputLength = 1024;    // Maximum input length
  unsigned SolverTimeoutMs = 5000; // Z3 solver timeout
};

/// Result of extending a prefix with new characters.
struct ExtensionResult {
  std::vector<std::unique_ptr<InputPrefix>> NewPrefixes;
  bool ReachedAcceptance = false; // True if parser accepted current prefix
  bool ReachedRejection = false;  // True if parser rejected (no valid next)
  std::string ErrorMsg;           // Error message if something went wrong
};

/// Implements the placeholder technique for finding valid parser inputs.
class PlaceholderEngine {
public:
  /// Create an engine with default configuration.
  PlaceholderEngine();

  /// Create an engine with custom configuration.
  explicit PlaceholderEngine(PlaceholderConfig Config);

  ~PlaceholderEngine() = default;

  /// Get the constraint manager.
  ConstraintManager &getConstraintManager() { return ConstraintMgr_; }

  /// Get the configuration.
  const PlaceholderConfig &getConfig() const { return Config_; }

  /// Set the configuration.
  void setConfig(PlaceholderConfig Config) { Config_ = std::move(Config); }

  /// Find all valid next characters for a prefix.
  /// This is the core placeholder technique:
  /// 1. Create prefix + placeholder input
  /// 2. Run symbolic execution
  /// 3. Collect constraints that reject the placeholder
  /// 4. Negate constraints to find valid characters
  std::set<uint8_t> findValidNextChars(const InputPrefix &Prefix);

  /// Extend a prefix with all valid next characters.
  /// Returns new prefixes for each valid continuation.
  ExtensionResult extendPrefix(const InputPrefix &Prefix);

  /// Check if the current prefix is accepted by the parser.
  /// This requires running the parser and checking for acceptance.
  bool isAccepted(const InputPrefix &Prefix);

  /// Collect constraints during symbolic execution.
  /// Called by the SymCC integration layer.
  void onBranch(z3::expr Constraint, bool Taken, uintptr_t SiteId);

  /// Called when entering a function.
  void onFunctionCall(const std::string &FuncName, uintptr_t SiteId);

  /// Called when returning from a function.
  void onFunctionReturn(uintptr_t SiteId);

  /// Clear collected constraints (between runs).
  void clearCollectedConstraints();

  /// Get collected constraints from the last run.
  const std::vector<Constraint> &getCollectedConstraints() const {
    return CollectedConstraints_;
  }

  /// Set the branch callback for constraint collection.
  void setBranchCallback(BranchCallback Cb) { BranchCb_ = std::move(Cb); }

  /// Set the function call callback.
  void setCallCallback(CallCallback Cb) { CallCb_ = std::move(Cb); }

  /// Set the function return callback.
  void setRetCallback(RetCallback Cb) { RetCb_ = std::move(Cb); }

  /// Statistics about the engine's operation.
  struct Stats {
    size_t TotalExtensions = 0;
    size_t SuccessfulExtensions = 0;
    size_t AcceptedInputs = 0;
    size_t RejectedInputs = 0;
    size_t TotalCharsFound = 0;
  };

  const Stats &getStats() const { return Stats_; }

  void resetStats();

private:
  PlaceholderConfig Config_;
  ConstraintManager ConstraintMgr_;
  std::vector<Constraint> CollectedConstraints_;
  size_t CurrentCallDepth_ = 0;

  BranchCallback BranchCb_;
  CallCallback CallCb_;
  RetCallback RetCb_;

  Stats Stats_;

  /// Filter characters to only printable ones if configured.
  std::set<uint8_t> filterChars(const std::set<uint8_t> &Chars);
};

} // namespace geninput

#endif // GENINPUT_PLACEHOLDERENGINE_H
