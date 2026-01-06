// ConstraintManager.h - Z3 constraint management and solving
//
// This file is part of the SymCC gen_input tool.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GENINPUT_CONSTRAINTMANAGER_H
#define GENINPUT_CONSTRAINTMANAGER_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <z3++.h>

#include "InputPrefix.h"

namespace geninput {

/// Result of constraint solving.
struct SolveResult {
  bool IsSat;                   // Whether the constraints are satisfiable
  std::vector<uint8_t> Model;   // Concrete values for symbolic bytes (if sat)
  std::string ErrorMsg;         // Error message (if error occurred)

  static SolveResult Sat(std::vector<uint8_t> Model) {
    return {true, std::move(Model), ""};
  }

  static SolveResult Unsat() { return {false, {}, ""}; }

  static SolveResult Error(std::string Msg) {
    return {false, {}, std::move(Msg)};
  }
};

/// Manages Z3 constraints and performs solving operations.
/// Central component for the placeholder technique.
class ConstraintManager {
public:
  /// Create a constraint manager with default timeout.
  ConstraintManager();

  /// Create a constraint manager with specified timeout (milliseconds).
  explicit ConstraintManager(unsigned TimeoutMs);

  ~ConstraintManager() = default;

  /// Get the Z3 context.
  z3::context &getContext() { return Ctx_; }

  /// Create a symbolic byte variable.
  z3::expr createSymbolicByte(const std::string &Name);

  /// Create a symbolic byte for input position.
  z3::expr createInputByte(size_t Position);

  /// Build constraint: byte equals concrete value.
  z3::expr buildEq(z3::expr Byte, uint8_t Value);

  /// Build constraint: byte not equals concrete value.
  z3::expr buildNeq(z3::expr Byte, uint8_t Value);

  /// Build constraint: byte is in range [Low, High].
  z3::expr buildInRange(z3::expr Byte, uint8_t Low, uint8_t High);

  /// Build constraint: byte is NOT in range [Low, High].
  z3::expr buildNotInRange(z3::expr Byte, uint8_t Low, uint8_t High);

  /// Build constraint: byte is printable ASCII (0x20-0x7E).
  z3::expr buildPrintable(z3::expr Byte);

  /// Solve constraints and return a model if satisfiable.
  /// The model contains concrete values for all symbolic input bytes.
  SolveResult solve(const std::vector<z3::expr> &Constraints,
                    size_t NumInputBytes);

  /// Solve constraints from an InputPrefix.
  SolveResult solve(const InputPrefix &Prefix);

  /// Negate the last constraint and solve.
  /// This is the core of the placeholder technique.
  SolveResult solveNegated(const InputPrefix &Prefix);

  /// Find all valid next characters for a given prefix.
  /// Uses the placeholder technique: appends placeholder, captures rejection
  /// constraints, negates to find valid chars.
  std::set<uint8_t> findValidNextChars(const InputPrefix &Prefix,
                                       uint8_t Placeholder = '~');

  /// Check if constraints are satisfiable (without extracting model).
  bool isSatisfiable(const std::vector<z3::expr> &Constraints);

  /// Set solver timeout in milliseconds.
  void setTimeout(unsigned TimeoutMs);

  /// Get statistics about solving.
  struct Stats {
    size_t TotalQueries = 0;
    size_t SatQueries = 0;
    size_t UnsatQueries = 0;
    size_t TimeoutQueries = 0;
    double TotalTimeMs = 0.0;
  };

  const Stats &getStats() const { return Stats_; }

  /// Reset statistics.
  void resetStats();

private:
  z3::context Ctx_;
  z3::solver Solver_;
  unsigned TimeoutMs_;
  Stats Stats_;

  /// Extract model values for input bytes.
  std::vector<uint8_t> extractModel(z3::model &Model, size_t NumInputBytes);
};

} // namespace geninput

#endif // GENINPUT_CONSTRAINTMANAGER_H
