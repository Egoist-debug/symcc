// InputPrefix.h - Input prefix data structure for grammar mining
//
// This file is part of the SymCC gen_input tool.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GENINPUT_INPUTPREFIX_H
#define GENINPUT_INPUTPREFIX_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <z3++.h>

namespace geninput {

/// Represents a constraint collected during symbolic execution.
/// Each constraint corresponds to a branch condition in the parser.
struct Constraint {
  z3::expr Expression;  // Z3 expression for this constraint
  bool Taken;           // Whether this branch was taken
  uintptr_t SiteId;     // Unique identifier for the branch site

  Constraint(z3::expr Expr, bool Taken, uintptr_t SiteId)
      : Expression(std::move(Expr)), Taken(Taken), SiteId(SiteId) {}
};

/// Represents the state of input generation at a point in the exploration.
/// Contains the current input prefix and its associated path constraints.
class InputPrefix {
public:
  /// Create an empty prefix.
  explicit InputPrefix(z3::context &Ctx);

  /// Create a prefix from raw bytes.
  InputPrefix(z3::context &Ctx, const std::vector<uint8_t> &Data);

  /// Create a prefix from a string.
  InputPrefix(z3::context &Ctx, const std::string &Data);

  /// Copy constructor (deep copy of constraints).
  InputPrefix(const InputPrefix &Other);

  /// Move constructor.
  InputPrefix(InputPrefix &&Other) noexcept;

  /// Copy assignment.
  InputPrefix &operator=(const InputPrefix &Other);

  /// Move assignment.
  InputPrefix &operator=(InputPrefix &&Other) noexcept;

  ~InputPrefix() = default;

  /// Get the current input data.
  const std::vector<uint8_t> &getData() const { return Data_; }

  /// Get the input as a string.
  std::string getDataAsString() const;

  /// Get the length of the input.
  size_t length() const { return Data_.size(); }

  /// Append a byte to the input.
  void appendByte(uint8_t Byte);

  /// Append a string to the input.
  void appendString(const std::string &Str);

  /// Append raw bytes to the input.
  void appendBytes(const std::vector<uint8_t> &Bytes);

  /// Get the path constraints.
  const std::vector<Constraint> &getConstraints() const { return Constraints_; }

  /// Add a constraint to the path.
  void addConstraint(z3::expr Expr, bool Taken, uintptr_t SiteId);

  /// Clear all constraints (but keep input data).
  void clearConstraints();

  /// Get the function call depth at which this prefix was created.
  size_t getCallDepth() const { return CallDepth_; }

  /// Set the function call depth.
  void setCallDepth(size_t Depth) { CallDepth_ = Depth; }

  /// Get the function name associated with this prefix (for stem tracking).
  const std::optional<std::string> &getFunctionName() const {
    return FunctionName_;
  }

  /// Set the function name.
  void setFunctionName(const std::string &Name) { FunctionName_ = Name; }

  /// Check if this prefix is marked as complete (reached acceptance).
  bool isComplete() const { return IsComplete_; }

  /// Mark this prefix as complete.
  void markComplete() { IsComplete_ = true; }

  /// Check if this prefix is a stem (partial result for modular expansion).
  bool isStem() const { return IsStem_; }

  /// Mark this prefix as a stem.
  void markAsStem() { IsStem_ = true; }

  /// Clone this prefix (deep copy).
  std::unique_ptr<InputPrefix> clone() const;

  /// Create a symbolic byte variable for the given position.
  z3::expr createSymbolicByte(size_t Position);

  /// Get the Z3 context.
  z3::context &getContext() { return Ctx_; }

private:
  z3::context &Ctx_;
  std::vector<uint8_t> Data_;
  std::vector<Constraint> Constraints_;
  size_t CallDepth_ = 0;
  std::optional<std::string> FunctionName_;
  bool IsComplete_ = false;
  bool IsStem_ = false;
};

/// Represents a queue of input prefixes to explore.
/// Used by the three-phase algorithm.
class PrefixQueue {
public:
  explicit PrefixQueue(size_t MaxSize = 0);

  /// Add a prefix to the queue.
  void push(std::unique_ptr<InputPrefix> Prefix);

  /// Get and remove the next prefix.
  std::unique_ptr<InputPrefix> pop();

  /// Check if the queue is empty.
  bool empty() const { return Queue_.empty(); }

  /// Get the current size of the queue.
  size_t size() const { return Queue_.size(); }

  /// Set the maximum queue size (0 = unlimited).
  void setMaxSize(size_t MaxSize) { MaxSize_ = MaxSize; }

  /// Check if the queue is bounded.
  bool isBounded() const { return MaxSize_ > 0; }

private:
  std::vector<std::unique_ptr<InputPrefix>> Queue_;
  size_t MaxSize_;
};

} // namespace geninput

#endif // GENINPUT_INPUTPREFIX_H
