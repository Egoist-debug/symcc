// SymCCIntegration.h - Interface with SymCC runtime
//
// This file is part of the SymCC gen_input tool.
//
// Provides hooks into the SymCC runtime to:
// - Intercept path constraints
// - Track function calls
// - Inject symbolic inputs
// - Execute instrumented programs
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GENINPUT_SYMCCINTEGRATION_H
#define GENINPUT_SYMCCINTEGRATION_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <z3++.h>

namespace geninput {

// Forward declarations
class PlaceholderEngine;
class InputPrefix;

/// Callback for constraint collection.
using ConstraintCallback =
    std::function<void(z3::expr, bool /*taken*/, uintptr_t /*site_id*/)>;

/// Callback for function call tracking.
using FunctionCallCallback =
    std::function<void(const std::string & /*name*/, uintptr_t /*site_id*/)>;

/// Callback for function return tracking.
using FunctionReturnCallback = std::function<void(uintptr_t /*site_id*/)>;

/// Result of executing a program with symbolic input.
struct ExecutionResult {
  bool Success;                  // Execution completed successfully
  int ExitCode;                  // Program exit code
  bool Accepted;                 // Parser accepted the input
  std::string Stdout;            // Captured stdout
  std::string Stderr;            // Captured stderr
  std::string ErrorMsg;          // Error message if !Success

  static ExecutionResult Ok(int ExitCode, bool Accepted) {
    return {true, ExitCode, Accepted, "", "", ""};
  }

  static ExecutionResult Failure(std::string Msg) {
    return {false, -1, false, "", "", std::move(Msg)};
  }
};

/// Configuration for SymCC integration.
struct SymCCConfig {
  std::string ProgramPath;          // Path to instrumented program
  std::string OutputDir;            // Directory for generated inputs
  std::vector<std::string> Args;    // Additional program arguments
  size_t TimeoutSec = 30;           // Execution timeout
  bool CaptureStdout = true;        // Capture program stdout
  bool CaptureStderr = true;        // Capture program stderr
  bool UseStdin = true;             // Provide input via stdin (vs file)
  std::string InputFile;            // Input file path (if !UseStdin)
};

/// Integration layer between gen_input and SymCC runtime.
/// Handles execution of instrumented programs and constraint collection.
class SymCCIntegration {
public:
  /// Create integration with default configuration.
  SymCCIntegration();

  /// Create integration with custom configuration.
  explicit SymCCIntegration(SymCCConfig Config);

  ~SymCCIntegration();

  /// Get the configuration.
  const SymCCConfig &getConfig() const { return Config_; }

  /// Set the configuration.
  void setConfig(SymCCConfig Config) { Config_ = std::move(Config); }

  /// Set the Z3 context to use for constraint building.
  void setContext(z3::context *Ctx) { Ctx_ = Ctx; }

  /// Set callback for constraint collection.
  void setConstraintCallback(ConstraintCallback Cb) {
    ConstraintCb_ = std::move(Cb);
  }

  /// Set callback for function call tracking.
  void setFunctionCallCallback(FunctionCallCallback Cb) {
    FunctionCallCb_ = std::move(Cb);
  }

  /// Set callback for function return tracking.
  void setFunctionReturnCallback(FunctionReturnCallback Cb) {
    FunctionReturnCb_ = std::move(Cb);
  }

  /// Execute the program with the given input.
  /// Collects constraints via the registered callbacks.
  ExecutionResult execute(const std::vector<uint8_t> &Input);

  /// Execute the program with input from an InputPrefix.
  ExecutionResult execute(const InputPrefix &Prefix);

  /// Execute the program with a string input.
  ExecutionResult execute(const std::string &Input);

  /// Check if the program accepts the given input.
  /// This is a simplified check based on exit code.
  bool isAccepted(const std::vector<uint8_t> &Input);

  /// Get the path to the instrumented program.
  const std::string &getProgramPath() const { return Config_.ProgramPath; }

  /// Set the path to the instrumented program.
  void setProgramPath(const std::string &Path) { Config_.ProgramPath = Path; }

  /// Set additional program arguments.
  void setArgs(std::vector<std::string> Args) {
    Config_.Args = std::move(Args);
  }

  /// Initialize the SymCC runtime.
  /// Must be called before any execution.
  bool initialize();

  /// Cleanup the SymCC runtime.
  void cleanup();

  /// Check if the runtime is initialized.
  bool isInitialized() const { return Initialized_; }

  /// Statistics about executions.
  struct Stats {
    size_t TotalExecutions = 0;
    size_t SuccessfulExecutions = 0;
    size_t FailedExecutions = 0;
    size_t TimeoutExecutions = 0;
    size_t AcceptedInputs = 0;
    size_t RejectedInputs = 0;
    double TotalExecutionTimeMs = 0.0;
  };

  const Stats &getStats() const { return Stats_; }

  void resetStats();

private:
  SymCCConfig Config_;
  z3::context *Ctx_ = nullptr;
  bool Initialized_ = false;

  ConstraintCallback ConstraintCb_;
  FunctionCallCallback FunctionCallCb_;
  FunctionReturnCallback FunctionReturnCb_;

  Stats Stats_;

  /// Write input to file or prepare for stdin.
  bool prepareInput(const std::vector<uint8_t> &Input, std::string &InputPath);

  /// Parse SymCC output for generated test cases.
  std::vector<std::vector<uint8_t>> parseGeneratedInputs();
};

/// Global hooks for SymCC runtime callbacks.
/// These are called by the modified SymCC runtime.
namespace hooks {

/// Initialize hooks with callbacks.
void initialize(ConstraintCallback OnConstraint,
                FunctionCallCallback OnCall,
                FunctionReturnCallback OnReturn);

/// Cleanup hooks.
void cleanup();

/// Called by SymCC when a path constraint is pushed.
void onPathConstraint(void *Expr, bool Taken, uintptr_t SiteId);

/// Called by SymCC when a function is called.
void onFunctionCall(const char *Name, uintptr_t SiteId);

/// Called by SymCC when a function returns.
void onFunctionReturn(uintptr_t SiteId);

/// Get the current Z3 context from hooks.
z3::context *getContext();

/// Set the Z3 context for hooks.
void setContext(z3::context *Ctx);

} // namespace hooks

} // namespace geninput

#endif // GENINPUT_SYMCCINTEGRATION_H
