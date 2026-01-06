// ThreePhaseGenerator.h - Three-phase algorithm for grammar mining
//
// This file is part of the SymCC gen_input tool.
//
// Implements the three-phase algorithm from:
// "Generating Inputs for Grammar Mining using Dynamic Symbolic Execution"
// (Pointner et al., 2025)
//
// Phase 1: Initialization
//   - Collect function prefixes from initial exploration
//   - Build initial stems for each grammar function
//
// Phase 2: Modular Expansion
//   - For each function call, inject pre-calculated stems
//   - Avoids exponential path explosion in recursive grammars
//
// Phase 3: Completion
//   - Bound the queue to force input completion
//   - Generate final valid inputs
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GENINPUT_THREEPHASEGENERATOR_H
#define GENINPUT_THREEPHASEGENERATOR_H

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "InputPrefix.h"
#include "PlaceholderEngine.h"

namespace geninput {

/// Configuration for the three-phase generator.
struct GeneratorConfig {
  size_t MaxInputLength = 1024;       // Maximum length for generated inputs
  size_t MaxQueueSize = 1000;         // Maximum queue size in phase 3
  size_t MaxStemsPerFunction = 10;    // Maximum stems to keep per function
  size_t MaxIterations = 10000;       // Maximum iterations before stopping
  unsigned SolverTimeoutMs = 5000;    // Z3 solver timeout
  bool OnlyPrintable = true;          // Only generate printable characters
  bool VerboseLogging = false;        // Enable verbose output
};

/// A stem is a partial input that represents a valid production of a grammar
/// rule. Stems are collected during Phase 1 and injected during Phase 2.
struct Stem {
  std::string FunctionName;          // Grammar function this stem belongs to
  std::vector<uint8_t> Data;         // The partial input data
  std::vector<Constraint> Constraints; // Constraints collected for this stem
  size_t EntryDepth;                 // Call depth when entering function
  size_t ExitDepth;                  // Call depth when exiting function

  Stem(std::string FuncName, std::vector<uint8_t> Data, size_t EntryDepth)
      : FunctionName(std::move(FuncName)), Data(std::move(Data)),
        EntryDepth(EntryDepth), ExitDepth(EntryDepth) {}
};

/// Callback for reporting generated inputs.
using InputCallback = std::function<void(const std::vector<uint8_t> &)>;

/// Callback for progress reporting.
using ProgressCallback = std::function<void(size_t, size_t, size_t)>;

/// Three-phase generator for systematic input generation.
class ThreePhaseGenerator {
public:
  /// Create a generator with default configuration.
  ThreePhaseGenerator();

  /// Create a generator with custom configuration.
  explicit ThreePhaseGenerator(GeneratorConfig Config);

  ~ThreePhaseGenerator() = default;

  /// Get the configuration.
  const GeneratorConfig &getConfig() const { return Config_; }

  /// Set the configuration.
  void setConfig(GeneratorConfig Config) { Config_ = std::move(Config); }

  /// Get the placeholder engine.
  PlaceholderEngine &getEngine() { return Engine_; }

  /// Set callback for generated inputs.
  void setInputCallback(InputCallback Cb) { InputCb_ = std::move(Cb); }

  /// Set callback for progress reporting.
  void setProgressCallback(ProgressCallback Cb) { ProgressCb_ = std::move(Cb); }

  /// Run the three-phase algorithm.
  /// Returns all valid inputs generated.
  std::vector<std::vector<uint8_t>> run();

  /// Run only Phase 1: Initialization.
  /// Collects function stems from initial exploration.
  void runPhase1();

  /// Run only Phase 2: Modular Expansion.
  /// Uses collected stems to avoid path explosion.
  void runPhase2();

  /// Run only Phase 3: Completion.
  /// Bounds the queue to force input completion.
  void runPhase3();

  /// Add an initial seed input.
  void addSeed(const std::vector<uint8_t> &Seed);

  /// Add an initial seed input from string.
  void addSeed(const std::string &Seed);

  /// Get collected stems for a function.
  const std::vector<Stem> &getStemsForFunction(const std::string &FuncName);

  /// Get all collected stems.
  const std::map<std::string, std::vector<Stem>> &getAllStems() const {
    return Stems_;
  }

  /// Get all generated valid inputs.
  const std::vector<std::vector<uint8_t>> &getGeneratedInputs() const {
    return GeneratedInputs_;
  }

  /// Clear all state (stems, inputs, queue).
  void reset();

  /// Statistics about the generation process.
  struct Stats {
    size_t Phase1Iterations = 0;
    size_t Phase2Iterations = 0;
    size_t Phase3Iterations = 0;
    size_t TotalStemsCollected = 0;
    size_t TotalInputsGenerated = 0;
    size_t StemInjections = 0;
    size_t QueueBoundHits = 0;
    double TotalTimeMs = 0.0;
  };

  const Stats &getStats() const { return Stats_; }

  void resetStats();

private:
  GeneratorConfig Config_;
  PlaceholderEngine Engine_;
  PrefixQueue Queue_;
  std::map<std::string, std::vector<Stem>> Stems_;
  std::vector<std::vector<uint8_t>> GeneratedInputs_;
  std::set<std::vector<uint8_t>> SeenInputs_; // Deduplication

  InputCallback InputCb_;
  ProgressCallback ProgressCb_;

  Stats Stats_;

  // Phase tracking
  enum class Phase { Init, Phase1, Phase2, Phase3, Done };
  Phase CurrentPhase_ = Phase::Init;

  // Current function call stack for stem tracking
  std::vector<std::pair<std::string, size_t>> CallStack_;

  /// Process a single prefix from the queue.
  void processPrefix(std::unique_ptr<InputPrefix> Prefix);

  /// Record a stem for the current function.
  void recordStem(const InputPrefix &Prefix, const std::string &FuncName);

  /// Inject stems when entering a known function.
  std::vector<std::unique_ptr<InputPrefix>>
  injectStems(const InputPrefix &Prefix, const std::string &FuncName);

  /// Report progress.
  void reportProgress();

  /// Check if we should stop (max iterations reached, etc.).
  bool shouldStop() const;

  /// Add a generated input (with deduplication).
  void addGeneratedInput(const std::vector<uint8_t> &Input);

  /// Handle function call during exploration.
  void onFunctionCall(const std::string &FuncName, size_t CallDepth);

  /// Handle function return during exploration.
  void onFunctionReturn(size_t CallDepth);
};

} // namespace geninput

#endif // GENINPUT_THREEPHASEGENERATOR_H
