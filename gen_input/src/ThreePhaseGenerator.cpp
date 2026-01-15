// SPDX-License-Identifier: GPL-3.0-or-later

#include "ThreePhaseGenerator.h"
#include <chrono>

namespace geninput {

namespace {
const std::vector<Stem> kEmptyStems;
}

ThreePhaseGenerator::ThreePhaseGenerator() {
  PlaceholderConfig EngineConfig;
  EngineConfig.MaxInputLength = Config_.MaxInputLength;
  EngineConfig.OnlyPrintable = Config_.OnlyPrintable;
  EngineConfig.SolverTimeoutMs = Config_.SolverTimeoutMs;
  Engine_.setConfig(EngineConfig);
}

ThreePhaseGenerator::ThreePhaseGenerator(GeneratorConfig Config)
    : Config_(std::move(Config)) {
  PlaceholderConfig EngineConfig;
  EngineConfig.MaxInputLength = Config_.MaxInputLength;
  EngineConfig.OnlyPrintable = Config_.OnlyPrintable;
  EngineConfig.SolverTimeoutMs = Config_.SolverTimeoutMs;
  Engine_.setConfig(EngineConfig);
}

std::vector<std::vector<uint8_t>> ThreePhaseGenerator::run() {
  auto Start = std::chrono::high_resolution_clock::now();

  runPhase1();
  runPhase2();
  runPhase3();

  auto End = std::chrono::high_resolution_clock::now();
  Stats_.TotalTimeMs =
      std::chrono::duration<double, std::milli>(End - Start).count();

  CurrentPhase_ = Phase::Done;
  return GeneratedInputs_;
}

void ThreePhaseGenerator::runPhase1() {
  CurrentPhase_ = Phase::Phase1;

  while (!Queue_.empty() && !shouldStopPhase1()) {
    auto Prefix = Queue_.pop();
    if (!Prefix) break;

    Stats_.Phase1Iterations++;
    processPrefixPhase1(std::move(Prefix));
    reportProgress();
  }

  while (!Queue_.empty()) {
    auto Prefix = Queue_.pop();
    if (Prefix) {
      Phase2Queue_.push(std::move(Prefix));
    }
  }
}

void ThreePhaseGenerator::runPhase2() {
  CurrentPhase_ = Phase::Phase2;

  while (!Phase2Queue_.empty()) {
    auto Prefix = Phase2Queue_.pop();
    if (Prefix) {
      Queue_.push(std::move(Prefix));
    }
  }

  while (!Queue_.empty() && !shouldStopPhase2()) {
    auto Prefix = Queue_.pop();
    if (!Prefix) break;

    Stats_.Phase2Iterations++;

    if (Prefix->getFunctionName()) {
      const std::string &FuncName = *Prefix->getFunctionName();
      const auto &FuncStems = getStemsForFunction(FuncName);

      if (!FuncStems.empty()) {
        auto InjectedPrefixes = injectStems(*Prefix, FuncName);
        for (auto &P : InjectedPrefixes) {
          Queue_.push(std::move(P));
          Stats_.StemInjections++;
        }
        continue;
      }
    }

    processPrefixPhase2And3(std::move(Prefix));
    reportProgress();
  }
}

void ThreePhaseGenerator::runPhase3() {
  CurrentPhase_ = Phase::Phase3;
  Queue_.setMaxSize(Config_.MaxQueueSize);

  while (!Queue_.empty() && !shouldStopPhase3()) {
    auto Prefix = Queue_.pop();
    if (!Prefix) break;

    Stats_.Phase3Iterations++;

    if (Queue_.isBounded() && Queue_.size() >= Config_.MaxQueueSize) {
      Stats_.QueueBoundHits++;
    }

    processPrefixPhase2And3(std::move(Prefix));
    reportProgress();
  }
}

void ThreePhaseGenerator::addSeed(const std::vector<uint8_t> &Seed) {
  auto Prefix = std::make_unique<InputPrefix>(
      Engine_.getConstraintManager().getContext(), Seed);
  Queue_.push(std::move(Prefix));
}

void ThreePhaseGenerator::addSeed(const std::string &Seed) {
  addSeed(std::vector<uint8_t>(Seed.begin(), Seed.end()));
}

const std::vector<Stem> &
ThreePhaseGenerator::getStemsForFunction(const std::string &FuncName) {
  auto It = Stems_.find(FuncName);
  if (It != Stems_.end()) {
    return It->second;
  }
  return kEmptyStems;
}

void ThreePhaseGenerator::reset() {
  while (!Queue_.empty()) {
    Queue_.pop();
  }
  while (!Phase2Queue_.empty()) {
    Phase2Queue_.pop();
  }
  Stems_.clear();
  GeneratedInputs_.clear();
  SeenInputs_.clear();
  CallStack_.clear();
  CurrentPhase_ = Phase::Init;
}

void ThreePhaseGenerator::resetStats() { Stats_ = Stats{}; }

void ThreePhaseGenerator::processPrefixPhase1(std::unique_ptr<InputPrefix> Prefix) {
  if (isAcceptedByParser(Prefix->getData())) {
    addGeneratedInput(Prefix->getData());
  }

  auto TestCases = runSymCCAndCollectTestCases(Prefix->getData());

  if (TestCases.empty()) {
    return;
  }

  if (Prefix->getFunctionName()) {
    recordStem(*Prefix, *Prefix->getFunctionName());
  }

  for (const auto &TestCase : TestCases) {
    if (TestCase.size() > Config_.MaxInputLength) {
      continue;
    }

    bool AlreadySeen = (SeenInputs_.count(TestCase) > 0);
    SeenInputs_.insert(TestCase);

    if (!AlreadySeen && isAcceptedByParser(TestCase)) {
      GeneratedInputs_.push_back(TestCase);
      Stats_.TotalInputsGenerated++;
      if (InputCb_) {
        InputCb_(TestCase);
      }
    }

    if (!AlreadySeen) {
      auto NewPrefix = std::make_unique<InputPrefix>(
          Engine_.getConstraintManager().getContext(), TestCase);
      Queue_.push(std::move(NewPrefix));
    }
  }
}

void ThreePhaseGenerator::processPrefixPhase2And3(std::unique_ptr<InputPrefix> Prefix) {
  if (isAcceptedByParser(Prefix->getData())) {
    addGeneratedInput(Prefix->getData());
  }

  auto TestCases = runSymCCAndCollectTestCases(Prefix->getData());

  if (TestCases.empty()) {
    return;
  }

  for (const auto &TestCase : TestCases) {
    if (TestCase.size() > Config_.MaxInputLength) {
      continue;
    }

    bool AlreadySeen = (SeenInputs_.count(TestCase) > 0);
    SeenInputs_.insert(TestCase);

    if (!AlreadySeen && isAcceptedByParser(TestCase)) {
      GeneratedInputs_.push_back(TestCase);
      Stats_.TotalInputsGenerated++;
      if (InputCb_) {
        InputCb_(TestCase);
      }
    }

    if (!AlreadySeen) {
      auto NewPrefix = std::make_unique<InputPrefix>(
          Engine_.getConstraintManager().getContext(), TestCase);
      Queue_.push(std::move(NewPrefix));
    }
  }
}

std::set<uint8_t> ThreePhaseGenerator::runSymCCAndFindExtensions(
    const std::vector<uint8_t> &Input) {

  if (!Runner_) {
    auto Prefix = std::make_unique<InputPrefix>(
        Engine_.getConstraintManager().getContext(), Input);
    return Engine_.findValidNextChars(*Prefix);
  }

  Stats_.SymCCRuns++;
  return Runner_->findValidExtensions(Input, Config_.PlaceholderChar);
}

std::vector<std::vector<uint8_t>> ThreePhaseGenerator::runSymCCAndCollectTestCases(
    const std::vector<uint8_t> &Input) {

  if (!Runner_) {
    return {};
  }

  Stats_.SymCCRuns++;
  auto Result = Runner_->run(Input);
  return Result.GeneratedTestCases;
}

bool ThreePhaseGenerator::isAcceptedByParser(const std::vector<uint8_t> &Input) {
  if (!Runner_) {
    auto Prefix = std::make_unique<InputPrefix>(
        Engine_.getConstraintManager().getContext(), Input);
    return Engine_.isAccepted(*Prefix);
  }

  return Runner_->isAccepted(Input);
}

void ThreePhaseGenerator::recordStem(const InputPrefix &Prefix,
                                      const std::string &FuncName) {
  auto &FuncStems = Stems_[FuncName];

  if (FuncStems.size() >= Config_.MaxStemsPerFunction) {
    return;
  }

  Stem NewStem(FuncName, Prefix.getData(), Prefix.getCallDepth());

  for (const auto &C : Prefix.getConstraints()) {
    NewStem.Constraints.emplace_back(C.Expression, C.Taken, C.SiteId);
  }

  FuncStems.push_back(std::move(NewStem));
  Stats_.TotalStemsCollected++;
}

std::vector<std::unique_ptr<InputPrefix>>
ThreePhaseGenerator::injectStems(const InputPrefix &Prefix,
                                  const std::string &FuncName) {
  std::vector<std::unique_ptr<InputPrefix>> Result;

  const auto &FuncStems = getStemsForFunction(FuncName);
  for (const auto &S : FuncStems) {
    auto NewPrefix = Prefix.clone();
    NewPrefix->appendBytes(S.Data);

    for (const auto &C : S.Constraints) {
      NewPrefix->addConstraint(C.Expression, C.Taken, C.SiteId);
    }

    Result.push_back(std::move(NewPrefix));
  }

  return Result;
}

void ThreePhaseGenerator::reportProgress() {
  if (ProgressCb_) {
    size_t TotalIter = Stats_.Phase1Iterations + Stats_.Phase2Iterations +
                       Stats_.Phase3Iterations;
    ProgressCb_(TotalIter, Queue_.size(), GeneratedInputs_.size());
  }
}

bool ThreePhaseGenerator::shouldStopPhase1() const {
  return Stats_.Phase1Iterations >= Config_.Phase1MaxIterations;
}

bool ThreePhaseGenerator::shouldStopPhase2() const {
  return Stats_.Phase2Iterations >= Config_.Phase2MaxIterations;
}

bool ThreePhaseGenerator::shouldStopPhase3() const {
  size_t TotalIter = Stats_.Phase1Iterations + Stats_.Phase2Iterations +
                     Stats_.Phase3Iterations;
  return TotalIter >= Config_.MaxIterations;
}

void ThreePhaseGenerator::addGeneratedInput(const std::vector<uint8_t> &Input) {
  if (SeenInputs_.count(Input) > 0) {
    return;
  }

  SeenInputs_.insert(Input);
  GeneratedInputs_.push_back(Input);
  Stats_.TotalInputsGenerated++;

  if (InputCb_) {
    InputCb_(Input);
  }
}

void ThreePhaseGenerator::onFunctionCall(const std::string &FuncName,
                                          size_t CallDepth) {
  CallStack_.emplace_back(FuncName, CallDepth);
}

void ThreePhaseGenerator::onFunctionReturn(size_t CallDepth) {
  while (!CallStack_.empty() && CallStack_.back().second >= CallDepth) {
    CallStack_.pop_back();
  }
}

}
