#include "PlaceholderEngine.h"

namespace geninput {

PlaceholderEngine::PlaceholderEngine()
    : ConstraintMgr_(Config_.SolverTimeoutMs) {}

PlaceholderEngine::PlaceholderEngine(PlaceholderConfig Config)
    : Config_(std::move(Config)), ConstraintMgr_(Config_.SolverTimeoutMs) {}

std::set<uint8_t> PlaceholderEngine::findValidNextChars(const InputPrefix &Prefix) {
  if (Prefix.length() >= Config_.MaxInputLength) {
    return {};
  }

  auto ValidChars = ConstraintMgr_.findValidNextChars(Prefix, Config_.PlaceholderChar);

  if (Config_.OnlyPrintable) {
    ValidChars = filterChars(ValidChars);
  }

  Stats_.TotalCharsFound += ValidChars.size();
  return ValidChars;
}

ExtensionResult PlaceholderEngine::extendPrefix(const InputPrefix &Prefix) {
  ExtensionResult Result;
  Stats_.TotalExtensions++;

  if (Prefix.length() >= Config_.MaxInputLength) {
    Result.ReachedRejection = true;
    return Result;
  }

  auto ValidChars = findValidNextChars(Prefix);

  if (ValidChars.empty()) {
    if (isAccepted(Prefix)) {
      Result.ReachedAcceptance = true;
      Stats_.AcceptedInputs++;
    } else {
      Result.ReachedRejection = true;
      Stats_.RejectedInputs++;
    }
    return Result;
  }

  Stats_.SuccessfulExtensions++;

  for (uint8_t Ch : ValidChars) {
    auto NewPrefix = Prefix.clone();
    NewPrefix->appendByte(Ch);
    Result.NewPrefixes.push_back(std::move(NewPrefix));
  }

  return Result;
}

bool PlaceholderEngine::isAccepted(const InputPrefix &Prefix) {
  (void)Prefix;
  return false;
}

void PlaceholderEngine::onBranch(z3::expr Constraint, bool Taken,
                                  uintptr_t SiteId) {
  CollectedConstraints_.emplace_back(std::move(Constraint), Taken, SiteId);

  if (BranchCb_) {
    BranchCb_(CollectedConstraints_.back().Expression,
              CollectedConstraints_.back().Taken,
              CollectedConstraints_.back().SiteId);
  }
}

void PlaceholderEngine::onFunctionCall(const std::string &FuncName,
                                        uintptr_t SiteId) {
  CurrentCallDepth_++;
  if (CallCb_) {
    CallCb_(FuncName, SiteId);
  }
}

void PlaceholderEngine::onFunctionReturn(uintptr_t SiteId) {
  if (CurrentCallDepth_ > 0) {
    CurrentCallDepth_--;
  }
  if (RetCb_) {
    RetCb_(SiteId);
  }
}

void PlaceholderEngine::clearCollectedConstraints() {
  CollectedConstraints_.clear();
  CurrentCallDepth_ = 0;
}

void PlaceholderEngine::resetStats() { Stats_ = Stats{}; }

std::set<uint8_t> PlaceholderEngine::filterChars(const std::set<uint8_t> &Chars) {
  std::set<uint8_t> Filtered;
  for (uint8_t Ch : Chars) {
    if (Ch >= 0x20 && Ch <= 0x7E) {
      Filtered.insert(Ch);
    }
  }
  return Filtered;
}

} // namespace geninput
