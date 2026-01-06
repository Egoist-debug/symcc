// SPDX-License-Identifier: GPL-3.0-or-later

#include "ConstraintManager.h"
#include <chrono>

namespace geninput {

namespace {
constexpr unsigned kDefaultTimeoutMs = 5000;
}

ConstraintManager::ConstraintManager()
    : Solver_(Ctx_), TimeoutMs_(kDefaultTimeoutMs) {
  Solver_.set("timeout", TimeoutMs_);
}

ConstraintManager::ConstraintManager(unsigned TimeoutMs)
    : Solver_(Ctx_), TimeoutMs_(TimeoutMs) {
  Solver_.set("timeout", TimeoutMs_);
}

z3::expr ConstraintManager::createSymbolicByte(const std::string &Name) {
  return Ctx_.bv_const(Name.c_str(), 8);
}

z3::expr ConstraintManager::createInputByte(size_t Position) {
  return createSymbolicByte("input_" + std::to_string(Position));
}

z3::expr ConstraintManager::buildEq(z3::expr Byte, uint8_t Value) {
  return Byte == Ctx_.bv_val(Value, 8);
}

z3::expr ConstraintManager::buildNeq(z3::expr Byte, uint8_t Value) {
  return Byte != Ctx_.bv_val(Value, 8);
}

z3::expr ConstraintManager::buildInRange(z3::expr Byte, uint8_t Low,
                                         uint8_t High) {
  return z3::uge(Byte, Ctx_.bv_val(Low, 8)) &&
         z3::ule(Byte, Ctx_.bv_val(High, 8));
}

z3::expr ConstraintManager::buildNotInRange(z3::expr Byte, uint8_t Low,
                                            uint8_t High) {
  return z3::ult(Byte, Ctx_.bv_val(Low, 8)) ||
         z3::ugt(Byte, Ctx_.bv_val(High, 8));
}

z3::expr ConstraintManager::buildPrintable(z3::expr Byte) {
  return buildInRange(Byte, 0x20, 0x7E);
}

SolveResult ConstraintManager::solve(const std::vector<z3::expr> &Constraints,
                                     size_t NumInputBytes) {
  auto Start = std::chrono::high_resolution_clock::now();
  Stats_.TotalQueries++;

  Solver_.reset();
  for (const auto &C : Constraints) {
    Solver_.add(C);
  }

  z3::check_result Result = Solver_.check();

  auto End = std::chrono::high_resolution_clock::now();
  Stats_.TotalTimeMs +=
      std::chrono::duration<double, std::milli>(End - Start).count();

  if (Result == z3::sat) {
    Stats_.SatQueries++;
    z3::model Model = Solver_.get_model();
    return SolveResult::Sat(extractModel(Model, NumInputBytes));
  } else if (Result == z3::unsat) {
    Stats_.UnsatQueries++;
    return SolveResult::Unsat();
  } else {
    Stats_.TimeoutQueries++;
    return SolveResult::Error("Solver timeout or unknown");
  }
}

SolveResult ConstraintManager::solve(const InputPrefix &Prefix) {
  std::vector<z3::expr> Exprs;
  Exprs.reserve(Prefix.getConstraints().size());
  for (const auto &C : Prefix.getConstraints()) {
    if (C.Taken) {
      Exprs.push_back(C.Expression);
    } else {
      Exprs.push_back(!C.Expression);
    }
  }
  return solve(Exprs, Prefix.length());
}

SolveResult ConstraintManager::solveNegated(const InputPrefix &Prefix) {
  const auto &Constraints = Prefix.getConstraints();
  if (Constraints.empty()) {
    return SolveResult::Unsat();
  }

  std::vector<z3::expr> Exprs;
  Exprs.reserve(Constraints.size());

  for (size_t I = 0; I < Constraints.size() - 1; ++I) {
    const auto &C = Constraints[I];
    if (C.Taken) {
      Exprs.push_back(C.Expression);
    } else {
      Exprs.push_back(!C.Expression);
    }
  }

  const auto &Last = Constraints.back();
  if (Last.Taken) {
    Exprs.push_back(!Last.Expression);
  } else {
    Exprs.push_back(Last.Expression);
  }

  return solve(Exprs, Prefix.length());
}

std::set<uint8_t>
ConstraintManager::findValidNextChars(const InputPrefix &Prefix,
                                      uint8_t Placeholder) {
  std::set<uint8_t> ValidChars;

  std::vector<z3::expr> BaseConstraints;
  for (const auto &C : Prefix.getConstraints()) {
    if (C.Taken) {
      BaseConstraints.push_back(C.Expression);
    } else {
      BaseConstraints.push_back(!C.Expression);
    }
  }

  z3::expr NextByte = createInputByte(Prefix.length());

  for (int Ch = 0; Ch < 256; ++Ch) {
    if (static_cast<uint8_t>(Ch) == Placeholder) {
      continue;
    }

    std::vector<z3::expr> TestConstraints = BaseConstraints;
    TestConstraints.push_back(buildEq(NextByte, static_cast<uint8_t>(Ch)));

    if (isSatisfiable(TestConstraints)) {
      ValidChars.insert(static_cast<uint8_t>(Ch));
    }
  }

  return ValidChars;
}

bool ConstraintManager::isSatisfiable(const std::vector<z3::expr> &Constraints) {
  Solver_.reset();
  for (const auto &C : Constraints) {
    Solver_.add(C);
  }
  return Solver_.check() == z3::sat;
}

void ConstraintManager::setTimeout(unsigned TimeoutMs) {
  TimeoutMs_ = TimeoutMs;
  Solver_.set("timeout", TimeoutMs_);
}

void ConstraintManager::resetStats() { Stats_ = Stats{}; }

std::vector<uint8_t> ConstraintManager::extractModel(z3::model &Model,
                                                     size_t NumInputBytes) {
  std::vector<uint8_t> Result(NumInputBytes, 0);

  for (size_t I = 0; I < NumInputBytes; ++I) {
    std::string Name = "input_" + std::to_string(I);
    z3::expr Var = Ctx_.bv_const(Name.c_str(), 8);
    z3::expr Val = Model.eval(Var, true);

    if (Val.is_numeral()) {
      Result[I] = static_cast<uint8_t>(Val.get_numeral_uint());
    }
  }

  return Result;
}

}
