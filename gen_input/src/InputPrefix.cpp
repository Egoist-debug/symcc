// SPDX-License-Identifier: GPL-3.0-or-later

#include "InputPrefix.h"

namespace geninput {

InputPrefix::InputPrefix(z3::context &Ctx) : Ctx_(Ctx) {}

InputPrefix::InputPrefix(z3::context &Ctx, const std::vector<uint8_t> &Data)
    : Ctx_(Ctx), Data_(Data) {}

InputPrefix::InputPrefix(z3::context &Ctx, const std::string &Data)
    : Ctx_(Ctx), Data_(Data.begin(), Data.end()) {}

InputPrefix::InputPrefix(const InputPrefix &Other)
    : Ctx_(Other.Ctx_), Data_(Other.Data_), CallDepth_(Other.CallDepth_),
      FunctionName_(Other.FunctionName_), IsComplete_(Other.IsComplete_),
      IsStem_(Other.IsStem_) {
  Constraints_.reserve(Other.Constraints_.size());
  for (const auto &C : Other.Constraints_) {
    Constraints_.emplace_back(C.Expression, C.Taken, C.SiteId);
  }
}

InputPrefix::InputPrefix(InputPrefix &&Other) noexcept
    : Ctx_(Other.Ctx_), Data_(std::move(Other.Data_)),
      Constraints_(std::move(Other.Constraints_)),
      CallDepth_(Other.CallDepth_),
      FunctionName_(std::move(Other.FunctionName_)),
      IsComplete_(Other.IsComplete_), IsStem_(Other.IsStem_) {}

InputPrefix &InputPrefix::operator=(const InputPrefix &Other) {
  if (this != &Other) {
    Data_ = Other.Data_;
    Constraints_.clear();
    Constraints_.reserve(Other.Constraints_.size());
    for (const auto &C : Other.Constraints_) {
      Constraints_.emplace_back(C.Expression, C.Taken, C.SiteId);
    }
    CallDepth_ = Other.CallDepth_;
    FunctionName_ = Other.FunctionName_;
    IsComplete_ = Other.IsComplete_;
    IsStem_ = Other.IsStem_;
  }
  return *this;
}

InputPrefix &InputPrefix::operator=(InputPrefix &&Other) noexcept {
  if (this != &Other) {
    Data_ = std::move(Other.Data_);
    Constraints_ = std::move(Other.Constraints_);
    CallDepth_ = Other.CallDepth_;
    FunctionName_ = std::move(Other.FunctionName_);
    IsComplete_ = Other.IsComplete_;
    IsStem_ = Other.IsStem_;
  }
  return *this;
}

std::string InputPrefix::getDataAsString() const {
  return std::string(Data_.begin(), Data_.end());
}

void InputPrefix::appendByte(uint8_t Byte) { Data_.push_back(Byte); }

void InputPrefix::appendString(const std::string &Str) {
  Data_.insert(Data_.end(), Str.begin(), Str.end());
}

void InputPrefix::appendBytes(const std::vector<uint8_t> &Bytes) {
  Data_.insert(Data_.end(), Bytes.begin(), Bytes.end());
}

void InputPrefix::addConstraint(z3::expr Expr, bool Taken, uintptr_t SiteId) {
  Constraints_.emplace_back(std::move(Expr), Taken, SiteId);
}

void InputPrefix::clearConstraints() { Constraints_.clear(); }

std::unique_ptr<InputPrefix> InputPrefix::clone() const {
  return std::make_unique<InputPrefix>(*this);
}

z3::expr InputPrefix::createSymbolicByte(size_t Position) {
  std::string Name = "input_" + std::to_string(Position);
  return Ctx_.bv_const(Name.c_str(), 8);
}

PrefixQueue::PrefixQueue(size_t MaxSize) : MaxSize_(MaxSize) {}

void PrefixQueue::push(std::unique_ptr<InputPrefix> Prefix) {
  if (MaxSize_ > 0 && Queue_.size() >= MaxSize_) {
    return;
  }
  Queue_.push_back(std::move(Prefix));
}

std::unique_ptr<InputPrefix> PrefixQueue::pop() {
  if (Queue_.empty()) {
    return nullptr;
  }
  auto Prefix = std::move(Queue_.back());
  Queue_.pop_back();
  return Prefix;
}

}
