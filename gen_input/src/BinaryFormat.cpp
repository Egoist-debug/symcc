// BinaryFormat.cpp - Binary format specification implementation
//
// This file is part of the SymCC gen_input tool.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../include/BinaryFormat.h"

#include <algorithm>
#include <unordered_map>
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace geninput {

namespace {

std::optional<size_t> getBoundedFieldSize(const FieldDef &Field);

std::optional<size_t> getBoundedStructSize(const std::vector<FieldDef> &Fields) {
  size_t TotalSize = 0;
  for (const auto &Child : Fields) {
    auto ChildSize = getBoundedFieldSize(Child);
    if (!ChildSize) {
      return std::nullopt;
    }
    TotalSize += *ChildSize;
  }
  return TotalSize;
}

std::optional<size_t> getBoundedFieldSize(const FieldDef &Field) {
  switch (Field.Type) {
  case FieldType::UInt8:
  case FieldType::Int8:
    return 1;
  case FieldType::UInt16:
  case FieldType::Int16:
    return 2;
  case FieldType::UInt32:
  case FieldType::Int32:
    return 4;
  case FieldType::IPv4Addr:
    return 4;
  case FieldType::IPv6Addr:
    return 16;
  case FieldType::FixedBytes:
  case FieldType::Padding:
    return Field.Size;
  case FieldType::Struct:
    return getBoundedStructSize(Field.Children);
  case FieldType::VarBytes:
  case FieldType::Array:
  case FieldType::DNSName:
  case FieldType::DNSRR:
  case FieldType::Union:
  case FieldType::LengthPrefix:
    return std::nullopt;
  default:
    if (Field.Size > 0) {
      return Field.Size;
    }
    return std::nullopt;
  }
}

std::optional<uint64_t> parseIntegerFieldValue(const FieldDef &Field,
                                               const std::vector<uint8_t> &Input,
                                               size_t Offset) {
  switch (Field.Type) {
  case FieldType::UInt8:
  case FieldType::Int8:
    if (Offset >= Input.size()) {
      return std::nullopt;
    }
    return static_cast<uint64_t>(Input[Offset]);
  case FieldType::UInt16:
  case FieldType::Int16:
    if (Offset + 1 >= Input.size()) {
      return std::nullopt;
    }
    if (Field.Endian == ByteOrder::Big) {
      return (static_cast<uint64_t>(Input[Offset]) << 8) |
             static_cast<uint64_t>(Input[Offset + 1]);
    }
    return static_cast<uint64_t>(Input[Offset]) |
           (static_cast<uint64_t>(Input[Offset + 1]) << 8);
  case FieldType::UInt32:
  case FieldType::Int32:
    if (Offset + 3 >= Input.size()) {
      return std::nullopt;
    }
    if (Field.Endian == ByteOrder::Big) {
      return (static_cast<uint64_t>(Input[Offset]) << 24) |
             (static_cast<uint64_t>(Input[Offset + 1]) << 16) |
             (static_cast<uint64_t>(Input[Offset + 2]) << 8) |
             static_cast<uint64_t>(Input[Offset + 3]);
    }
    return static_cast<uint64_t>(Input[Offset]) |
           (static_cast<uint64_t>(Input[Offset + 1]) << 8) |
           (static_cast<uint64_t>(Input[Offset + 2]) << 16) |
           (static_cast<uint64_t>(Input[Offset + 3]) << 24);
  default:
    return std::nullopt;
  }
}

std::optional<size_t> consumeDNSNameBytes(const std::vector<uint8_t> &Input,
                                          size_t Offset) {
  size_t Cursor = Offset;
  while (Cursor < Input.size()) {
    const uint8_t Len = Input[Cursor];
    if (Len == 0) {
      return Cursor + 1 - Offset;
    }
    if ((Len & 0xC0) == 0xC0) {
      if (Cursor + 1 >= Input.size()) {
        return std::nullopt;
      }
      return Cursor + 2 - Offset;
    }
    if (Cursor + 1 + Len > Input.size()) {
      return std::nullopt;
    }
    Cursor += 1 + Len;
  }
  return std::nullopt;
}

std::optional<size_t>
consumeFieldBytes(const FieldDef &Field, const std::vector<uint8_t> &Input,
                  size_t Offset,
                  std::unordered_map<std::string, uint64_t> &NumericValues) {
  switch (Field.Type) {
  case FieldType::UInt8:
  case FieldType::Int8:
  case FieldType::UInt16:
  case FieldType::Int16:
  case FieldType::UInt32:
  case FieldType::Int32: {
    auto Value = parseIntegerFieldValue(Field, Input, Offset);
    if (!Value) {
      return std::nullopt;
    }
    NumericValues[Field.Name] = *Value;
    return getBoundedFieldSize(Field);
  }
  case FieldType::IPv4Addr:
    if (Offset + 4 > Input.size()) {
      return std::nullopt;
    }
    return 4;
  case FieldType::IPv6Addr:
    if (Offset + 16 > Input.size()) {
      return std::nullopt;
    }
    return 16;
  case FieldType::FixedBytes:
  case FieldType::Padding:
    if (Offset + Field.Size > Input.size()) {
      return std::nullopt;
    }
    return Field.Size;
  case FieldType::DNSName:
    return consumeDNSNameBytes(Input, Offset);
  case FieldType::VarBytes: {
    if (!Field.LengthField) {
      return std::nullopt;
    }
    const auto It = NumericValues.find(*Field.LengthField);
    if (It == NumericValues.end()) {
      return std::nullopt;
    }
    const uint64_t Length = It->second;
    if (Length > static_cast<uint64_t>(Input.size() - Offset)) {
      return std::nullopt;
    }
    return static_cast<size_t>(Length);
  }
  case FieldType::Struct: {
    auto LocalValues = NumericValues;
    size_t Cursor = Offset;
    for (const auto &Child : Field.Children) {
      auto ChildSize = consumeFieldBytes(Child, Input, Cursor, LocalValues);
      if (!ChildSize) {
        return std::nullopt;
      }
      Cursor += *ChildSize;
    }
    return Cursor - Offset;
  }
  case FieldType::Array: {
    if (Field.Children.empty()) {
      return 0;
    }
    if (!Field.CountField) {
      return std::nullopt;
    }
    const auto It = NumericValues.find(*Field.CountField);
    if (It == NumericValues.end()) {
      return std::nullopt;
    }
    size_t Cursor = Offset;
    for (uint64_t Index = 0; Index < It->second; ++Index) {
      auto ElementValues = NumericValues;
      auto ElementSize =
          consumeFieldBytes(Field.Children.front(), Input, Cursor, ElementValues);
      if (!ElementSize) {
        return std::nullopt;
      }
      Cursor += *ElementSize;
    }
    return Cursor - Offset;
  }
  default:
    if (Field.Size > 0 && Offset + Field.Size <= Input.size()) {
      return Field.Size;
    }
    return std::nullopt;
  }
}

}

//===----------------------------------------------------------------------===//
// FieldConstraint Implementation
//===----------------------------------------------------------------------===//

FieldConstraint FieldConstraint::Range(uint64_t Min, uint64_t Max) {
  FieldConstraint C;
  C.ConstraintType = Type::Range;
  C.Value = std::vector<uint64_t>{Min, Max};
  return C;
}

FieldConstraint FieldConstraint::Equals(uint64_t Value) {
  FieldConstraint C;
  C.ConstraintType = Type::Equals;
  C.Value = Value;
  return C;
}

FieldConstraint FieldConstraint::NotEquals(uint64_t Value) {
  FieldConstraint C;
  C.ConstraintType = Type::NotEquals;
  C.Value = Value;
  return C;
}

FieldConstraint FieldConstraint::OneOf(std::vector<uint64_t> Values) {
  FieldConstraint C;
  C.ConstraintType = Type::OneOf;
  C.Value = std::move(Values);
  return C;
}

FieldConstraint FieldConstraint::Bitmask(uint64_t Mask, uint64_t Expected) {
  FieldConstraint C;
  C.ConstraintType = Type::Bitmask;
  C.Value = std::vector<uint64_t>{Mask, Expected};
  return C;
}

FieldConstraint FieldConstraint::LessThanField(const std::string &FieldName) {
  FieldConstraint C;
  C.ConstraintType = Type::LessThan;
  C.DependentField = FieldName;
  return C;
}

FieldConstraint FieldConstraint::GreaterThanField(const std::string &FieldName) {
  FieldConstraint C;
  C.ConstraintType = Type::GreaterThan;
  C.DependentField = FieldName;
  return C;
}

//===----------------------------------------------------------------------===//
// FieldDef Factory Methods
//===----------------------------------------------------------------------===//

FieldDef FieldDef::U8(const std::string &Name) {
  FieldDef F;
  F.Name = Name;
  F.Type = FieldType::UInt8;
  F.Size = 1;
  F.Endian = ByteOrder::Big; // Doesn't matter for single byte
  return F;
}

FieldDef FieldDef::U16(const std::string &Name, ByteOrder Endian) {
  FieldDef F;
  F.Name = Name;
  F.Type = FieldType::UInt16;
  F.Size = 2;
  F.Endian = Endian;
  return F;
}

FieldDef FieldDef::U32(const std::string &Name, ByteOrder Endian) {
  FieldDef F;
  F.Name = Name;
  F.Type = FieldType::UInt32;
  F.Size = 4;
  F.Endian = Endian;
  return F;
}

FieldDef FieldDef::Bytes(const std::string &Name, size_t Size) {
  FieldDef F;
  F.Name = Name;
  F.Type = FieldType::FixedBytes;
  F.Size = Size;
  F.Endian = ByteOrder::Big;
  return F;
}

FieldDef FieldDef::VarLen(const std::string &Name, const std::string &LengthField) {
  FieldDef F;
  F.Name = Name;
  F.Type = FieldType::VarBytes;
  F.Size = 0; // Variable
  F.Endian = ByteOrder::Big;
  F.LengthField = LengthField;
  return F;
}

FieldDef FieldDef::Struct(const std::string &Name, std::vector<FieldDef> Fields) {
  FieldDef F;
  F.Name = Name;
  F.Type = FieldType::Struct;
  F.Size = 0; // Calculated from children
  F.Endian = ByteOrder::Big;
  F.Children = std::move(Fields);
  return F;
}

FieldDef FieldDef::Array(const std::string &Name, FieldDef Element,
                          const std::string &CountField) {
  FieldDef F;
  F.Name = Name;
  F.Type = FieldType::Array;
  F.Size = 0; // Variable
  F.Endian = ByteOrder::Big;
  F.CountField = CountField;
  F.Children.push_back(std::move(Element));
  return F;
}

FieldDef FieldDef::Pad(size_t Size) {
  FieldDef F;
  F.Name = "_padding";
  F.Type = FieldType::Padding;
  F.Size = Size;
  F.Endian = ByteOrder::Big;
  F.IsSymbolic = false;
  return F;
}

//===----------------------------------------------------------------------===//
// BinaryFormat Implementation
//===----------------------------------------------------------------------===//

BinaryFormat::BinaryFormat(const std::string &Name) : Name_(Name) {}

void BinaryFormat::addField(FieldDef Field) {
  Fields_.push_back(std::move(Field));
}

const FieldDef *BinaryFormat::findField(const std::string &Path) const {
  return findFieldRecursive(Fields_, Path);
}

const FieldDef *
BinaryFormat::findFieldRecursive(const std::vector<FieldDef> &Fields,
                                  const std::string &Path) const {
  // Split path by '.'
  size_t DotPos = Path.find('.');
  std::string FirstPart = (DotPos != std::string::npos) ? Path.substr(0, DotPos) : Path;
  std::string Rest = (DotPos != std::string::npos) ? Path.substr(DotPos + 1) : "";

  for (const auto &F : Fields) {
    if (F.Name == FirstPart) {
      if (Rest.empty()) {
        return &F;
      }
      return findFieldRecursive(F.Children, Rest);
    }
  }
  return nullptr;
}

size_t BinaryFormat::getMinSize() const {
  size_t Size = 0;
  for (const auto &F : Fields_) {
    if (F.IsOptional)
      continue;

    switch (F.Type) {
    case FieldType::UInt8:
    case FieldType::Int8:
      Size += 1;
      break;
    case FieldType::UInt16:
    case FieldType::Int16:
      Size += 2;
      break;
    case FieldType::UInt32:
    case FieldType::Int32:
      Size += 4;
      break;
    case FieldType::FixedBytes:
    case FieldType::Padding:
      Size += F.Size;
      break;
    case FieldType::Struct: {
      // Calculate struct size recursively
      BinaryFormat Nested;
      for (const auto &Child : F.Children) {
        Nested.addField(Child);
      }
      Size += Nested.getMinSize();
      break;
    }
    default:
      // Variable-length fields don't contribute to minimum size
      break;
    }
  }
  return Size;
}

std::optional<size_t> BinaryFormat::getMaxSize() const {
  size_t Size = 0;
  for (const auto &F : Fields_) {
    auto FieldSize = getBoundedFieldSize(F);
    if (!FieldSize) {
      return std::nullopt;
    }
    Size += *FieldSize;
  }
  return Size;
}

std::vector<uint8_t> BinaryFormat::createSeed() const {
  std::vector<uint8_t> Result;
  Result.reserve(getMinSize());

  for (const auto &F : Fields_) {
    if (F.IsOptional)
      continue;

    uint64_t Value = F.DefaultValue.value_or(F.FixedValue.value_or(0));

    switch (F.Type) {
    case FieldType::UInt8:
    case FieldType::Int8:
      Result.push_back(static_cast<uint8_t>(Value));
      break;

    case FieldType::UInt16:
    case FieldType::Int16:
      if (F.Endian == ByteOrder::Big) {
        Result.push_back(static_cast<uint8_t>((Value >> 8) & 0xFF));
        Result.push_back(static_cast<uint8_t>(Value & 0xFF));
      } else {
        Result.push_back(static_cast<uint8_t>(Value & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 8) & 0xFF));
      }
      break;

    case FieldType::UInt32:
    case FieldType::Int32:
      if (F.Endian == ByteOrder::Big) {
        Result.push_back(static_cast<uint8_t>((Value >> 24) & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 16) & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 8) & 0xFF));
        Result.push_back(static_cast<uint8_t>(Value & 0xFF));
      } else {
        Result.push_back(static_cast<uint8_t>(Value & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 8) & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 16) & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 24) & 0xFF));
      }
      break;

    case FieldType::FixedBytes:
    case FieldType::Padding:
      for (size_t I = 0; I < F.Size; ++I) {
        Result.push_back(0);
      }
      break;

    case FieldType::Struct:
      // Recursively create seed for nested struct
      {
        BinaryFormat Nested;
        for (const auto &Child : F.Children) {
          Nested.addField(Child);
        }
        auto NestedSeed = Nested.createSeed();
        Result.insert(Result.end(), NestedSeed.begin(), NestedSeed.end());
      }
      break;

    case FieldType::VarBytes: {
      size_t Length = 0;
      if (F.LengthField) {
        if (const auto *LengthField = findField(*F.LengthField)) {
          Length = static_cast<size_t>(
              LengthField->DefaultValue.value_or(LengthField->FixedValue.value_or(0)));
        }
      }
      Result.insert(Result.end(), Length, 0);
      break;
    }

    case FieldType::Array: {
      if (F.Children.empty()) {
        break;
      }

      size_t Count = 0;
      if (F.CountField) {
        if (const auto *CountField = findField(*F.CountField)) {
          Count = CountField->DefaultValue.value_or(0);
        }
      }

      BinaryFormat ElementFormat;
      ElementFormat.addField(F.Children.front());
      auto ElementSeed = ElementFormat.createSeed();
      for (size_t Index = 0; Index < Count; ++Index) {
        Result.insert(Result.end(), ElementSeed.begin(), ElementSeed.end());
      }
      break;
    }

    case FieldType::DNSName:
      // RFC 1035: length-prefixed labels, null-terminated. Minimum valid = 1-char label "a"
      Result.push_back(0x01);
      Result.push_back('a');
      Result.push_back(0x00);
      break;

    default:
      // Variable-length fields: add nothing in minimal seed
      break;
    }
  }

  return Result;
}

std::vector<uint8_t>
BinaryFormat::createSeed(const std::vector<std::pair<std::string, uint64_t>> &Values) const {
  // Start with default seed
  auto Result = createSeed();

  // Apply specified values
  for (const auto &[Name, Value] : Values) {
    auto Offset = getFieldOffset(Name);
    if (!Offset)
      continue;

    const auto *Field = findField(Name);
    if (!Field)
      continue;

    size_t Pos = *Offset;

    switch (Field->Type) {
    case FieldType::UInt8:
    case FieldType::Int8:
      if (Pos < Result.size()) {
        Result[Pos] = static_cast<uint8_t>(Value);
      }
      break;

    case FieldType::UInt16:
    case FieldType::Int16:
      if (Pos + 1 < Result.size()) {
        if (Field->Endian == ByteOrder::Big) {
          Result[Pos] = static_cast<uint8_t>((Value >> 8) & 0xFF);
          Result[Pos + 1] = static_cast<uint8_t>(Value & 0xFF);
        } else {
          Result[Pos] = static_cast<uint8_t>(Value & 0xFF);
          Result[Pos + 1] = static_cast<uint8_t>((Value >> 8) & 0xFF);
        }
      }
      break;

    case FieldType::UInt32:
    case FieldType::Int32:
      if (Pos + 3 < Result.size()) {
        if (Field->Endian == ByteOrder::Big) {
          Result[Pos] = static_cast<uint8_t>((Value >> 24) & 0xFF);
          Result[Pos + 1] = static_cast<uint8_t>((Value >> 16) & 0xFF);
          Result[Pos + 2] = static_cast<uint8_t>((Value >> 8) & 0xFF);
          Result[Pos + 3] = static_cast<uint8_t>(Value & 0xFF);
        } else {
          Result[Pos] = static_cast<uint8_t>(Value & 0xFF);
          Result[Pos + 1] = static_cast<uint8_t>((Value >> 8) & 0xFF);
          Result[Pos + 2] = static_cast<uint8_t>((Value >> 16) & 0xFF);
          Result[Pos + 3] = static_cast<uint8_t>((Value >> 24) & 0xFF);
        }
      }
      break;

    default:
      break;
    }
  }

  return Result;
}

std::optional<size_t> BinaryFormat::getFieldOffset(const std::string &FieldName) const {
  size_t Offset = 0;

  for (const auto &F : Fields_) {
    if (F.Name == FieldName) {
      return Offset;
    }

    auto FieldSize = getBoundedFieldSize(F);
    if (!FieldSize) {
      return std::nullopt;
    }
    Offset += *FieldSize;
  }

  return std::nullopt;
}

std::vector<size_t> BinaryFormat::getSymbolicPositions(size_t InputLength) const {
  std::vector<size_t> Positions;
  size_t Offset = 0;

  for (const auto &F : Fields_) {
    if (Offset >= InputLength)
      break;

    size_t FieldSize = 0;
    switch (F.Type) {
    case FieldType::UInt8:
    case FieldType::Int8:
      FieldSize = 1;
      break;
    case FieldType::UInt16:
    case FieldType::Int16:
      FieldSize = 2;
      break;
    case FieldType::UInt32:
    case FieldType::Int32:
      FieldSize = 4;
      break;
    case FieldType::FixedBytes:
    case FieldType::Padding:
      FieldSize = F.Size;
      break;
    default:
      // For variable fields, assume rest of input
      FieldSize = InputLength - Offset;
      break;
    }

    if (F.IsSymbolic) {
      for (size_t I = 0; I < FieldSize && (Offset + I) < InputLength; ++I) {
        Positions.push_back(Offset + I);
      }
    }

    Offset += FieldSize;
  }

  return Positions;
}

std::optional<std::string> BinaryFormat::getFieldAtPosition(size_t Position) const {
  size_t Offset = 0;

  for (const auto &F : Fields_) {
    size_t FieldSize = 0;
    switch (F.Type) {
    case FieldType::UInt8:
    case FieldType::Int8:
      FieldSize = 1;
      break;
    case FieldType::UInt16:
    case FieldType::Int16:
      FieldSize = 2;
      break;
    case FieldType::UInt32:
    case FieldType::Int32:
      FieldSize = 4;
      break;
    case FieldType::FixedBytes:
    case FieldType::Padding:
      FieldSize = F.Size;
      break;
    default:
      // Variable field - check if position is in range
      return F.Name; // Assume rest belongs to this field
    }

    if (Position >= Offset && Position < Offset + FieldSize) {
      return F.Name;
    }

    Offset += FieldSize;
  }

  return std::nullopt;
}

bool BinaryFormat::validate(const std::vector<uint8_t> &Input) const {
  if (Input.size() < getMinSize()) {
    return false;
  }

  auto MaxSize = getMaxSize();
  if (MaxSize && Input.size() > *MaxSize) {
    return false;
  }

  auto ParsedInput = parse(Input);
  if (!ParsedInput) {
    return false;
  }

  auto getNumericValue = [&ParsedInput](const FieldDef &Field)
      -> std::optional<uint64_t> {
    switch (Field.Type) {
    case FieldType::UInt8:
    case FieldType::Int8:
    case FieldType::UInt16:
    case FieldType::Int16:
    case FieldType::UInt32:
    case FieldType::Int32:
      return ParsedInput->getIntField(Field.Name);
    default:
      return std::nullopt;
    }
  };

  auto checkConstraint = [&ParsedInput](
                             const FieldConstraint &Constraint,
                             const std::optional<uint64_t> &CurrentValue) {
    switch (Constraint.ConstraintType) {
    case FieldConstraint::Type::Range: {
      if (!CurrentValue)
        return false;
      auto Values = std::get_if<std::vector<uint64_t>>(&Constraint.Value);
      if (!Values || Values->size() < 2)
        return true;
      return *CurrentValue >= (*Values)[0] && *CurrentValue <= (*Values)[1];
    }
    case FieldConstraint::Type::Equals: {
      if (!CurrentValue)
        return false;
      auto Value = std::get_if<uint64_t>(&Constraint.Value);
      if (!Value)
        return true;
      return *CurrentValue == *Value;
    }
    case FieldConstraint::Type::NotEquals: {
      if (!CurrentValue)
        return false;
      auto Value = std::get_if<uint64_t>(&Constraint.Value);
      if (!Value)
        return true;
      return *CurrentValue != *Value;
    }
    case FieldConstraint::Type::OneOf: {
      if (!CurrentValue)
        return false;
      auto Values = std::get_if<std::vector<uint64_t>>(&Constraint.Value);
      if (!Values)
        return true;
      return std::find(Values->begin(), Values->end(), *CurrentValue) !=
             Values->end();
    }
    case FieldConstraint::Type::Bitmask: {
      if (!CurrentValue)
        return false;
      auto Values = std::get_if<std::vector<uint64_t>>(&Constraint.Value);
      if (!Values || Values->size() < 2)
        return true;
      const uint64_t Mask = (*Values)[0];
      const uint64_t Expected = (*Values)[1];
      return (*CurrentValue & Mask) == Expected;
    }
    case FieldConstraint::Type::LessThan: {
      if (!CurrentValue || !Constraint.DependentField)
        return true;
      auto DependentValue = ParsedInput->getIntField(*Constraint.DependentField);
      if (!DependentValue)
        return false;
      return *CurrentValue < *DependentValue;
    }
    case FieldConstraint::Type::GreaterThan: {
      if (!CurrentValue || !Constraint.DependentField)
        return true;
      auto DependentValue = ParsedInput->getIntField(*Constraint.DependentField);
      if (!DependentValue)
        return false;
      return *CurrentValue > *DependentValue;
    }
    case FieldConstraint::Type::DependsOn:
    case FieldConstraint::Type::Custom:
      return true;
    }
    return true;
  };

  for (const auto &Field : Fields_) {
    if (!Field.IsOptional && !ParsedInput->hasField(Field.Name)) {
      return false;
    }

    if (Field.LengthField) {
      auto LengthValue = ParsedInput->getIntField(*Field.LengthField);
      auto BytesValue = ParsedInput->getBytesField(Field.Name);
      if (!LengthValue || !BytesValue || BytesValue->size() != *LengthValue) {
        return false;
      }
    }

    if (Field.Type == FieldType::Array && Field.CountField) {
      auto CountValue = ParsedInput->getIntField(*Field.CountField);
      auto BytesValue = ParsedInput->getBytesField(Field.Name);
      if (!CountValue || !BytesValue) {
        return false;
      }

      if (!Field.Children.empty()) {
        auto ElementSize = getBoundedFieldSize(Field.Children.front());
        if (ElementSize && *ElementSize > 0) {
          if (*CountValue > BytesValue->size() / *ElementSize) {
            return false;
          }
        }
      }
    }

    auto CurrentValue = getNumericValue(Field);
    for (const auto &Constraint : Field.Constraints) {
      if (!checkConstraint(Constraint, CurrentValue)) {
        return false;
      }
    }
  }

  return true;
}

std::unique_ptr<StructuredInput> BinaryFormat::parse(const std::vector<uint8_t> &Input) const {
  auto Result = std::make_unique<StructuredInput>(*this);
  size_t Offset = 0;

  for (size_t FieldIndex = 0; FieldIndex < Fields_.size(); ++FieldIndex) {
    const auto &F = Fields_[FieldIndex];
    if (Offset >= Input.size()) {
      if (F.Type == FieldType::Array && F.CountField) {
        if (auto CountValue = Result->getIntField(*F.CountField); CountValue && *CountValue == 0) {
          Result->setField(F.Name, std::vector<uint8_t>{});
          continue;
        }
      }
      if (F.LengthField) {
        if (auto LenVal = Result->getIntField(*F.LengthField); LenVal && *LenVal == 0) {
          Result->setField(F.Name, std::vector<uint8_t>{});
          continue;
        }
      }
      if (F.IsOptional) {
        continue;
      }
      return nullptr;
    }

    switch (F.Type) {
    case FieldType::UInt8:
    case FieldType::Int8:
      if (Offset < Input.size()) {
        Result->setField(F.Name, static_cast<uint64_t>(Input[Offset]));
        Offset += 1;
      }
      break;

    case FieldType::UInt16:
    case FieldType::Int16:
      if (Offset + 1 < Input.size()) {
        uint64_t Value;
        if (F.Endian == ByteOrder::Big) {
          Value = (static_cast<uint64_t>(Input[Offset]) << 8) |
                  static_cast<uint64_t>(Input[Offset + 1]);
        } else {
          Value = static_cast<uint64_t>(Input[Offset]) |
                  (static_cast<uint64_t>(Input[Offset + 1]) << 8);
        }
        Result->setField(F.Name, Value);
        Offset += 2;
      }
      break;

    case FieldType::UInt32:
    case FieldType::Int32:
      if (Offset + 3 < Input.size()) {
        uint64_t Value;
        if (F.Endian == ByteOrder::Big) {
          Value = (static_cast<uint64_t>(Input[Offset]) << 24) |
                  (static_cast<uint64_t>(Input[Offset + 1]) << 16) |
                  (static_cast<uint64_t>(Input[Offset + 2]) << 8) |
                  static_cast<uint64_t>(Input[Offset + 3]);
        } else {
          Value = static_cast<uint64_t>(Input[Offset]) |
                  (static_cast<uint64_t>(Input[Offset + 1]) << 8) |
                  (static_cast<uint64_t>(Input[Offset + 2]) << 16) |
                  (static_cast<uint64_t>(Input[Offset + 3]) << 24);
        }
        Result->setField(F.Name, Value);
        Offset += 4;
      }
      break;

    case FieldType::FixedBytes:
    case FieldType::Padding:
      if (Offset + F.Size <= Input.size()) {
        std::vector<uint8_t> Bytes(Input.begin() + Offset,
                                    Input.begin() + Offset + F.Size);
        Result->setField(F.Name, Bytes);
        Offset += F.Size;
      }
      break;

    case FieldType::DNSName: {
      auto NameSize = consumeDNSNameBytes(Input, Offset);
      if (!NameSize) {
        return nullptr;
      }
      std::vector<uint8_t> NameBytes(Input.begin() + Offset,
                                     Input.begin() + Offset + *NameSize);
      Result->setField(F.Name, NameBytes);
      Offset += *NameSize;
      break;
    }

    case FieldType::Array: {
      if (F.Children.empty()) {
        Result->setField(F.Name, std::vector<uint8_t>{});
        break;
      }

      size_t Count = 0;
      if (F.CountField) {
        if (auto CountValue = Result->getIntField(*F.CountField)) {
          Count = *CountValue;
        }
      }

      std::vector<uint8_t> ArrayBytes;
      if (Count == 0) {
        Result->setField(F.Name, ArrayBytes);
        break;
      }

      auto ElementSize = getBoundedFieldSize(F.Children.front());
      if (ElementSize) {
        size_t Remaining = Input.size() - Offset;
        if (*ElementSize > 0 && Count > Remaining / *ElementSize) {
          return nullptr;
        }
        size_t TotalSize = Count * *ElementSize;
        ArrayBytes.assign(Input.begin() + Offset, Input.begin() + Offset + TotalSize);
        Offset += TotalSize;
        Result->setField(F.Name, ArrayBytes);
        break;
      }

      std::unordered_map<std::string, uint64_t> ContextValues;
      for (size_t ParsedIndex = 0; ParsedIndex < FieldIndex; ++ParsedIndex) {
        const auto &ParsedField = Fields_[ParsedIndex];
        if (auto ParsedValue = Result->getIntField(ParsedField.Name)) {
          ContextValues.emplace(ParsedField.Name, *ParsedValue);
        }
      }
      size_t ArrayStart = Offset;
      for (size_t Index = 0; Index < Count; ++Index) {
        auto ElementValues = ContextValues;
        auto ParsedSize =
            consumeFieldBytes(F.Children.front(), Input, Offset, ElementValues);
        if (!ParsedSize) {
          return nullptr;
        }
        Offset += *ParsedSize;
      }
      ArrayBytes.assign(Input.begin() + ArrayStart, Input.begin() + Offset);
      Result->setField(F.Name, ArrayBytes);
      break;
    }

    default:
      // Variable length fields need length field reference
      if (F.LengthField) {
        auto LenVal = Result->getIntField(*F.LengthField);
        if (!LenVal || Offset + *LenVal > Input.size()) {
          return nullptr;
        }
        std::vector<uint8_t> Bytes(Input.begin() + Offset,
                                   Input.begin() + Offset + *LenVal);
        Result->setField(F.Name, Bytes);
        Offset += *LenVal;
      }
      break;
    }
  }

  return Result;
}

std::vector<uint8_t> BinaryFormat::serialize(const StructuredInput &Input) const {
  std::vector<uint8_t> Result;

  for (const auto &F : Fields_) {
    switch (F.Type) {
    case FieldType::UInt8:
    case FieldType::Int8: {
      uint64_t Value = 0;
      if (auto V = Input.getIntField(F.Name)) {
        Value = *V;
      } else if (F.DefaultValue) {
        Value = *F.DefaultValue;
      } else if (F.FixedValue) {
        Value = *F.FixedValue;
      }
      Result.push_back(static_cast<uint8_t>(Value));
      break;
    }

    case FieldType::UInt16:
    case FieldType::Int16: {
      uint64_t Value = 0;
      if (auto V = Input.getIntField(F.Name)) {
        Value = *V;
      } else if (F.DefaultValue) {
        Value = *F.DefaultValue;
      } else if (F.FixedValue) {
        Value = *F.FixedValue;
      }
      if (F.Endian == ByteOrder::Big) {
        Result.push_back(static_cast<uint8_t>((Value >> 8) & 0xFF));
        Result.push_back(static_cast<uint8_t>(Value & 0xFF));
      } else {
        Result.push_back(static_cast<uint8_t>(Value & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 8) & 0xFF));
      }
      break;
    }

    case FieldType::UInt32:
    case FieldType::Int32: {
      uint64_t Value = 0;
      if (auto V = Input.getIntField(F.Name)) {
        Value = *V;
      } else if (F.DefaultValue) {
        Value = *F.DefaultValue;
      } else if (F.FixedValue) {
        Value = *F.FixedValue;
      }
      if (F.Endian == ByteOrder::Big) {
        Result.push_back(static_cast<uint8_t>((Value >> 24) & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 16) & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 8) & 0xFF));
        Result.push_back(static_cast<uint8_t>(Value & 0xFF));
      } else {
        Result.push_back(static_cast<uint8_t>(Value & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 8) & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 16) & 0xFF));
        Result.push_back(static_cast<uint8_t>((Value >> 24) & 0xFF));
      }
      break;
    }

    case FieldType::FixedBytes:
    case FieldType::Padding: {
      if (auto Bytes = Input.getBytesField(F.Name)) {
        for (size_t I = 0; I < F.Size; ++I) {
          if (I < Bytes->size()) {
            Result.push_back((*Bytes)[I]);
          } else {
            Result.push_back(0);
          }
        }
      } else {
        for (size_t I = 0; I < F.Size; ++I) {
          Result.push_back(0);
        }
      }
      break;
    }

    case FieldType::DNSName:
    case FieldType::VarBytes: {
      if (auto Bytes = Input.getBytesField(F.Name)) {
        Result.insert(Result.end(), Bytes->begin(), Bytes->end());
      } else if (F.Type == FieldType::DNSName) {
        // RFC 1035: default to single-char label "a" if no name specified
        Result.push_back(0x01);
        Result.push_back('a');
        Result.push_back(0x00);
      }
      break;
    }

    case FieldType::Struct: {
      BinaryFormat Nested;
      for (const auto &Child : F.Children) {
        Nested.addField(Child);
      }
      auto NestedBytes = Nested.serialize(Input);
      Result.insert(Result.end(), NestedBytes.begin(), NestedBytes.end());
      break;
    }

    case FieldType::Array: {
      if (auto Bytes = Input.getBytesField(F.Name)) {
        Result.insert(Result.end(), Bytes->begin(), Bytes->end());
        break;
      }

      if (F.Children.empty()) {
        break;
      }

      size_t Count = 0;
      if (F.CountField) {
        if (auto CountValue = Input.getIntField(*F.CountField)) {
          Count = *CountValue;
        } else if (const auto *CountField = findField(*F.CountField)) {
          Count = CountField->DefaultValue.value_or(0);
        }
      }

      BinaryFormat ElementFormat;
      ElementFormat.addField(F.Children.front());
      auto ElementSeed = ElementFormat.createSeed();
      for (size_t Index = 0; Index < Count; ++Index) {
        Result.insert(Result.end(), ElementSeed.begin(), ElementSeed.end());
      }
      break;
    }

    default:
      break;
    }
  }

  return Result;
}

//===----------------------------------------------------------------------===//
// StructuredInput Implementation
//===----------------------------------------------------------------------===//

StructuredInput::StructuredInput(const BinaryFormat &Format) : Format_(Format) {}

void StructuredInput::setField(const std::string &Name, uint64_t Value) {
  Fields_[Name] = FieldValue{Value, false};
}

void StructuredInput::setField(const std::string &Name, const std::vector<uint8_t> &Value) {
  Fields_[Name] = FieldValue{Value, false};
}

void StructuredInput::setField(const std::string &Name, const std::string &Value) {
  setField(Name, std::vector<uint8_t>(Value.begin(), Value.end()));
}

std::optional<uint64_t> StructuredInput::getIntField(const std::string &Name) const {
  auto It = Fields_.find(Name);
  if (It == Fields_.end())
    return std::nullopt;

  if (auto *Val = std::get_if<uint64_t>(&It->second.Data)) {
    return *Val;
  }
  return std::nullopt;
}

std::optional<std::vector<uint8_t>>
StructuredInput::getBytesField(const std::string &Name) const {
  auto It = Fields_.find(Name);
  if (It == Fields_.end())
    return std::nullopt;

  if (auto *Val = std::get_if<std::vector<uint8_t>>(&It->second.Data)) {
    return *Val;
  }
  return std::nullopt;
}

bool StructuredInput::hasField(const std::string &Name) const {
  return Fields_.count(Name) > 0;
}

std::vector<std::string> StructuredInput::getFieldNames() const {
  std::vector<std::string> Names;
  Names.reserve(Fields_.size());
  for (const auto &[Name, _] : Fields_) {
    Names.push_back(Name);
  }
  return Names;
}

void StructuredInput::markSymbolic(const std::string &Name) {
  auto It = Fields_.find(Name);
  if (It != Fields_.end()) {
    It->second.IsSymbolic = true;
  }
}

bool StructuredInput::isSymbolic(const std::string &Name) const {
  auto It = Fields_.find(Name);
  if (It != Fields_.end()) {
    return It->second.IsSymbolic;
  }
  return false;
}

std::unique_ptr<StructuredInput> StructuredInput::clone() const {
  auto Clone = std::make_unique<StructuredInput>(Format_);
  Clone->Fields_ = Fields_;
  return Clone;
}

//===----------------------------------------------------------------------===//
// BinaryFormatFactory - DNS Format
//===----------------------------------------------------------------------===//

BinaryFormat BinaryFormatFactory::createDNS() {
  BinaryFormat Format("DNS");
  Format.setDefaultEndian(ByteOrder::Big);

  // DNS Header (12 bytes)
  // Transaction ID
  auto ID = FieldDef::U16("id");
  Format.addField(ID);

  // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
  auto Flags = FieldDef::U16("flags");
  Flags.Constraints.push_back(FieldConstraint::Bitmask(0x8000, 0x0000)); // QR=0 for query
  Format.addField(Flags);

  // Question count
  auto QDCOUNT = FieldDef::U16("qdcount");
  QDCOUNT.DefaultValue = 1;
  Format.addField(QDCOUNT);

  // Answer count
  auto ANCOUNT = FieldDef::U16("ancount");
  ANCOUNT.DefaultValue = 0;
  Format.addField(ANCOUNT);

  // Authority count
  auto NSCOUNT = FieldDef::U16("nscount");
  NSCOUNT.DefaultValue = 0;
  Format.addField(NSCOUNT);

  // Additional count
  auto ARCOUNT = FieldDef::U16("arcount");
  ARCOUNT.DefaultValue = 0;
  Format.addField(ARCOUNT);

  // Question section (variable length)
  // DNS Name - special encoding with length-prefixed labels
  FieldDef QName;
  QName.Name = "qname";
  QName.Type = FieldType::DNSName;
  QName.Size = 0; // Variable
  Format.addField(QName);

  // Query Type
  auto QTYPE = FieldDef::U16("qtype");
  QTYPE.DefaultValue = 1; // A record
  QTYPE.Constraints.push_back(FieldConstraint::OneOf({
      1,   // A
      2,   // NS
      5,   // CNAME
      6,   // SOA
      12,  // PTR
      15,  // MX
      16,  // TXT
      28,  // AAAA
      33,  // SRV
      255, // ANY
  }));
  Format.addField(QTYPE);

  // Query Class
  auto QCLASS = FieldDef::U16("qclass");
  QCLASS.DefaultValue = 1; // IN (Internet)
  QCLASS.Constraints.push_back(FieldConstraint::OneOf({1, 3, 4, 255}));
  Format.addField(QCLASS);

  return Format;
}

BinaryFormat BinaryFormatFactory::createDNSQuery() {
  return createDNS(); // Query is the default DNS format
}

BinaryFormat BinaryFormatFactory::createDNSResponse() {
  BinaryFormat Format("DNS_Response");
  Format.setDefaultEndian(ByteOrder::Big);

  auto ID = FieldDef::U16("id");
  Format.addField(ID);

  auto Flags = FieldDef::U16("flags");
  Flags.DefaultValue = 0x8180;
  Flags.Constraints.push_back(FieldConstraint::Bitmask(0x8000, 0x8000));
  Format.addField(Flags);

  auto QDCOUNT = FieldDef::U16("qdcount");
  QDCOUNT.DefaultValue = 1;
  Format.addField(QDCOUNT);

  auto ANCOUNT = FieldDef::U16("ancount");
  ANCOUNT.DefaultValue = 1;
  Format.addField(ANCOUNT);

  auto NSCOUNT = FieldDef::U16("nscount");
  NSCOUNT.DefaultValue = 0;
  Format.addField(NSCOUNT);

  auto ARCOUNT = FieldDef::U16("arcount");
  ARCOUNT.DefaultValue = 0;
  Format.addField(ARCOUNT);

  FieldDef QName;
  QName.Name = "qname";
  QName.Type = FieldType::DNSName;
  QName.Size = 0;
  Format.addField(QName);

  auto QTYPE = FieldDef::U16("qtype");
  QTYPE.DefaultValue = 1;
  Format.addField(QTYPE);

  auto QCLASS = FieldDef::U16("qclass");
  QCLASS.DefaultValue = 1;
  Format.addField(QCLASS);

  FieldDef RRName;
  RRName.Name = "rr_name";
  // DNSName 已经支持压缩指针和完整标签编码，两种 RR owner name 形式都要兼容。
  RRName.Type = FieldType::DNSName;
  RRName.Size = 0;

  auto RRType = FieldDef::U16("rr_type");
  RRType.DefaultValue = 1;
  RRType.Constraints.push_back(FieldConstraint::OneOf({1, 2, 5, 6, 12, 15, 16, 28, 33}));

  auto RRClass = FieldDef::U16("rr_class");
  RRClass.DefaultValue = 1;

  auto RRTTL = FieldDef::U32("rr_ttl");
  RRTTL.DefaultValue = 300;

  auto RRDLength = FieldDef::U16("rr_rdlength");
  RRDLength.DefaultValue = 4;
  RRDLength.Constraints.push_back(FieldConstraint::OneOf({0, 1, 2, 4, 8, 16, 32}));

  auto RRData = FieldDef::VarLen("rr_rdata", "rr_rdlength");

  auto RRElement =
      FieldDef::Struct("rr_element", {RRName, RRType, RRClass, RRTTL, RRDLength, RRData});

  Format.addField(FieldDef::Array("answer_rrs", RRElement, "ancount"));
  Format.addField(FieldDef::Array("authority_rrs", RRElement, "nscount"));
  Format.addField(FieldDef::Array("additional_rrs", RRElement, "arcount"));

  return Format;
}

BinaryFormat BinaryFormatFactory::createDNSResourceRecord() {
  BinaryFormat Format("DNS_RR");
  Format.setDefaultEndian(ByteOrder::Big);

  FieldDef Name;
  Name.Name = "name";
  Name.Type = FieldType::DNSName;
  Name.Size = 0;
  Format.addField(Name);

  auto Type = FieldDef::U16("type");
  Type.DefaultValue = 1;
  Type.Constraints.push_back(FieldConstraint::OneOf({
      1, 2, 5, 6, 12, 15, 16, 28, 33, 41, 43, 46, 47, 48, 257
  }));
  Format.addField(Type);

  auto Class = FieldDef::U16("class");
  Class.DefaultValue = 1;
  Format.addField(Class);

  auto TTL = FieldDef::U32("ttl");
  TTL.DefaultValue = 300;
  Format.addField(TTL);

  auto RDLength = FieldDef::U16("rdlength");
  RDLength.DefaultValue = 4;
  Format.addField(RDLength);

  FieldDef RData;
  RData.Name = "rdata";
  RData.Type = FieldType::VarBytes;
  RData.LengthField = "rdlength";
  Format.addField(RData);

  return Format;
}

BinaryFormat BinaryFormatFactory::createTLV(ByteOrder Endian) {
  BinaryFormat Format("TLV");
  Format.setDefaultEndian(Endian);

  auto Type = FieldDef::U16("type", Endian);
  Format.addField(Type);

  auto Length = FieldDef::U16("length", Endian);
  Format.addField(Length);

  auto Value = FieldDef::VarLen("value", "length");
  Format.addField(Value);

  return Format;
}

BinaryFormat BinaryFormatFactory::createLengthPrefixed(size_t LengthBytes,
                                                        ByteOrder Endian) {
  BinaryFormat Format("LengthPrefixed");
  Format.setDefaultEndian(Endian);

  FieldDef Length;
  Length.Name = "length";
  Length.Endian = Endian;
  switch (LengthBytes) {
  case 1:
    Length.Type = FieldType::UInt8;
    Length.Size = 1;
    break;
  case 2:
    Length.Type = FieldType::UInt16;
    Length.Size = 2;
    break;
  case 4:
    Length.Type = FieldType::UInt32;
    Length.Size = 4;
    break;
  default:
    throw std::invalid_argument("LengthBytes must be 1, 2, or 4");
  }
  Format.addField(Length);

  auto Data = FieldDef::VarLen("data", "length");
  Format.addField(Data);

  return Format;
}

} // namespace geninput
