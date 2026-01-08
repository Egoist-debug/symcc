// BinaryFormat.h - Binary format specification for structured input generation
//
// This file is part of the SymCC gen_input tool.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GENINPUT_BINARYFORMAT_H
#define GENINPUT_BINARYFORMAT_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace geninput {

// Forward declarations
class StructuredInput;

/// Byte order for multi-byte fields
enum class ByteOrder { Big, Little };

/// Field type enumeration
enum class FieldType {
  UInt8,        // 8-bit unsigned
  UInt16,       // 16-bit unsigned
  UInt32,       // 32-bit unsigned
  Int8,         // 8-bit signed
  Int16,        // 16-bit signed
  Int32,        // 32-bit signed
  FixedBytes,   // Fixed-length byte array
  VarBytes,     // Variable-length byte array (length from another field)
  Flags,        // Bit flags
  Enum,         // Enumerated values
  Struct,       // Nested structure
  Array,        // Array of elements
  Union,        // Tagged union (choice based on discriminator)
  Padding,      // Padding bytes (ignored in symbolic execution)
  Checksum,     // Checksum field (computed from other fields)
  LengthPrefix, // Length-prefixed data
  DNSName,      // DNS-style compressed name (special handling)
  DNSRR,        // DNS Resource Record (for responses)
  IPv4Addr,     // IPv4 address (4 bytes)
  IPv6Addr,     // IPv6 address (16 bytes)
};

/// Constraint on field values
struct FieldConstraint {
  enum class Type {
    Range,       // Value in [min, max]
    Equals,      // Value == constant
    NotEquals,   // Value != constant
    OneOf,       // Value in set
    Bitmask,     // (Value & mask) == expected
    LessThan,    // Value < other field
    GreaterThan, // Value > other field
    DependsOn,   // Value depends on another field's value
    Custom,      // Custom constraint function
  };

  Type ConstraintType;
  std::variant<uint64_t, std::vector<uint64_t>, std::string> Value;
  std::optional<std::string> DependentField;

  // Factory methods
  static FieldConstraint Range(uint64_t Min, uint64_t Max);
  static FieldConstraint Equals(uint64_t Value);
  static FieldConstraint NotEquals(uint64_t Value);
  static FieldConstraint OneOf(std::vector<uint64_t> Values);
  static FieldConstraint Bitmask(uint64_t Mask, uint64_t Expected);
  static FieldConstraint LessThanField(const std::string &FieldName);
  static FieldConstraint GreaterThanField(const std::string &FieldName);
};

/// Definition of a single field in the binary format
struct FieldDef {
  std::string Name;
  FieldType Type;
  size_t Size;       // Size in bytes (for fixed-size types)
  ByteOrder Endian;  // Byte order for multi-byte types

  // Optional attributes
  std::optional<std::string> LengthField;   // Name of field containing length
  std::optional<std::string> CountField;    // Name of field containing array count
  std::optional<std::string> DiscrimField;  // Name of discriminator field (for Union)
  std::optional<uint64_t> DefaultValue;     // Default value for generation
  std::optional<uint64_t> FixedValue;       // Fixed value (not symbolic)

  // Constraints
  std::vector<FieldConstraint> Constraints;

  // For nested structures/unions
  std::vector<FieldDef> Children;

  // For enums
  std::vector<std::pair<std::string, uint64_t>> EnumValues;

  // For unions: discriminator value -> child index mapping
  std::vector<std::pair<uint64_t, size_t>> UnionCases;

  // Flags
  bool IsOptional = false;
  bool IsSymbolic = true;    // Whether to treat as symbolic (vs concrete)
  bool IsRepeatable = false; // Can appear multiple times

  // Factory methods for common field types
  static FieldDef U8(const std::string &Name);
  static FieldDef U16(const std::string &Name, ByteOrder Endian = ByteOrder::Big);
  static FieldDef U32(const std::string &Name, ByteOrder Endian = ByteOrder::Big);
  static FieldDef Bytes(const std::string &Name, size_t Size);
  static FieldDef VarLen(const std::string &Name, const std::string &LengthField);
  static FieldDef Struct(const std::string &Name, std::vector<FieldDef> Fields);
  static FieldDef Array(const std::string &Name, FieldDef Element,
                        const std::string &CountField);
  static FieldDef Pad(size_t Size);
};

/// Complete binary format specification
class BinaryFormat {
public:
  BinaryFormat() = default;
  explicit BinaryFormat(const std::string &Name);

  /// Set format name
  void setName(const std::string &Name) { Name_ = Name; }
  const std::string &getName() const { return Name_; }

  /// Set default byte order
  void setDefaultEndian(ByteOrder Endian) { DefaultEndian_ = Endian; }
  ByteOrder getDefaultEndian() const { return DefaultEndian_; }

  /// Add a field to the format
  void addField(FieldDef Field);

  /// Get all fields
  const std::vector<FieldDef> &getFields() const { return Fields_; }

  /// Find a field by name (supports dotted paths for nested fields)
  const FieldDef *findField(const std::string &Path) const;

  /// Calculate minimum size required for the format
  size_t getMinSize() const;

  /// Calculate maximum size (if bounded)
  std::optional<size_t> getMaxSize() const;

  /// Create a seed input with default/zero values
  std::vector<uint8_t> createSeed() const;

  /// Create a seed input with specific field values
  std::vector<uint8_t>
  createSeed(const std::vector<std::pair<std::string, uint64_t>> &Values) const;

  /// Validate that input conforms to format structure
  bool validate(const std::vector<uint8_t> &Input) const;

  /// Parse input into structured form
  std::unique_ptr<StructuredInput> parse(const std::vector<uint8_t> &Input) const;

  /// Serialize structured input back to bytes
  std::vector<uint8_t> serialize(const StructuredInput &Input) const;

  /// Get field offset in the serialized format (returns nullopt for variable fields)
  std::optional<size_t> getFieldOffset(const std::string &FieldName) const;

  /// Get symbolic positions (byte indices that should be symbolic)
  std::vector<size_t> getSymbolicPositions(size_t InputLength) const;

  /// Get field at byte position
  std::optional<std::string> getFieldAtPosition(size_t Position) const;

private:
  std::string Name_;
  ByteOrder DefaultEndian_ = ByteOrder::Big;
  std::vector<FieldDef> Fields_;

  // Helper for recursive field lookup
  const FieldDef *findFieldRecursive(const std::vector<FieldDef> &Fields,
                                      const std::string &Path) const;
};

/// Represents a parsed/structured input with named fields
class StructuredInput {
public:
  explicit StructuredInput(const BinaryFormat &Format);

  /// Set field value by name
  void setField(const std::string &Name, uint64_t Value);
  void setField(const std::string &Name, const std::vector<uint8_t> &Value);
  void setField(const std::string &Name, const std::string &Value);

  /// Get field value by name
  std::optional<uint64_t> getIntField(const std::string &Name) const;
  std::optional<std::vector<uint8_t>> getBytesField(const std::string &Name) const;

  /// Check if field is set
  bool hasField(const std::string &Name) const;

  /// Get all set field names
  std::vector<std::string> getFieldNames() const;

  /// Mark a field as symbolic (for exploration)
  void markSymbolic(const std::string &Name);
  bool isSymbolic(const std::string &Name) const;

  /// Clone this structured input
  std::unique_ptr<StructuredInput> clone() const;

  /// Get underlying format
  const BinaryFormat &getFormat() const { return Format_; }

private:
  const BinaryFormat &Format_;

  // Field storage
  struct FieldValue {
    std::variant<uint64_t, std::vector<uint8_t>> Data;
    bool IsSymbolic = false;
  };
  std::unordered_map<std::string, FieldValue> Fields_;
};

/// Factory for creating common binary formats
class BinaryFormatFactory {
public:
  /// Create DNS packet format
  static BinaryFormat createDNS();

  /// Create DNS query packet format (subset)
  static BinaryFormat createDNSQuery();

  /// Create DNS response packet format with full RR support
  static BinaryFormat createDNSResponse();

  /// Create a DNS Resource Record format
  static BinaryFormat createDNSResourceRecord();

  /// Create generic TLV (Type-Length-Value) format
  static BinaryFormat createTLV(ByteOrder Endian = ByteOrder::Big);

  /// Create length-prefixed format
  static BinaryFormat createLengthPrefixed(size_t LengthBytes,
                                            ByteOrder Endian = ByteOrder::Big);

  /// Load format from JSON specification file
  static BinaryFormat loadFromJSON(const std::string &Path);

  /// Load format from YAML specification file
  static BinaryFormat loadFromYAML(const std::string &Path);
};

} // namespace geninput

#endif // GENINPUT_BINARYFORMAT_H
