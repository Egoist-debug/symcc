#pragma once

#include <cstdint>
#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace dnslab::json {

class Value {
public:
  using Array = std::vector<Value>;
  using Object = std::map<std::string, Value>;
  using Storage =
      std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array,
                   Object>;

  Value() : Storage_(nullptr) {}
  Value(std::nullptr_t) : Storage_(nullptr) {}
  Value(bool Input) : Storage_(Input) {}
  Value(int Input) : Storage_(static_cast<std::int64_t>(Input)) {}
  Value(std::int64_t Input) : Storage_(Input) {}
  Value(double Input) : Storage_(Input) {}
  Value(std::string Input) : Storage_(std::move(Input)) {}
  Value(const char *Input) : Storage_(std::string(Input ? Input : "")) {}
  Value(Array Input) : Storage_(std::move(Input)) {}
  Value(Object Input) : Storage_(std::move(Input)) {}

  const Storage &storage() const { return Storage_; }

  std::string dump(int indent = 2) const {
    std::string Output;
    appendDump(Output, indent, 0);
    return Output;
  }

private:
  Storage Storage_;

  static std::string escapeString(const std::string &Input) {
    std::ostringstream Stream;
    for (const unsigned char Ch : Input) {
      switch (Ch) {
      case '\\':
        Stream << "\\\\";
        break;
      case '"':
        Stream << "\\\"";
        break;
      case '\b':
        Stream << "\\b";
        break;
      case '\f':
        Stream << "\\f";
        break;
      case '\n':
        Stream << "\\n";
        break;
      case '\r':
        Stream << "\\r";
        break;
      case '\t':
        Stream << "\\t";
        break;
      default:
        if (Ch < 0x20) {
          Stream << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                 << static_cast<int>(Ch) << std::dec << std::setfill(' ');
        } else {
          Stream << static_cast<char>(Ch);
        }
      }
    }
    return Stream.str();
  }

  static void appendIndent(std::string &Output, int indent, int depth) {
    if (indent <= 0) {
      return;
    }
    Output.append(static_cast<size_t>(indent * depth), ' ');
  }

  void appendDump(std::string &Output, int indent, int depth) const {
    std::visit(
        [&](const auto &Item) {
          using ItemType = std::decay_t<decltype(Item)>;
          if constexpr (std::is_same_v<ItemType, std::nullptr_t>) {
            Output += "null";
          } else if constexpr (std::is_same_v<ItemType, bool>) {
            Output += Item ? "true" : "false";
          } else if constexpr (std::is_same_v<ItemType, std::int64_t>) {
            Output += std::to_string(Item);
          } else if constexpr (std::is_same_v<ItemType, double>) {
            std::ostringstream Stream;
            Stream << Item;
            Output += Stream.str();
          } else if constexpr (std::is_same_v<ItemType, std::string>) {
            Output.push_back('"');
            Output += escapeString(Item);
            Output.push_back('"');
          } else if constexpr (std::is_same_v<ItemType, Array>) {
            Output.push_back('[');
            if (!Item.empty()) {
              for (size_t Index = 0; Index < Item.size(); ++Index) {
                if (indent > 0) {
                  Output.push_back('\n');
                  appendIndent(Output, indent, depth + 1);
                }
                Item[Index].appendDump(Output, indent, depth + 1);
                if (Index + 1 != Item.size()) {
                  Output.push_back(',');
                }
              }
              if (indent > 0) {
                Output.push_back('\n');
                appendIndent(Output, indent, depth);
              }
            }
            Output.push_back(']');
          } else if constexpr (std::is_same_v<ItemType, Object>) {
            Output.push_back('{');
            if (!Item.empty()) {
              size_t Index = 0;
              for (const auto &[Key, Value] : Item) {
                if (indent > 0) {
                  Output.push_back('\n');
                  appendIndent(Output, indent, depth + 1);
                }
                Output.push_back('"');
                Output += escapeString(Key);
                Output += "\":";
                if (indent > 0) {
                  Output.push_back(' ');
                }
                Value.appendDump(Output, indent, depth + 1);
                if (Index + 1 != Item.size()) {
                  Output.push_back(',');
                }
                ++Index;
              }
              if (indent > 0) {
                Output.push_back('\n');
                appendIndent(Output, indent, depth);
              }
            }
            Output.push_back('}');
          }
        },
        Storage_);
  }
};

inline Value::Object object() { return Value::Object(); }
inline Value::Array array() { return Value::Array(); }

template <typename T>
inline void setOptional(Value::Object &Output, const std::string &Key,
                        const std::optional<T> &ValueOrNull) {
  if (ValueOrNull.has_value()) {
    Output[Key] = Value(*ValueOrNull);
    return;
  }
  Output[Key] = Value();
}

} // namespace dnslab::json
