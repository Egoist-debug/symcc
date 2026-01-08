// FormatAwareGenerator.cpp - Format-aware seed input generator implementation
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../include/FormatAwareGenerator.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>
#include <sstream>

namespace geninput {

FormatAwareGenerator::FormatAwareGenerator() = default;

FormatAwareGenerator::FormatAwareGenerator(const BinaryFormat &Format)
    : Format_(&Format) {}

FormatAwareGenerator::FormatAwareGenerator(const BinaryFormat &Format,
                                           FormatGeneratorConfig Config)
    : Format_(&Format), Config_(std::move(Config)) {}

void FormatAwareGenerator::setFormat(const BinaryFormat &Format) {
  Format_ = &Format;
}

void FormatAwareGenerator::setRunner(std::shared_ptr<SymCCRunner> Runner) {
  Runner_ = std::move(Runner);
}

void FormatAwareGenerator::setConfig(FormatGeneratorConfig Config) {
  Config_ = std::move(Config);
}

void FormatAwareGenerator::addSeed(const std::vector<uint8_t> &Seed) {
  if (!Format_)
    return;

  FormatWorkItem Item;
  Item.Input = std::make_unique<StructuredInput>(*Format_);
  Item.RawBytes = Seed;
  Item.Depth = 0;
  Item.Priority = 100; // High priority for seeds

  if (SeenInputs_.count(Seed) == 0) {
    SeenInputs_.insert(Seed);
    Queue_.push(std::move(Item));
  }
}

void FormatAwareGenerator::addSeed(const StructuredInput &Seed) {
  if (!Format_)
    return;

  auto RawBytes = Format_->serialize(Seed);
  if (SeenInputs_.count(RawBytes) == 0) {
    FormatWorkItem Item;
    Item.Input = Seed.clone();
    Item.RawBytes = std::move(RawBytes);
    Item.Depth = 0;
    Item.Priority = 100;

    SeenInputs_.insert(Item.RawBytes);
    Queue_.push(std::move(Item));
  }
}

FormatGeneratorResult FormatAwareGenerator::run() {
  if (!Format_ || !Runner_) {
    return {};
  }

  auto Start = std::chrono::high_resolution_clock::now();

  // If no seeds, create one from format
  if (Queue_.empty()) {
    auto DefaultSeed = Format_->createSeed();
    addSeed(DefaultSeed);
  }

  while (!Queue_.empty() && !shouldStop()) {
    FormatWorkItem Item = std::move(const_cast<FormatWorkItem &>(Queue_.top()));
    Queue_.pop();

    processWorkItem(Item);

    Stats_.TotalIterations++;

    if (ProgressCb_) {
      ProgressCb_(Stats_.TotalIterations, Queue_.size(), ValidInputs_.size());
    }
  }

  auto End = std::chrono::high_resolution_clock::now();
  Stats_.TotalTimeMs =
      std::chrono::duration<double, std::milli>(End - Start).count();

  FormatGeneratorResult Result;
  Result.ValidInputs = ValidInputs_;
  Result.AcceptedInputs = ValidInputs_; // TODO: track separately
  return Result;
}

void FormatAwareGenerator::processWorkItem(FormatWorkItem &Item) {
  // Run SymCC on the current input
  auto RunResult = Runner_->run(Item.RawBytes);
  Stats_.TotalSymCCRuns++;

  if (RunResult.Accepted) {
    addValidInput(Item.RawBytes);
  }

  // Process generated test cases
  for (const auto &TestCase : RunResult.GeneratedTestCases) {
    if (SeenInputs_.count(TestCase) > 0)
      continue;

    // Check if test case conforms to format
    if (Config_.StrictFormat && !checkFormatConstraints(TestCase)) {
      Stats_.FormatViolations++;
      continue;
    }

    SeenInputs_.insert(TestCase);

    FormatWorkItem NewItem;
    NewItem.Input = std::make_unique<StructuredInput>(*Format_);
    NewItem.RawBytes = TestCase;
    NewItem.Depth = Item.Depth + 1;
    NewItem.Priority = 50 - static_cast<int>(NewItem.Depth);

    if (NewItem.Depth <= Config_.MaxRecursionDepth) {
      Queue_.push(std::move(NewItem));
    }
  }

  // Field mutation exploration
  if (Config_.EnableFieldMutation && Item.Depth < Config_.MaxRecursionDepth) {
    for (const auto &Field : Format_->getFields()) {
      if (!Field.IsSymbolic)
        continue;

      auto Variants = exploreField(*Item.Input, Field.Name);
      for (auto &Variant : Variants) {
        if (SeenInputs_.count(Variant.RawBytes) == 0) {
          SeenInputs_.insert(Variant.RawBytes);
          Queue_.push(std::move(Variant));
          Stats_.FieldMutations++;
        }
      }
    }
  }
}

std::vector<FormatWorkItem>
FormatAwareGenerator::exploreField(const StructuredInput &Input,
                                    const std::string &FieldName) {
  std::vector<FormatWorkItem> Results;

  const auto *Field = Format_->findField(FieldName);
  if (!Field || !Field->IsSymbolic)
    return Results;

  auto Values = generateFieldValues(*Field);

  for (uint64_t Value : Values) {
    auto NewInput = Input.clone();
    NewInput->setField(FieldName, Value);

    auto RawBytes = Format_->serialize(*NewInput);

    if (SeenInputs_.count(RawBytes) > 0)
      continue;

    FormatWorkItem Item;
    Item.Input = std::move(NewInput);
    Item.RawBytes = std::move(RawBytes);
    Item.FocusField = FieldName;
    Item.Priority = 30;

    Results.push_back(std::move(Item));

    if (Results.size() >= Config_.MaxVariantsPerField)
      break;
  }

  return Results;
}

std::vector<uint64_t> FormatAwareGenerator::generateFieldValues(const FieldDef &Field) {
  std::vector<uint64_t> Values;

  // Calculate value range based on field type
  uint64_t MaxValue = 0;
  switch (Field.Type) {
  case FieldType::UInt8:
  case FieldType::Int8:
    MaxValue = 0xFF;
    break;
  case FieldType::UInt16:
  case FieldType::Int16:
    MaxValue = 0xFFFF;
    break;
  case FieldType::UInt32:
  case FieldType::Int32:
    MaxValue = 0xFFFFFFFF;
    break;
  default:
    return Values;
  }

  // Process constraints
  for (const auto &Constraint : Field.Constraints) {
    switch (Constraint.ConstraintType) {
    case FieldConstraint::Type::OneOf:
      if (auto *Vals = std::get_if<std::vector<uint64_t>>(&Constraint.Value)) {
        Values.insert(Values.end(), Vals->begin(), Vals->end());
      }
      return Values;

    case FieldConstraint::Type::Range:
      if (auto *Vals = std::get_if<std::vector<uint64_t>>(&Constraint.Value)) {
        if (Vals->size() >= 2) {
          uint64_t Min = (*Vals)[0];
          uint64_t Max = (*Vals)[1];
          // Sample values from range
          Values.push_back(Min);
          Values.push_back(Max);
          if (Max > Min + 1) {
            Values.push_back((Min + Max) / 2);
          }
        }
      }
      break;

    case FieldConstraint::Type::Equals:
      if (auto *Val = std::get_if<uint64_t>(&Constraint.Value)) {
        Values.push_back(*Val);
        return Values;
      }
      break;

    default:
      break;
    }
  }

  // If no constraints, generate boundary values
  if (Values.empty()) {
    Values.push_back(0);
    Values.push_back(1);
    Values.push_back(MaxValue / 2);
    Values.push_back(MaxValue - 1);
    Values.push_back(MaxValue);
  }

  // Deduplicate
  std::sort(Values.begin(), Values.end());
  Values.erase(std::unique(Values.begin(), Values.end()), Values.end());

  return Values;
}

std::vector<std::vector<uint8_t>> FormatAwareGenerator::generateDNSNames() {
  std::vector<std::vector<uint8_t>> Names;

  // Common test domain names
  std::vector<std::string> TestDomains = {
      "a",
      "test",
      "example.com",
      "www.example.com",
      "sub.domain.example.com",
      "a.b.c.d.e.f.g",
      std::string(63, 'a'),                    // Max label length
      std::string(63, 'a') + ".example.com",   // Long label
  };

  for (const auto &Domain : TestDomains) {
    Names.push_back(encodeDNSName(Domain));
  }

  return Names;
}

std::vector<uint8_t> FormatAwareGenerator::encodeDNSName(const std::string &Name) {
  return DNSNameCodec::encode(Name);
}

bool FormatAwareGenerator::checkFormatConstraints(const std::vector<uint8_t> &Input) {
  if (!Format_)
    return true;

  // Basic size check
  size_t MinSize = Format_->getMinSize();
  if (Input.size() < MinSize)
    return false;

  auto MaxSize = Format_->getMaxSize();
  if (MaxSize && Input.size() > *MaxSize)
    return false;

  return true;
}

std::vector<uint8_t>
FormatAwareGenerator::updateComputedFields(std::vector<uint8_t> Input) {
  // TODO: Implement checksum/length field computation
  return Input;
}

void FormatAwareGenerator::addValidInput(const std::vector<uint8_t> &Input) {
  ValidInputs_.push_back(Input);
  Stats_.AcceptedCount++;

  if (InputCb_) {
    InputCb_(Input);
  }
}

bool FormatAwareGenerator::shouldStop() const {
  return Stats_.TotalIterations >= Config_.MaxIterations;
}

void FormatAwareGenerator::reset() {
  while (!Queue_.empty())
    Queue_.pop();
  SeenInputs_.clear();
  ValidInputs_.clear();
  Stats_ = FormatGeneratorStats{};
}

//===----------------------------------------------------------------------===//
// DNSNameCodec Implementation
//===----------------------------------------------------------------------===//

std::vector<uint8_t> DNSNameCodec::encode(const std::string &Name) {
  std::vector<uint8_t> Result;

  if (Name.empty()) {
    Result.push_back(0);
    return Result;
  }

  std::istringstream Stream(Name);
  std::string Label;

  while (std::getline(Stream, Label, '.')) {
    if (Label.empty())
      continue;

    // Truncate to max label length (63)
    if (Label.size() > 63) {
      Label = Label.substr(0, 63);
    }

    Result.push_back(static_cast<uint8_t>(Label.size()));
    Result.insert(Result.end(), Label.begin(), Label.end());
  }

  // Null terminator
  Result.push_back(0);

  return Result;
}

std::string DNSNameCodec::decode(const std::vector<uint8_t> &Data, size_t Offset) {
  std::string Result;
  size_t Pos = Offset;

  while (Pos < Data.size()) {
    uint8_t Len = Data[Pos++];

    if (Len == 0)
      break;

    // Check for compression pointer (top 2 bits set)
    if ((Len & 0xC0) == 0xC0) {
      if (Pos >= Data.size())
        break;
      size_t Pointer = ((Len & 0x3F) << 8) | Data[Pos];
      if (Pointer >= Offset) // Prevent infinite loops
        break;
      if (!Result.empty())
        Result += ".";
      Result += decode(Data, Pointer);
      break;
    }

    if (Pos + Len > Data.size())
      break;

    if (!Result.empty())
      Result += ".";
    Result += std::string(Data.begin() + Pos, Data.begin() + Pos + Len);
    Pos += Len;
  }

  return Result;
}

bool DNSNameCodec::hasCompression(const std::vector<uint8_t> &Data, size_t Offset) {
  size_t Pos = Offset;
  while (Pos < Data.size()) {
    uint8_t Len = Data[Pos];
    if (Len == 0)
      return false;
    if ((Len & 0xC0) == 0xC0)
      return true;
    Pos += 1 + Len;
  }
  return false;
}

size_t DNSNameCodec::getEncodedLength(const std::vector<uint8_t> &Data, size_t Offset) {
  size_t Pos = Offset;
  while (Pos < Data.size()) {
    uint8_t Len = Data[Pos++];
    if (Len == 0)
      break;
    if ((Len & 0xC0) == 0xC0) {
      Pos++; // Compression pointer is 2 bytes
      break;
    }
    Pos += Len;
  }
  return Pos - Offset;
}

std::vector<std::string> DNSNameCodec::generateLabelVariants(const std::string &Label) {
  std::vector<std::string> Variants;
  Variants.push_back(Label);

  // Single character
  Variants.push_back("a");
  Variants.push_back("0");

  // Uppercase
  std::string Upper = Label;
  std::transform(Upper.begin(), Upper.end(), Upper.begin(), ::toupper);
  Variants.push_back(Upper);

  // Max length (63 chars)
  Variants.push_back(std::string(63, 'x'));

  // With hyphen
  Variants.push_back("test-label");

  // With numbers
  Variants.push_back("test123");

  return Variants;
}

std::vector<std::string> DNSNameCodec::generateNameVariants(const std::string &Name) {
  std::vector<std::string> Variants;
  Variants.push_back(Name);

  // Single label
  Variants.push_back("localhost");

  // Multiple labels
  Variants.push_back("www.example.com");
  Variants.push_back("sub.domain.example.com");

  // Maximum depth (127 labels theoretically, but 253 char limit)
  std::string LongName;
  for (int I = 0; I < 10; ++I) {
    if (!LongName.empty())
      LongName += ".";
    LongName += "a";
  }
  Variants.push_back(LongName);

  // Near max length
  Variants.push_back(std::string(63, 'a') + "." + std::string(63, 'b'));

  return Variants;
}

//===----------------------------------------------------------------------===//
// DNSPacketBuilder Implementation
//===----------------------------------------------------------------------===//

DNSPacketBuilder::DNSPacketBuilder() : ID_(0), Flags_(0) {}

DNSPacketBuilder &DNSPacketBuilder::setID(uint16_t ID) {
  ID_ = ID;
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::setFlags(uint16_t Flags) {
  Flags_ = Flags;
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::asQuery() {
  Flags_ &= ~0x8000;
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::asResponse() {
  Flags_ |= 0x8000;
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::setRecursionDesired(bool RD) {
  if (RD) {
    Flags_ |= 0x0100;
  } else {
    Flags_ &= ~0x0100;
  }
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::setAuthoritative(bool AA) {
  if (AA) {
    Flags_ |= 0x0400;
  } else {
    Flags_ &= ~0x0400;
  }
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::setRecursionAvailable(bool RA) {
  if (RA) {
    Flags_ |= 0x0080;
  } else {
    Flags_ &= ~0x0080;
  }
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::setRCode(uint8_t RCode) {
  Flags_ = (Flags_ & 0xFFF0) | (RCode & 0x0F);
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::addQuestion(const std::string &Name,
                                                 uint16_t Type, uint16_t Class) {
  Questions_.push_back({Name, Type, Class});
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::addAnswer(const std::string &Name, uint16_t Type,
                                               uint16_t Class, uint32_t TTL,
                                               const std::vector<uint8_t> &RData) {
  Answers_.push_back({Name, Type, Class, TTL, RData});
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::addAuthority(const std::string &Name, uint16_t Type,
                                                  uint16_t Class, uint32_t TTL,
                                                  const std::vector<uint8_t> &RData) {
  Authority_.push_back({Name, Type, Class, TTL, RData});
  return *this;
}

DNSPacketBuilder &DNSPacketBuilder::addAdditional(const std::string &Name, uint16_t Type,
                                                   uint16_t Class, uint32_t TTL,
                                                   const std::vector<uint8_t> &RData) {
  Additional_.push_back({Name, Type, Class, TTL, RData});
  return *this;
}

std::vector<uint8_t> DNSPacketBuilder::build() const {
  std::vector<uint8_t> Packet;
  Packet.reserve(512);

  Packet.push_back(static_cast<uint8_t>((ID_ >> 8) & 0xFF));
  Packet.push_back(static_cast<uint8_t>(ID_ & 0xFF));

  Packet.push_back(static_cast<uint8_t>((Flags_ >> 8) & 0xFF));
  Packet.push_back(static_cast<uint8_t>(Flags_ & 0xFF));

  uint16_t QDCOUNT = static_cast<uint16_t>(Questions_.size());
  Packet.push_back(static_cast<uint8_t>((QDCOUNT >> 8) & 0xFF));
  Packet.push_back(static_cast<uint8_t>(QDCOUNT & 0xFF));

  uint16_t ANCOUNT = static_cast<uint16_t>(Answers_.size());
  Packet.push_back(static_cast<uint8_t>((ANCOUNT >> 8) & 0xFF));
  Packet.push_back(static_cast<uint8_t>(ANCOUNT & 0xFF));

  uint16_t NSCOUNT = static_cast<uint16_t>(Authority_.size());
  Packet.push_back(static_cast<uint8_t>((NSCOUNT >> 8) & 0xFF));
  Packet.push_back(static_cast<uint8_t>(NSCOUNT & 0xFF));

  uint16_t ARCOUNT = static_cast<uint16_t>(Additional_.size());
  Packet.push_back(static_cast<uint8_t>((ARCOUNT >> 8) & 0xFF));
  Packet.push_back(static_cast<uint8_t>(ARCOUNT & 0xFF));

  for (const auto &Q : Questions_) {
    auto EncodedName = DNSNameCodec::encode(Q.Name);
    Packet.insert(Packet.end(), EncodedName.begin(), EncodedName.end());
    Packet.push_back(static_cast<uint8_t>((Q.Type >> 8) & 0xFF));
    Packet.push_back(static_cast<uint8_t>(Q.Type & 0xFF));
    Packet.push_back(static_cast<uint8_t>((Q.Class >> 8) & 0xFF));
    Packet.push_back(static_cast<uint8_t>(Q.Class & 0xFF));
  }

  auto appendRR = [&Packet](const ResourceRecord &RR) {
    auto EncodedName = DNSNameCodec::encode(RR.Name);
    Packet.insert(Packet.end(), EncodedName.begin(), EncodedName.end());
    Packet.push_back(static_cast<uint8_t>((RR.Type >> 8) & 0xFF));
    Packet.push_back(static_cast<uint8_t>(RR.Type & 0xFF));
    Packet.push_back(static_cast<uint8_t>((RR.Class >> 8) & 0xFF));
    Packet.push_back(static_cast<uint8_t>(RR.Class & 0xFF));
    Packet.push_back(static_cast<uint8_t>((RR.TTL >> 24) & 0xFF));
    Packet.push_back(static_cast<uint8_t>((RR.TTL >> 16) & 0xFF));
    Packet.push_back(static_cast<uint8_t>((RR.TTL >> 8) & 0xFF));
    Packet.push_back(static_cast<uint8_t>(RR.TTL & 0xFF));
    uint16_t RDLength = static_cast<uint16_t>(RR.RData.size());
    Packet.push_back(static_cast<uint8_t>((RDLength >> 8) & 0xFF));
    Packet.push_back(static_cast<uint8_t>(RDLength & 0xFF));
    Packet.insert(Packet.end(), RR.RData.begin(), RR.RData.end());
  };

  for (const auto &A : Answers_) {
    appendRR(A);
  }
  for (const auto &A : Authority_) {
    appendRR(A);
  }
  for (const auto &A : Additional_) {
    appendRR(A);
  }

  return Packet;
}

std::vector<uint8_t> DNSPacketBuilder::buildQuery(const std::string &Domain,
                                                   uint16_t Type) {
  return DNSPacketBuilder()
      .setID(0x1234)
      .asQuery()
      .setRecursionDesired(true)
      .addQuestion(Domain, Type, 1)
      .build();
}

std::vector<uint8_t>
DNSPacketBuilder::buildResponse(const std::string &Domain,
                                 const std::vector<uint8_t> &Answer) {
  return DNSPacketBuilder()
      .setID(0x1234)
      .asResponse()
      .setRecursionDesired(true)
      .setRecursionAvailable(true)
      .addQuestion(Domain, 1, 1)
      .addAnswer(Domain, 1, 1, 300, Answer)
      .build();
}

std::vector<uint8_t>
DNSPacketBuilder::buildResponseFromQuery(const std::vector<uint8_t> &Query,
                                          const std::vector<uint8_t> &AnswerRData,
                                          uint16_t AnswerType,
                                          uint32_t TTL) {
  if (Query.size() < 12) {
    return {};
  }

  uint16_t TxID = (static_cast<uint16_t>(Query[0]) << 8) | Query[1];
  uint16_t QueryFlags = (static_cast<uint16_t>(Query[2]) << 8) | Query[3];
  uint16_t QDCOUNT = (static_cast<uint16_t>(Query[4]) << 8) | Query[5];

  if (QDCOUNT == 0 || Query.size() < 13) {
    return {};
  }

  size_t QNameStart = 12;
  size_t Pos = QNameStart;
  while (Pos < Query.size() && Query[Pos] != 0) {
    uint8_t Len = Query[Pos];
    if ((Len & 0xC0) == 0xC0) {
      Pos += 2;
      break;
    }
    Pos += 1 + Len;
  }
  if (Pos < Query.size() && Query[Pos] == 0) {
    Pos++;
  }

  if (Pos + 4 > Query.size()) {
    return {};
  }

  uint16_t QTYPE = (static_cast<uint16_t>(Query[Pos]) << 8) | Query[Pos + 1];
  uint16_t QCLASS = (static_cast<uint16_t>(Query[Pos + 2]) << 8) | Query[Pos + 3];
  Pos += 4;

  std::vector<uint8_t> QNameBytes(Query.begin() + QNameStart, Query.begin() + Pos);

  std::vector<uint8_t> Response;
  Response.reserve(512);

  Response.push_back(static_cast<uint8_t>((TxID >> 8) & 0xFF));
  Response.push_back(static_cast<uint8_t>(TxID & 0xFF));

  uint16_t ResponseFlags = 0x8000 | (QueryFlags & 0x0100) | 0x0080;
  Response.push_back(static_cast<uint8_t>((ResponseFlags >> 8) & 0xFF));
  Response.push_back(static_cast<uint8_t>(ResponseFlags & 0xFF));

  Response.push_back(0x00);
  Response.push_back(0x01);
  Response.push_back(0x00);
  Response.push_back(0x01);
  Response.push_back(0x00);
  Response.push_back(0x00);
  Response.push_back(0x00);
  Response.push_back(0x00);

  Response.insert(Response.end(), QNameBytes.begin(), QNameBytes.end());
  Response.push_back(static_cast<uint8_t>((QTYPE >> 8) & 0xFF));
  Response.push_back(static_cast<uint8_t>(QTYPE & 0xFF));
  Response.push_back(static_cast<uint8_t>((QCLASS >> 8) & 0xFF));
  Response.push_back(static_cast<uint8_t>(QCLASS & 0xFF));

  Response.insert(Response.end(), QNameBytes.begin(), QNameBytes.end());
  Response.push_back(static_cast<uint8_t>((AnswerType >> 8) & 0xFF));
  Response.push_back(static_cast<uint8_t>(AnswerType & 0xFF));
  Response.push_back(static_cast<uint8_t>((QCLASS >> 8) & 0xFF));
  Response.push_back(static_cast<uint8_t>(QCLASS & 0xFF));
  Response.push_back(static_cast<uint8_t>((TTL >> 24) & 0xFF));
  Response.push_back(static_cast<uint8_t>((TTL >> 16) & 0xFF));
  Response.push_back(static_cast<uint8_t>((TTL >> 8) & 0xFF));
  Response.push_back(static_cast<uint8_t>(TTL & 0xFF));
  uint16_t RDLength = static_cast<uint16_t>(AnswerRData.size());
  Response.push_back(static_cast<uint8_t>((RDLength >> 8) & 0xFF));
  Response.push_back(static_cast<uint8_t>(RDLength & 0xFF));
  Response.insert(Response.end(), AnswerRData.begin(), AnswerRData.end());

  return Response;
}

DNSQueryResponseGenerator::DNSQueryResponseGenerator() = default;

DNSQueryResponseGenerator::DNSQueryResponseGenerator(Config Cfg)
    : Config_(std::move(Cfg)) {}

void DNSQueryResponseGenerator::setRunner(std::shared_ptr<SymCCRunner> Runner) {
  Runner_ = std::move(Runner);
}

void DNSQueryResponseGenerator::addQuerySeed(const std::vector<uint8_t> &Query) {
  QuerySeeds_.push_back(Query);
}

std::vector<DNSQueryResponseGenerator::QueryResponsePair>
DNSQueryResponseGenerator::generate() {
  std::vector<QueryResponsePair> Results;

  if (QuerySeeds_.empty()) {
    auto DefaultQuery = DNSPacketBuilder::buildQuery("example.com", 1);
    QuerySeeds_.push_back(DefaultQuery);
  }

  for (const auto &Query : QuerySeeds_) {
    auto BaseResponse = generateResponseForQuery(Query);
    if (BaseResponse.empty()) {
      continue;
    }

    QueryResponsePair Pair{Query, BaseResponse};
    Results.push_back(Pair);
    if (PairCb_) {
      PairCb_(Pair);
    }

    if (Config_.ExploreAnswerSection && Runner_) {
      size_t PreserveBytes = Config_.HeaderBytesToPreserve + Config_.QuestionBytesToPreserve;
      auto Variants = exploreResponseVariants(BaseResponse, PreserveBytes);
      for (auto &Variant : Variants) {
        QueryResponsePair VarPair{Query, std::move(Variant)};
        Results.push_back(VarPair);
        if (PairCb_) {
          PairCb_(VarPair);
        }
      }
    }
  }

  return Results;
}

std::vector<uint8_t>
DNSQueryResponseGenerator::generateResponseForQuery(const std::vector<uint8_t> &Query) {
  std::vector<uint8_t> DefaultAnswer = {127, 0, 0, 1};
  return DNSPacketBuilder::buildResponseFromQuery(Query, DefaultAnswer, 1, 300);
}

std::vector<std::vector<uint8_t>>
DNSQueryResponseGenerator::exploreResponseVariants(const std::vector<uint8_t> &BaseResponse,
                                                    size_t PreserveBytes) {
  std::vector<std::vector<uint8_t>> Results;

  if (!Runner_ || BaseResponse.size() <= PreserveBytes) {
    return Results;
  }

  std::vector<uint8_t> Header(BaseResponse.begin(),
                              BaseResponse.begin() + PreserveBytes);
  std::vector<uint8_t> Payload(BaseResponse.begin() + PreserveBytes,
                               BaseResponse.end());

  std::set<std::vector<uint8_t>> Seen;
  Seen.insert(Payload);

  std::queue<std::vector<uint8_t>> Queue;
  Queue.push(Payload);

  size_t Iterations = 0;
  while (!Queue.empty() && Iterations < Config_.MaxIterations) {
    auto Current = Queue.front();
    Queue.pop();
    Iterations++;

    std::vector<uint8_t> FullPacket = Header;
    FullPacket.insert(FullPacket.end(), Current.begin(), Current.end());

    auto RunResult = Runner_->run(FullPacket);

    for (const auto &TestCase : RunResult.GeneratedTestCases) {
      if (TestCase.size() <= PreserveBytes) {
        continue;
      }

      std::vector<uint8_t> NewPayload(TestCase.begin() + PreserveBytes,
                                       TestCase.end());
      if (Seen.count(NewPayload) == 0) {
        Seen.insert(NewPayload);
        Queue.push(NewPayload);

        std::vector<uint8_t> NewPacket = Header;
        NewPacket.insert(NewPacket.end(), NewPayload.begin(), NewPayload.end());
        Results.push_back(NewPacket);
      }
    }
  }

  return Results;
}

HybridDNSGenerator::HybridDNSGenerator() = default;

HybridDNSGenerator::HybridDNSGenerator(Config Cfg) : Config_(std::move(Cfg)) {}

void HybridDNSGenerator::setRunner(std::shared_ptr<SymCCRunner> Runner) {
  Runner_ = std::move(Runner);
}

void HybridDNSGenerator::addSeed(const std::vector<uint8_t> &Seed) {
  Seeds_.push_back(Seed);
}

std::vector<std::vector<uint8_t>> HybridDNSGenerator::generate() {
  std::vector<std::vector<uint8_t>> Results;

  if (Seeds_.empty()) {
    std::vector<uint8_t> DefaultSeed;
    if (Config_.IsResponse) {
      DefaultSeed = DNSPacketBuilder()
          .setID(0x1234)
          .asResponse()
          .setRecursionDesired(true)
          .setRecursionAvailable(true)
          .addQuestion("example.com", 1, 1)
          .addAnswer("example.com", 1, 1, 300, {127, 0, 0, 1})
          .build();
    } else {
      DefaultSeed = DNSPacketBuilder::buildQuery("example.com", 1);
    }
    Seeds_.push_back(DefaultSeed);
  }

  for (const auto &Seed : Seeds_) {
    auto Header = createHeaderFromSeed(Seed);
    auto PayloadVariants = explorePayload(Header);

    for (auto &Variant : PayloadVariants) {
      Results.push_back(std::move(Variant));
      if (InputCb_ && !Results.empty()) {
        InputCb_(Results.back());
      }
    }
  }

  return Results;
}

std::vector<uint8_t>
HybridDNSGenerator::createHeaderFromSeed(const std::vector<uint8_t> &Seed) {
  size_t HeaderSize = std::min(Config_.PreserveHeaderBytes, Seed.size());
  return std::vector<uint8_t>(Seed.begin(), Seed.begin() + HeaderSize);
}

std::vector<std::vector<uint8_t>>
HybridDNSGenerator::explorePayload(const std::vector<uint8_t> &Header) {
  std::vector<std::vector<uint8_t>> Results;

  if (!Runner_) {
    return Results;
  }

  std::vector<uint8_t> InitialPayload;
  if (Config_.IsResponse) {
    auto EncodedName = DNSNameCodec::encode("a");
    InitialPayload.insert(InitialPayload.end(), EncodedName.begin(), EncodedName.end());
    InitialPayload.push_back(0x00); InitialPayload.push_back(0x01);
    InitialPayload.push_back(0x00); InitialPayload.push_back(0x01);

    InitialPayload.insert(InitialPayload.end(), EncodedName.begin(), EncodedName.end());
    InitialPayload.push_back(0x00); InitialPayload.push_back(0x01);
    InitialPayload.push_back(0x00); InitialPayload.push_back(0x01);
    InitialPayload.push_back(0x00); InitialPayload.push_back(0x00);
    InitialPayload.push_back(0x01); InitialPayload.push_back(0x2C);
    InitialPayload.push_back(0x00); InitialPayload.push_back(0x04);
    InitialPayload.push_back(127); InitialPayload.push_back(0);
    InitialPayload.push_back(0); InitialPayload.push_back(1);
  }

  std::set<std::vector<uint8_t>> Seen;
  std::queue<std::vector<uint8_t>> Queue;

  Queue.push(InitialPayload);
  Seen.insert(InitialPayload);

  std::vector<uint8_t> InitialPacket = Header;
  InitialPacket.insert(InitialPacket.end(), InitialPayload.begin(), InitialPayload.end());
  Results.push_back(InitialPacket);

  size_t Iterations = 0;
  while (!Queue.empty() && Iterations < Config_.MaxIterations) {
    auto Current = Queue.front();
    Queue.pop();
    Iterations++;

    std::vector<uint8_t> FullPacket = Header;
    FullPacket.insert(FullPacket.end(), Current.begin(), Current.end());

    if (FullPacket.size() > Config_.MaxPayloadLength + Header.size()) {
      continue;
    }

    auto RunResult = Runner_->run(FullPacket);

    for (const auto &TestCase : RunResult.GeneratedTestCases) {
      if (TestCase.size() <= Header.size()) {
        continue;
      }

      std::vector<uint8_t> NewPayload(TestCase.begin() + Header.size(),
                                       TestCase.end());
      if (Seen.count(NewPayload) == 0 &&
          NewPayload.size() <= Config_.MaxPayloadLength) {
        Seen.insert(NewPayload);
        Queue.push(NewPayload);

        std::vector<uint8_t> NewPacket = Header;
        NewPacket.insert(NewPacket.end(), NewPayload.begin(), NewPayload.end());
        Results.push_back(NewPacket);
      }
    }
  }

  return Results;
}

} // namespace geninput
