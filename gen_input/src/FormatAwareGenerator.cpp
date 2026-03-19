// FormatAwareGenerator.cpp - Format-aware seed input generator implementation
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../include/FormatAwareGenerator.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>

namespace geninput {

namespace {

size_t computeByteDifference(const std::vector<uint8_t> &Left,
                             const std::vector<uint8_t> &Right) {
  const size_t MinSize = std::min(Left.size(), Right.size());
  size_t Differences = Left.size() > Right.size() ? Left.size() - Right.size()
                                                  : Right.size() - Left.size();

  for (size_t Index = 0; Index < MinSize; ++Index) {
    if (Left[Index] != Right[Index]) {
      ++Differences;
    }
  }

  return Differences;
}

std::optional<size_t> consumeDnsName(const std::vector<uint8_t> &Packet,
                                     size_t Offset) {
  size_t Position = Offset;
  size_t Remaining = Packet.size();

  while (Position < Packet.size() && Remaining > 0) {
    const uint8_t Length = Packet[Position];
    if ((Length & 0xC0) == 0xC0) {
      if (Position + 1 >= Packet.size()) {
        return std::nullopt;
      }
      return Position + 2;
    }

    if (Length == 0) {
      return Position + 1;
    }

    if (Length > 63 || Position + 1 + Length > Packet.size()) {
      return std::nullopt;
    }

    Position += 1 + Length;
    --Remaining;
  }

  return std::nullopt;
}

std::optional<size_t> getQuestionSectionEnd(const std::vector<uint8_t> &Packet) {
  if (Packet.size() < 12) {
    return std::nullopt;
  }

  const uint16_t QuestionCount =
      (static_cast<uint16_t>(Packet[4]) << 8) | Packet[5];
  size_t Position = 12;

  for (uint16_t Index = 0; Index < QuestionCount; ++Index) {
    auto NameEnd = consumeDnsName(Packet, Position);
    if (!NameEnd || *NameEnd + 4 > Packet.size()) {
      return std::nullopt;
    }
    Position = *NameEnd + 4;
  }

  return Position;
}

std::optional<size_t>
getFirstAnswerRdLengthOffset(const std::vector<uint8_t> &Packet) {
  if (Packet.size() < 12) {
    return std::nullopt;
  }

  const uint16_t AnswerCount = (static_cast<uint16_t>(Packet[6]) << 8) | Packet[7];
  if (AnswerCount == 0) {
    return std::nullopt;
  }

  auto QuestionEnd = getQuestionSectionEnd(Packet);
  if (!QuestionEnd) {
    return std::nullopt;
  }

  auto NameEnd = consumeDnsName(Packet, *QuestionEnd);
  if (!NameEnd || *NameEnd + 10 > Packet.size()) {
    return std::nullopt;
  }

  return *NameEnd + 8;
}

struct ParsedDnsQuestion {
  uint16_t ID = 0;
  bool RecursionDesired = false;
  std::string Name;
  uint16_t Type = 1;
  uint16_t DnsClass = 1;
};

std::optional<ParsedDnsQuestion>
parseDnsQuestionSpec(const std::vector<uint8_t> &Packet) {
  ParsedDnsQuestion Result;
  auto NameEnd = getQuestionSectionEnd(Packet);

  if (!NameEnd || *NameEnd < 17 || Packet.size() < *NameEnd) {
    return std::nullopt;
  }
  if (((static_cast<uint16_t>(Packet[4]) << 8) | Packet[5]) == 0) {
    return std::nullopt;
  }

  Result.ID = (static_cast<uint16_t>(Packet[0]) << 8) | Packet[1];
  Result.RecursionDesired = (Packet[2] & 0x01) != 0;
  Result.Name = DNSNameCodec::decode(Packet, 12);
  Result.Type = (static_cast<uint16_t>(Packet[*NameEnd - 4]) << 8) |
                Packet[*NameEnd - 3];
  Result.DnsClass = (static_cast<uint16_t>(Packet[*NameEnd - 2]) << 8) |
                    Packet[*NameEnd - 1];

  if (Result.Name.empty()) {
    return std::nullopt;
  }

  return Result;
}

std::string getParentZone(const std::string &Name) {
  const auto Dot = Name.find('.');

  if (Dot == std::string::npos || Dot + 1 >= Name.size()) {
    return Name;
  }

  return Name.substr(Dot + 1);
}

void appendU16Le(std::vector<uint8_t> &Output, size_t Value) {
  Output.push_back(static_cast<uint8_t>(Value & 0xFF));
  Output.push_back(static_cast<uint8_t>((Value >> 8) & 0xFF));
}

std::vector<uint8_t>
buildAddressRDataForQuestion(const ParsedDnsQuestion &Question, uint8_t Variant) {
  switch (Question.Type) {
  case 1:
    return {127, 0, 0, Variant};
  case 28:
    return {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, Variant};
  default:
    return {127, 0, 0, Variant};
  }
}

std::vector<uint8_t>
buildBenignResponse(const std::vector<uint8_t> &Query,
                    const ParsedDnsQuestion &Question, uint32_t TTL,
                    uint8_t VariantOctet) {
  switch (Question.Type) {
  case 1:
  case 28:
    return DNSPacketBuilder::buildResponseFromQuery(
        Query, buildAddressRDataForQuestion(Question, VariantOctet), Question.Type,
        TTL);
  case 2:
    return DNSPacketBuilder()
        .setID(Question.ID)
        .asResponse()
        .setRecursionDesired(Question.RecursionDesired)
        .setRecursionAvailable(true)
        .addQuestion(Question.Name, Question.Type, Question.DnsClass)
        .addAnswer(Question.Name, 2, Question.DnsClass, TTL,
                   DNSNameCodec::encode("ns1." + getParentZone(Question.Name)))
        .addAdditional("ns1." + getParentZone(Question.Name), 1, Question.DnsClass,
                       TTL, {127, 0, 0, VariantOctet})
        .build();
  case 5:
    return DNSPacketBuilder()
        .setID(Question.ID)
        .asResponse()
        .setRecursionDesired(Question.RecursionDesired)
        .setRecursionAvailable(true)
        .addQuestion(Question.Name, Question.Type, Question.DnsClass)
        .addAnswer(Question.Name, 5, Question.DnsClass, TTL,
                   DNSNameCodec::encode("edge." + getParentZone(Question.Name)))
        .addAdditional("edge." + getParentZone(Question.Name), 1,
                       Question.DnsClass, TTL, {127, 0, 0, VariantOctet})
        .build();
  default:
    return DNSPacketBuilder()
        .setID(Question.ID)
        .asResponse()
        .setRecursionDesired(Question.RecursionDesired)
        .setRecursionAvailable(true)
        .addQuestion(Question.Name, Question.Type, Question.DnsClass)
        .addAnswer(Question.Name, 5, Question.DnsClass, TTL,
                   DNSNameCodec::encode("cache." + getParentZone(Question.Name)))
        .addAdditional("cache." + getParentZone(Question.Name), 1,
                       Question.DnsClass, TTL, {127, 0, 0, VariantOctet})
        .build();
  }
}

std::vector<uint8_t>
buildAuthorityPoisonResponse(const ParsedDnsQuestion &Question,
                             bool InBailiwick, uint32_t TTL = 300,
                             bool IncludeForgedAnswer = false) {
  const std::string Zone = getParentZone(Question.Name);
  const std::string NameServer =
      InBailiwick ? ("ns1." + Zone) : "ns1.attacker.test";

  DNSPacketBuilder Builder;
  Builder.setID(Question.ID)
      .asResponse()
      .setRecursionDesired(Question.RecursionDesired)
      .setRecursionAvailable(true)
      .addQuestion(Question.Name, Question.Type, Question.DnsClass);

  if (IncludeForgedAnswer) {
    Builder.addAnswer(Question.Name, 5, Question.DnsClass, TTL,
                      DNSNameCodec::encode("cache." + Zone));
  }

  return Builder.addAuthority(Zone, 2, Question.DnsClass, TTL,
                              DNSNameCodec::encode(NameServer))
      .addAdditional(NameServer, 1, Question.DnsClass, TTL, {6, 6, 6, 6})
      .build();
}

std::vector<uint8_t>
buildCnamePoisonResponse(const ParsedDnsQuestion &Question, uint32_t TTL = 300,
                         bool IncludeAuthority = false) {
  const std::string Zone = getParentZone(Question.Name);
  const std::string Alias = "cache.attacker.test";

  DNSPacketBuilder Builder;
  Builder.setID(Question.ID)
      .asResponse()
      .setRecursionDesired(Question.RecursionDesired)
      .setRecursionAvailable(true)
      .addQuestion(Question.Name, Question.Type, Question.DnsClass)
      .addAnswer(Question.Name, 5, Question.DnsClass, TTL,
                 DNSNameCodec::encode(Alias))
      .addAdditional(Alias, 1, Question.DnsClass, TTL, {6, 6, 6, 6});

  if (IncludeAuthority) {
    Builder.addAuthority(Zone, 2, Question.DnsClass, TTL,
                         DNSNameCodec::encode("ns1.attacker.test"));
  }

  return Builder.build();
}

std::vector<uint8_t>
buildNxdomainPoisonResponse(const ParsedDnsQuestion &Question, bool InBailiwick,
                            uint32_t TTL) {
  const std::string Zone = getParentZone(Question.Name);
  const std::string NameServer =
      InBailiwick ? ("ns1." + Zone) : "ns.evil.test";

  return DNSPacketBuilder()
      .setID(Question.ID)
      .asResponse()
      .setRecursionDesired(Question.RecursionDesired)
      .setRecursionAvailable(true)
      .setRCode(3)
      .addQuestion(Question.Name, Question.Type, Question.DnsClass)
      .addAuthority(Zone, 2, Question.DnsClass, TTL,
                    DNSNameCodec::encode(NameServer))
      .addAdditional(NameServer, 1, Question.DnsClass, TTL, {6, 6, 6, 7})
      .build();
}

std::vector<uint8_t>
buildPostCheckQuery(const std::vector<uint8_t> &Query, uint16_t Delta) {
  if (Query.size() < 2) {
    return Query;
  }

  std::vector<uint8_t> PostCheck = Query;
  uint16_t ID = (static_cast<uint16_t>(PostCheck[0]) << 8) | PostCheck[1];
  ID = static_cast<uint16_t>(ID + Delta);
  PostCheck[0] = static_cast<uint8_t>((ID >> 8) & 0xFF);
  PostCheck[1] = static_cast<uint8_t>(ID & 0xFF);
  return PostCheck;
}

std::vector<std::vector<uint8_t>>
buildPoisonResponseTemplates(const std::vector<uint8_t> &Query,
                             const ParsedDnsQuestion &Question,
                             bool IncludeExtendedTemplates) {
  std::vector<std::vector<uint8_t>> Results;

  Results.push_back(buildBenignResponse(Query, Question, 300, 1));
  Results.push_back(buildAuthorityPoisonResponse(Question, true));
  Results.push_back(buildAuthorityPoisonResponse(Question, false));
  Results.push_back(buildCnamePoisonResponse(Question));

  if (IncludeExtendedTemplates) {
    Results.push_back(buildBenignResponse(Query, Question, 30, 2));
    Results.push_back(
        buildAuthorityPoisonResponse(Question, true, 30, true));
    Results.push_back(
        buildAuthorityPoisonResponse(Question, false, 900, true));
    Results.push_back(buildCnamePoisonResponse(Question, 30, true));
    Results.push_back(buildNxdomainPoisonResponse(Question, true, 60));
    Results.push_back(buildNxdomainPoisonResponse(Question, false, 600));
  }

  return Results;
}

std::vector<uint8_t>
buildStatefulTranscriptBlob(const std::vector<uint8_t> &ClientQuery,
                            const std::vector<std::vector<uint8_t>> &Responses,
                            const std::vector<uint8_t> &PostCheckQuery) {
  std::vector<uint8_t> Output;

  if (Responses.size() > 255 || ClientQuery.empty() || ClientQuery.size() > 0xFFFF ||
      PostCheckQuery.size() > 0xFFFF) {
    return {};
  }
  for (const auto &Response : Responses) {
    if (Response.empty() || Response.size() > 0xFFFF) {
      return {};
    }
  }

  Output.insert(Output.end(), {'D', 'S', 'T', '1'});
  Output.push_back(static_cast<uint8_t>(Responses.size()));
  Output.push_back(0);
  appendU16Le(Output, ClientQuery.size());
  appendU16Le(Output, PostCheckQuery.size());
  for (const auto &Response : Responses) {
    appendU16Le(Output, Response.size());
  }
  Output.insert(Output.end(), ClientQuery.begin(), ClientQuery.end());
  for (const auto &Response : Responses) {
    Output.insert(Output.end(), Response.begin(), Response.end());
  }
  Output.insert(Output.end(), PostCheckQuery.begin(), PostCheckQuery.end());
  return Output;
}

bool addUniquePacket(std::vector<std::vector<uint8_t>> &Results,
                     std::set<std::vector<uint8_t>> &Seen,
                     std::vector<uint8_t> Packet,
                     const std::function<void(const std::vector<uint8_t> &)> &Cb) {
  if (Packet.empty() || Seen.count(Packet) > 0) {
    return false;
  }

  Seen.insert(Packet);
  Results.push_back(std::move(Packet));
  if (Cb) {
    Cb(Results.back());
  }
  return true;
}

bool appendTranscriptVariant(
    std::vector<std::vector<uint8_t>> &Results, std::set<std::vector<uint8_t>> &Seen,
    const std::vector<uint8_t> &Query, const std::vector<std::vector<uint8_t>> &Responses,
    const std::vector<uint8_t> &PostCheckQuery, size_t MaxTranscripts,
    const std::function<void(const std::vector<uint8_t> &)> &Cb) {
  if (Results.size() >= MaxTranscripts) {
    return false;
  }

  return addUniquePacket(Results, Seen,
                         buildStatefulTranscriptBlob(Query, Responses, PostCheckQuery),
                         Cb);
}

void setDnsU16(std::vector<uint8_t> &Packet, size_t Offset, uint16_t Value) {
  if (Offset + 1 >= Packet.size()) {
    return;
  }
  Packet[Offset] = static_cast<uint8_t>((Value >> 8) & 0xFF);
  Packet[Offset + 1] = static_cast<uint8_t>(Value & 0xFF);
}

uint16_t getDnsU16(const std::vector<uint8_t> &Packet, size_t Offset) {
  if (Offset + 1 >= Packet.size()) {
    return 0;
  }
  return (static_cast<uint16_t>(Packet[Offset]) << 8) |
         static_cast<uint16_t>(Packet[Offset + 1]);
}

std::vector<std::vector<uint8_t>>
generateDNSStructuralMutations(const std::vector<uint8_t> &Packet,
                               size_t MaxInputLength) {
  std::vector<std::vector<uint8_t>> Mutations;

  if (Packet.size() < 12) {
    return Mutations;
  }

  auto addMutation = [&](std::vector<uint8_t> Mutation) {
    if (MaxInputLength > 0 && Mutation.size() > MaxInputLength) {
      return;
    }
    if (std::find(Mutations.begin(), Mutations.end(), Mutation) == Mutations.end()) {
      Mutations.push_back(std::move(Mutation));
    }
  };

  if (Packet.size() > 13 && Packet[12] > 0 && (Packet[12] & 0xC0) == 0 &&
      Packet[12] < 64) {
    auto IncreasedLabel = Packet;
    IncreasedLabel[12] = Packet[12] == 63 ? 62 : static_cast<uint8_t>(Packet[12] + 1);
    addMutation(std::move(IncreasedLabel));

    if (Packet[12] > 1) {
      auto DecreasedLabel = Packet;
      DecreasedLabel[12] = static_cast<uint8_t>(Packet[12] - 1);
      addMutation(std::move(DecreasedLabel));
    }
  }

  if (Packet.size() > 14) {
    auto CompressionPointerMutation = Packet;
    CompressionPointerMutation[12] = 0xC0;
    CompressionPointerMutation[13] = 0x0C;
    addMutation(std::move(CompressionPointerMutation));
  }

  auto RdLengthOffset = getFirstAnswerRdLengthOffset(Packet);
  if (RdLengthOffset && *RdLengthOffset + 1 < Packet.size()) {
    const uint16_t DeclaredLength =
        (static_cast<uint16_t>(Packet[*RdLengthOffset]) << 8) |
        Packet[*RdLengthOffset + 1];

    auto LowerLengthMutation = Packet;
    const uint16_t LowerLength = DeclaredLength == 0 ? 1 : DeclaredLength - 1;
    LowerLengthMutation[*RdLengthOffset] =
        static_cast<uint8_t>((LowerLength >> 8) & 0xFF);
    LowerLengthMutation[*RdLengthOffset + 1] = static_cast<uint8_t>(LowerLength & 0xFF);
    addMutation(std::move(LowerLengthMutation));

    if (DeclaredLength < 0xFFFF) {
      auto HigherLengthMutation = Packet;
      const uint16_t HigherLength = static_cast<uint16_t>(DeclaredLength + 1);
      HigherLengthMutation[*RdLengthOffset] =
          static_cast<uint8_t>((HigherLength >> 8) & 0xFF);
      HigherLengthMutation[*RdLengthOffset + 1] =
          static_cast<uint8_t>(HigherLength & 0xFF);
      addMutation(std::move(HigherLengthMutation));
    }
  }

  return Mutations;
}

}

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
  RemainingMalformationBudget_ = Config_.ControlledMalformationBudget;
}

void FormatAwareGenerator::addSeed(const std::vector<uint8_t> &Seed) {
  if (!Format_)
    return;

  FormatWorkItem Item;
  Item.Input = Format_->parse(Seed);
  if (!Item.Input) {
    Item.Input = std::make_unique<StructuredInput>(*Format_);
  }
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

  auto Start = std::chrono::steady_clock::now();
  auto UpdateElapsed = [&]() {
    Stats_.TotalTimeMs =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() -
                                                  Start)
            .count();
  };

  RemainingMalformationBudget_ = Config_.ControlledMalformationBudget;
  Stats_.TotalTimeMs = 0.0;

  // If no seeds, create one from format
  if (Queue_.empty()) {
    auto DefaultSeed = Format_->createSeed();
    addSeed(DefaultSeed);
  }

  while (!Queue_.empty()) {
    UpdateElapsed();
    if (shouldStop()) {
      break;
    }

    FormatWorkItem Item = std::move(const_cast<FormatWorkItem &>(Queue_.top()));
    Queue_.pop();

    processWorkItem(Item);

    Stats_.TotalIterations++;
    UpdateElapsed();

    if (ProgressCb_) {
      ProgressCb_(Stats_.TotalIterations, Queue_.size(), ValidInputs_.size());
    }
  }

  UpdateElapsed();

  FormatGeneratorResult Result;
  Result.ValidInputs = ValidInputs_;
  Result.AcceptedInputs = AcceptedInputs_;
  return Result;
}

void FormatAwareGenerator::processWorkItem(FormatWorkItem &Item) {
  const bool UseTailFocus = shouldApplyTailFocus();

  // Run SymCC on the current input
  auto RunResult = Runner_->run(Item.RawBytes);
  Stats_.TotalSymCCRuns++;

  if (RunResult.Accepted) {
    addAcceptedInput(Item.RawBytes);
  }

  // Process generated test cases
  for (const auto &TestCase : RunResult.GeneratedTestCases) {
    auto NormalizedTestCase =
        normalizeWithControlledFix(TestCase, UseTailFocus);
    NormalizedTestCase = applySemanticFreeze(NormalizedTestCase, Item.RawBytes);
    if (SeenInputs_.count(NormalizedTestCase) > 0)
      continue;

    const size_t ByteDifference =
        computeByteDifference(Item.RawBytes, NormalizedTestCase);
    if (Config_.MaxByteDiff > 0 && ByteDifference > Config_.MaxByteDiff) {
      continue;
    }

    if (Config_.StrictFormat && !checkFormatConstraints(NormalizedTestCase)) {
      Stats_.FormatViolations++;
      continue;
    }

    addValidInput(NormalizedTestCase);
    SeenInputs_.insert(NormalizedTestCase);

    FormatWorkItem NewItem;
    NewItem.Input = Format_->parse(NormalizedTestCase);
    if (!NewItem.Input) {
      NewItem.Input = std::make_unique<StructuredInput>(*Format_);
    }
    NewItem.RawBytes = std::move(NormalizedTestCase);
    NewItem.Depth = Item.Depth + 1;
    size_t LocalityBonus = 0;
    if (Config_.MaxByteDiff > 0) {
      LocalityBonus = Config_.MaxByteDiff > ByteDifference
                          ? Config_.MaxByteDiff - ByteDifference
                          : 0;
      LocalityBonus = std::min<size_t>(LocalityBonus, 50);
    }
    NewItem.Priority = 50 - static_cast<int>(NewItem.Depth) +
                       static_cast<int>(LocalityBonus);

    if (NewItem.Depth <= Config_.MaxRecursionDepth) {
      Queue_.push(std::move(NewItem));
    }
  }

  auto DnsMutations = generateDNSStructuralMutations(Item.RawBytes, Config_.MaxInputLength);
  for (const auto &Mutation : DnsMutations) {
    auto NormalizedMutation = normalizeWithControlledFix(Mutation, UseTailFocus);
    NormalizedMutation = applySemanticFreeze(NormalizedMutation, Item.RawBytes);
    if (SeenInputs_.count(NormalizedMutation) > 0) {
      continue;
    }

    if (Config_.StrictFormat && !checkFormatConstraints(NormalizedMutation)) {
      Stats_.FormatViolations++;
      continue;
    }

    addValidInput(NormalizedMutation);
    SeenInputs_.insert(NormalizedMutation);

    FormatWorkItem MutatedItem;
    MutatedItem.Input = Format_->parse(NormalizedMutation);
    if (!MutatedItem.Input) {
      MutatedItem.Input = std::make_unique<StructuredInput>(*Format_);
    }
    MutatedItem.RawBytes = std::move(NormalizedMutation);
    MutatedItem.Depth = Item.Depth + 1;
    MutatedItem.Priority = 45 - static_cast<int>(MutatedItem.Depth);

    if (MutatedItem.Depth <= Config_.MaxRecursionDepth) {
      Queue_.push(std::move(MutatedItem));
    }
  }

  if (UseTailFocus) {
    auto TailMutations = generateTailStrategyMutations(Item.RawBytes);
    for (const auto &Mutation : TailMutations) {
      auto NormalizedMutation = normalizeWithControlledFix(Mutation, true);
      if (SeenInputs_.count(NormalizedMutation) > 0) {
        continue;
      }

      if (Config_.StrictFormat && !checkFormatConstraints(NormalizedMutation)) {
        Stats_.FormatViolations++;
        continue;
      }

      addValidInput(NormalizedMutation);
      SeenInputs_.insert(NormalizedMutation);

      FormatWorkItem MutatedItem;
      MutatedItem.Input = Format_->parse(NormalizedMutation);
      if (!MutatedItem.Input) {
        MutatedItem.Input = std::make_unique<StructuredInput>(*Format_);
      }
      MutatedItem.RawBytes = std::move(NormalizedMutation);
      MutatedItem.Depth = Item.Depth + 1;
      MutatedItem.Priority = 48 - static_cast<int>(MutatedItem.Depth);

      if (MutatedItem.Depth <= Config_.MaxRecursionDepth) {
        Queue_.push(std::move(MutatedItem));
      }
    }
  }

  // Field mutation exploration
  if (Config_.EnableFieldMutation && Item.Depth < Config_.MaxRecursionDepth) {
    for (const auto &Field : Format_->getFields()) {
      if (!Field.IsSymbolic)
        continue;

      auto Variants = exploreField(*Item.Input, Field.Name);
      for (auto &Variant : Variants) {
        Variant.RawBytes = updateComputedFields(std::move(Variant.RawBytes));
        Variant.RawBytes = applySemanticFreeze(Variant.RawBytes, Item.RawBytes);
        if (SeenInputs_.count(Variant.RawBytes) > 0)
          continue;

        if (Config_.StrictFormat && !checkFormatConstraints(Variant.RawBytes)) {
          Stats_.FormatViolations++;
          continue;
        }

        auto ParsedVariant = Format_->parse(Variant.RawBytes);
        if (!ParsedVariant) {
          ParsedVariant = std::make_unique<StructuredInput>(*Format_);
        }
        Variant.Input = std::move(ParsedVariant);

        addValidInput(Variant.RawBytes);
        SeenInputs_.insert(Variant.RawBytes);
        Queue_.push(std::move(Variant));
        Stats_.FieldMutations++;
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

  return Format_->validate(Input);
}

std::vector<uint8_t>
FormatAwareGenerator::updateComputedFields(std::vector<uint8_t> Input) {
  if (Input.size() < 12)
    return Input;

  uint16_t QdCount = getDnsU16(Input, 4);
  auto QuestionEnd = getQuestionSectionEnd(Input);
  bool QuestionValid = QuestionEnd.has_value();
  if (QdCount > 0 && !QuestionValid) {
    setDnsU16(Input, 4, 0);
  } else if (QdCount > 1 && QuestionValid) {
    setDnsU16(Input, 4, 1);
  }

  bool HasAnswer = false;
  auto RdLengthOffset = getFirstAnswerRdLengthOffset(Input);
  if (RdLengthOffset && (*RdLengthOffset + 1) < Input.size()) {
    size_t RdataStart = *RdLengthOffset + 2;
    size_t RdataSize = Input.size() - RdataStart;
    uint16_t FixedLength =
        static_cast<uint16_t>(std::min<size_t>(RdataSize, 0xFFFF));
    setDnsU16(Input, *RdLengthOffset, FixedLength);
    HasAnswer = true;
  }

  setDnsU16(Input, 6, HasAnswer ? 1 : 0);
  setDnsU16(Input, 8, 0);
  setDnsU16(Input, 10, 0);

  return Input;
}

std::vector<uint8_t> FormatAwareGenerator::applySemanticFreeze(
    const std::vector<uint8_t> &Candidate,
    const std::vector<uint8_t> &Reference) {
  if (!Config_.FreezeDNSHeaderQuestion || Reference.size() < 12) {
    return Candidate;
  }

  auto QuestionEnd = getQuestionSectionEnd(Reference);
  if (!QuestionEnd || *QuestionEnd > Reference.size()) {
    return Candidate;
  }

  std::vector<uint8_t> Frozen = Candidate;
  if (Frozen.size() < *QuestionEnd) {
    Frozen.resize(*QuestionEnd, 0);
  }

  if (Frozen.size() >= 4 && Reference.size() >= 4) {
    std::copy(Reference.begin(), Reference.begin() + 4, Frozen.begin());
  }
  if (*QuestionEnd > 12 && Frozen.size() >= *QuestionEnd) {
    std::copy(Reference.begin() + 12, Reference.begin() + *QuestionEnd,
              Frozen.begin() + 12);
  }

  return Frozen;
}

bool FormatAwareGenerator::shouldApplyTailFocus() const {
  if (Config_.TailFocusLastBytes == 0 || Config_.TailStrategies.empty()) {
    return false;
  }
  if (Config_.TailFocusRatio <= 0.0) {
    return false;
  }
  if (Config_.TailFocusRatio >= 1.0) {
    return true;
  }

  constexpr size_t Window = 1000;
  const size_t Threshold =
      static_cast<size_t>(Config_.TailFocusRatio * static_cast<double>(Window));
  return (Stats_.TotalIterations % Window) < Threshold;
}

std::vector<std::vector<uint8_t>>
FormatAwareGenerator::generateTailStrategyMutations(
    const std::vector<uint8_t> &Packet) {
  std::vector<std::vector<uint8_t>> Mutations;
  if (Packet.empty() || Config_.TailFocusLastBytes == 0) {
    return Mutations;
  }

  const std::vector<uint8_t> FrozenBase = applySemanticFreeze(Packet, Packet);
  const size_t TailWindow = std::min(Config_.TailFocusLastBytes, FrozenBase.size());
  const size_t TailStart = FrozenBase.size() - TailWindow;

  auto addMutation = [&](std::vector<uint8_t> Mutation) {
    if (Config_.MaxInputLength > 0 && Mutation.size() > Config_.MaxInputLength) {
      return;
    }
    if (std::find(Mutations.begin(), Mutations.end(), Mutation) == Mutations.end()) {
      Mutations.push_back(std::move(Mutation));
    }
  };

  for (const auto &Strategy : Config_.TailStrategies) {
    if (Strategy == "truncate") {
      if (FrozenBase.size() > TailStart + 1) {
        auto Mutation = FrozenBase;
        const size_t RemoveCount = std::max<size_t>(1, TailWindow / 2);
        const size_t NewSize =
            std::max(TailStart, Mutation.size() > RemoveCount
                                    ? Mutation.size() - RemoveCount
                                    : TailStart);
        Mutation.resize(NewSize);
        addMutation(std::move(Mutation));
      }
      continue;
    }

    if (Strategy == "append") {
      auto Mutation = FrozenBase;
      const size_t AppendCount = std::max<size_t>(1, std::min<size_t>(8, TailWindow));
      for (size_t Index = 0; Index < AppendCount; ++Index) {
        Mutation.push_back(static_cast<uint8_t>((Index * 17) & 0xFF));
      }
      addMutation(std::move(Mutation));
      continue;
    }

    if (Strategy == "bitflip") {
      if (!FrozenBase.empty()) {
        auto MutationA = FrozenBase;
        MutationA.back() ^= 0x01;
        addMutation(std::move(MutationA));

        auto MutationB = FrozenBase;
        MutationB[TailStart] ^= 0x80;
        addMutation(std::move(MutationB));
      }
      continue;
    }

    if (Strategy == "rdlength-mismatch") {
      auto RdLengthOffset = getFirstAnswerRdLengthOffset(FrozenBase);
      if (RdLengthOffset && *RdLengthOffset + 1 < FrozenBase.size()) {
        const uint16_t DeclaredLength = getDnsU16(FrozenBase, *RdLengthOffset);
        auto Mutation = FrozenBase;
        setDnsU16(Mutation, *RdLengthOffset,
                  static_cast<uint16_t>(DeclaredLength + 2));
        addMutation(std::move(Mutation));
      }
      continue;
    }

    if (Strategy == "count-mismatch") {
      if (FrozenBase.size() >= 12) {
        auto Mutation = FrozenBase;
        const uint16_t AnswerCount = getDnsU16(Mutation, 6);
        setDnsU16(Mutation, 6, static_cast<uint16_t>(AnswerCount + 1));
        addMutation(std::move(Mutation));
      }
      continue;
    }
  }

  return Mutations;
}

std::vector<uint8_t> FormatAwareGenerator::normalizeWithControlledFix(
    std::vector<uint8_t> Input,
    bool PreferMalformed,
    bool *KeptMalformed) {
  if (KeptMalformed) {
    *KeptMalformed = false;
  }

  if (PreferMalformed && RemainingMalformationBudget_ > 0) {
    --RemainingMalformationBudget_;
    if (KeptMalformed) {
      *KeptMalformed = true;
    }
    return Input;
  }

  return updateComputedFields(std::move(Input));
}

void FormatAwareGenerator::addValidInput(const std::vector<uint8_t> &Input) {
  if (std::find(ValidInputs_.begin(), ValidInputs_.end(), Input) !=
      ValidInputs_.end()) {
    return;
  }

  ValidInputs_.push_back(Input);

  if (InputCb_) {
    InputCb_(Input);
  }
}

void FormatAwareGenerator::addAcceptedInput(const std::vector<uint8_t> &Input) {
  if (std::find(AcceptedInputs_.begin(), AcceptedInputs_.end(), Input) ==
      AcceptedInputs_.end()) {
    AcceptedInputs_.push_back(Input);
    Stats_.AcceptedCount++;
  }

  addValidInput(Input);
}

bool FormatAwareGenerator::shouldStop() const {
  if (Stats_.TotalIterations >= Config_.MaxIterations) {
    return true;
  }
  
  // Check time-based stopping condition
  if (Config_.TimeoutSec > 0 && Stats_.TotalTimeMs > 0) {
    double ElapsedSec = Stats_.TotalTimeMs / 1000.0;
    if (ElapsedSec >= static_cast<double>(Config_.TimeoutSec)) {
      return true;
    }
  }
  
  return false;
}

void FormatAwareGenerator::reset() {
  while (!Queue_.empty())
    Queue_.pop();
  SeenInputs_.clear();
  ValidInputs_.clear();
  AcceptedInputs_.clear();
  Stats_ = FormatGeneratorStats{};
  RemainingMalformationBudget_ = Config_.ControlledMalformationBudget;
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

  std::vector<std::vector<uint8_t>> InitialPayloads;
  if (Config_.IsResponse) {
    auto buildPayloadWithRDataLen = [](size_t RDataLength) {
      std::vector<uint8_t> Payload;
      auto EncodedName = DNSNameCodec::encode("a");

      Payload.insert(Payload.end(), EncodedName.begin(), EncodedName.end());
      Payload.push_back(0x00);
      Payload.push_back(0x01);
      Payload.push_back(0x00);
      Payload.push_back(0x01);

      Payload.insert(Payload.end(), EncodedName.begin(), EncodedName.end());
      Payload.push_back(0x00);
      Payload.push_back(0x01);
      Payload.push_back(0x00);
      Payload.push_back(0x01);
      Payload.push_back(0x00);
      Payload.push_back(0x00);
      Payload.push_back(0x01);
      Payload.push_back(0x2C);
      const uint16_t DeclaredLength = static_cast<uint16_t>(std::min<size_t>(RDataLength, 0xFFFF));
      Payload.push_back(static_cast<uint8_t>((DeclaredLength >> 8) & 0xFF));
      Payload.push_back(static_cast<uint8_t>(DeclaredLength & 0xFF));

      for (size_t Index = 0; Index < RDataLength; ++Index) {
        Payload.push_back(static_cast<uint8_t>((Index * 31) & 0xFF));
      }
      return Payload;
    };

    InitialPayloads.push_back(buildPayloadWithRDataLen(0));
    InitialPayloads.push_back(buildPayloadWithRDataLen(1));
    InitialPayloads.push_back(buildPayloadWithRDataLen(4));
    InitialPayloads.push_back(buildPayloadWithRDataLen(16));
  } else {
    InitialPayloads.push_back({});
  }

  std::set<std::vector<uint8_t>> Seen;
  std::queue<std::vector<uint8_t>> Queue;

  for (const auto &InitialPayload : InitialPayloads) {
    if (InitialPayload.size() > Config_.MaxPayloadLength) {
      continue;
    }
    if (Seen.insert(InitialPayload).second) {
      Queue.push(InitialPayload);
      std::vector<uint8_t> InitialPacket = Header;
      InitialPacket.insert(InitialPacket.end(), InitialPayload.begin(),
                           InitialPayload.end());
      Results.push_back(std::move(InitialPacket));
    }
  }

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

StatefulDNSGenerator::StatefulDNSGenerator() = default;

StatefulDNSGenerator::StatefulDNSGenerator(Config Cfg)
    : Config_(std::move(Cfg)) {}

void StatefulDNSGenerator::addQuerySeed(const std::vector<uint8_t> &Query) {
  QuerySeeds_.push_back(Query);
}

void StatefulDNSGenerator::addResponseSeed(const std::vector<uint8_t> &Response) {
  ResponseSeeds_.push_back(Response);
}

std::vector<std::vector<uint8_t>> StatefulDNSGenerator::generatePoisonResponses() {
  std::vector<std::vector<uint8_t>> Results;
  std::set<std::vector<uint8_t>> Seen;
  std::vector<std::vector<uint8_t>> Queries = QuerySeeds_;

  if (Queries.empty()) {
    Queries.push_back(DNSPacketBuilder::buildQuery("www.example.com", 1));
    Queries.push_back(DNSPacketBuilder::buildQuery("ns.target.test", 28));
  }

  for (const auto &ResponseSeed : ResponseSeeds_) {
    if (Results.size() >= Config_.MaxVariantsPerQuery) {
      break;
    }
    addUniquePacket(Results, Seen, ResponseSeed, InputCb_);
  }

  for (const auto &Query : Queries) {
    auto Question = parseDnsQuestionSpec(Query);
    size_t Before = Results.size();

    if (!Question) {
      continue;
    }

    for (const auto &Response : buildPoisonResponseTemplates(
             Query, *Question, Config_.GenerateExtendedPoisonTemplates)) {
      if (Results.size() - Before >= Config_.MaxVariantsPerQuery) {
        break;
      }
      addUniquePacket(Results, Seen, Response, InputCb_);
    }

    if (Results.size() - Before >= Config_.MaxVariantsPerQuery) {
      continue;
    }
  }

  return Results;
}

std::vector<std::vector<uint8_t>> StatefulDNSGenerator::generateStatefulTranscripts() {
  std::vector<std::vector<uint8_t>> Results;
  std::set<std::vector<uint8_t>> Seen;
  std::vector<std::vector<uint8_t>> Queries = QuerySeeds_;

  if (Queries.empty()) {
    Queries.push_back(DNSPacketBuilder::buildQuery("www.example.com", 1));
  }

  for (const auto &Query : Queries) {
    std::vector<std::vector<uint8_t>> Responses = ResponseSeeds_;
    auto Question = parseDnsQuestionSpec(Query);
    std::vector<std::vector<uint8_t>> TemplateResponses;
    std::vector<uint8_t> BenignResponse;
    std::vector<std::vector<uint8_t>> PoisonResponses;
    const std::vector<uint8_t> PostCheckQuery =
        Config_.IncludePostCheck ? buildPostCheckQuery(Query, 0x0101)
                                 : std::vector<uint8_t>{};

    if (Question) {
      TemplateResponses = buildPoisonResponseTemplates(
          Query, *Question, Config_.GenerateExtendedPoisonTemplates);
      if (!TemplateResponses.empty()) {
        BenignResponse = TemplateResponses.front();
        Responses.insert(Responses.end(), TemplateResponses.begin(),
                         TemplateResponses.end());
        PoisonResponses.insert(PoisonResponses.end(), TemplateResponses.begin() + 1,
                               TemplateResponses.end());
      }
    }

    for (const auto &Response : Responses) {
      if (Results.size() >= Config_.MaxTranscripts) {
        return Results;
      }
      appendTranscriptVariant(Results, Seen, Query, {Response}, PostCheckQuery,
                              Config_.MaxTranscripts, InputCb_);
    }

    if (Config_.GenerateResponseRaces && Config_.MaxResponsesPerTranscript > 1 &&
        !BenignResponse.empty() && !PoisonResponses.empty()) {
      size_t Permutations = 0;
      const size_t PoisonLimit =
          std::min(PoisonResponses.size(), Config_.MaxRacePermutations);

      for (size_t Index = 0; Index < PoisonLimit; ++Index) {
        const auto &Poison = PoisonResponses[Index];

        if (Results.size() >= Config_.MaxTranscripts ||
            Permutations >= Config_.MaxRacePermutations) {
          break;
        }
        appendTranscriptVariant(Results, Seen, Query, {Poison, BenignResponse},
                                PostCheckQuery, Config_.MaxTranscripts, InputCb_);
        ++Permutations;

        if (Results.size() >= Config_.MaxTranscripts ||
            Permutations >= Config_.MaxRacePermutations) {
          break;
        }
        appendTranscriptVariant(Results, Seen, Query, {BenignResponse, Poison},
                                PostCheckQuery, Config_.MaxTranscripts, InputCb_);
        ++Permutations;

        if (Config_.MaxResponsesPerTranscript > 2 && PoisonLimit > 1 &&
            Results.size() < Config_.MaxTranscripts &&
            Permutations < Config_.MaxRacePermutations) {
          const auto &NextPoison = PoisonResponses[(Index + 1) % PoisonLimit];
          appendTranscriptVariant(Results, Seen, Query,
                                  {Poison, BenignResponse, NextPoison},
                                  PostCheckQuery, Config_.MaxTranscripts, InputCb_);
          ++Permutations;
        }
      }
    }

    if (Config_.MaxResponsesPerTranscript > 1 && Responses.size() >= 2 &&
        Results.size() < Config_.MaxTranscripts) {
      std::vector<std::vector<uint8_t>> Sequence;
      const size_t Limit =
          std::min(Config_.MaxResponsesPerTranscript, Responses.size());

      Sequence.insert(Sequence.end(), Responses.begin(), Responses.begin() + Limit);
      appendTranscriptVariant(Results, Seen, Query, Sequence, PostCheckQuery,
                              Config_.MaxTranscripts, InputCb_);
    }
  }

  return Results;
}

} // namespace geninput
