// FormatAwareGenerator.h - Format-aware seed input generator
//
// This file is part of the SymCC gen_input tool.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GENINPUT_FORMATAWAREGENERATOR_H
#define GENINPUT_FORMATAWAREGENERATOR_H

#include "BinaryFormat.h"
#include "InputPrefix.h"
#include "SymCCRunner.h"

#include <functional>
#include <memory>
#include <queue>
#include <set>
#include <string>
#include <vector>

namespace geninput {

/// Configuration for the format-aware generator
struct FormatGeneratorConfig {
  /// Maximum number of iterations
  size_t MaxIterations = 10000;

  /// Maximum input length
  size_t MaxInputLength = 4096;

  /// Timeout for each SymCC execution (seconds)
  unsigned TimeoutSec = 30;

  /// Maximum queue size (0 = unlimited)
  size_t MaxQueueSize = 100000;

  /// Whether to explore only within format constraints
  bool StrictFormat = true;

  /// Whether to generate variants by mutating symbolic fields
  bool EnableFieldMutation = true;

  /// Maximum variants per field
  size_t MaxVariantsPerField = 16;

  size_t MaxByteDiff = 32;

  /// Enable DNS name compression exploration
  bool EnableDNSCompression = true;

  /// Maximum recursion depth for nested structures
  size_t MaxRecursionDepth = 5;
};

/// Result of format-aware generation
struct FormatGeneratorResult {
  /// Generated valid inputs
  std::vector<std::vector<uint8_t>> ValidInputs;

  /// Inputs that reached acceptance
  std::vector<std::vector<uint8_t>> AcceptedInputs;

  /// Inputs that caused interesting behavior (new coverage)
  std::vector<std::vector<uint8_t>> InterestingInputs;
};

/// Statistics for format-aware generation
struct FormatGeneratorStats {
  size_t TotalIterations = 0;
  size_t TotalSymCCRuns = 0;
  size_t FieldMutations = 0;
  size_t FormatViolations = 0;
  size_t AcceptedCount = 0;
  double TotalTimeMs = 0.0;
};

/// Represents a work item for the generator queue
struct FormatWorkItem {
  /// Current structured input
  std::unique_ptr<StructuredInput> Input;

  /// Raw bytes (cached from Input)
  std::vector<uint8_t> RawBytes;

  /// Which field to explore next (empty = explore all)
  std::string FocusField;

  /// Exploration depth
  size_t Depth = 0;

  /// Priority (higher = process first)
  int Priority = 0;

  bool operator<(const FormatWorkItem &Other) const {
    return Priority < Other.Priority; // Lower priority = lower in queue
  }
};

/// Format-aware seed input generator
///
/// This generator understands binary format structure and uses that knowledge
/// to generate valid inputs more efficiently than byte-by-byte exploration.
///
/// Key features:
/// - Field-level symbolic exploration (instead of byte-level)
/// - Format constraint enforcement
/// - DNS-specific handling (name compression, label encoding)
/// - Checksum/length field auto-computation
class FormatAwareGenerator {
public:
  FormatAwareGenerator();
  explicit FormatAwareGenerator(const BinaryFormat &Format);
  FormatAwareGenerator(const BinaryFormat &Format, FormatGeneratorConfig Config);

  /// Set the binary format specification
  void setFormat(const BinaryFormat &Format);

  /// Set the SymCC runner
  void setRunner(std::shared_ptr<SymCCRunner> Runner);

  /// Set configuration
  void setConfig(FormatGeneratorConfig Config);

  /// Add a seed input to explore
  void addSeed(const std::vector<uint8_t> &Seed);
  void addSeed(const StructuredInput &Seed);

  /// Run the generator
  FormatGeneratorResult run();

  /// Set progress callback
  using ProgressCallback = std::function<void(size_t Iteration, size_t QueueSize,
                                               size_t ValidCount)>;
  void setProgressCallback(ProgressCallback Cb) { ProgressCb_ = std::move(Cb); }

  /// Set input found callback
  using InputCallback = std::function<void(const std::vector<uint8_t> &)>;
  void setInputCallback(InputCallback Cb) { InputCb_ = std::move(Cb); }

  /// Get current statistics
  const FormatGeneratorStats &getStats() const { return Stats_; }

  /// Reset generator state
  void reset();

private:
  const BinaryFormat *Format_ = nullptr;
  FormatGeneratorConfig Config_;
  std::shared_ptr<SymCCRunner> Runner_;

  // Work queue (priority queue)
  std::priority_queue<FormatWorkItem> Queue_;

  // Seen inputs (for deduplication)
  std::set<std::vector<uint8_t>> SeenInputs_;

  std::vector<std::vector<uint8_t>> ValidInputs_;
  std::vector<std::vector<uint8_t>> AcceptedInputs_;

  // Statistics
  FormatGeneratorStats Stats_;

  // Callbacks
  ProgressCallback ProgressCb_;
  InputCallback InputCb_;

  /// Process a single work item
  void processWorkItem(FormatWorkItem &Item);

  /// Explore a specific field
  std::vector<FormatWorkItem> exploreField(const StructuredInput &Input,
                                            const std::string &FieldName);

  /// Generate field mutations based on constraints
  std::vector<uint64_t> generateFieldValues(const FieldDef &Field);

  /// Handle DNS-specific name field
  std::vector<std::vector<uint8_t>> generateDNSNames();

  /// Encode a domain name in DNS format
  std::vector<uint8_t> encodeDNSName(const std::string &Name);

  /// Check if input satisfies format constraints
  bool checkFormatConstraints(const std::vector<uint8_t> &Input);

  /// Update computed fields (checksums, lengths)
  std::vector<uint8_t> updateComputedFields(std::vector<uint8_t> Input);

  void addValidInput(const std::vector<uint8_t> &Input);
  void addAcceptedInput(const std::vector<uint8_t> &Input);

  /// Check stopping condition
  bool shouldStop() const;
};

//===----------------------------------------------------------------------===//
// DNS-Specific Utilities
//===----------------------------------------------------------------------===//

/// DNS name encoder/decoder
class DNSNameCodec {
public:
  /// Encode a dotted domain name to DNS wire format
  /// Example: "example.com" -> "\x07example\x03com\x00"
  static std::vector<uint8_t> encode(const std::string &Name);

  /// Decode DNS wire format to dotted name
  static std::string decode(const std::vector<uint8_t> &Data, size_t Offset = 0);

  /// Check if a name uses compression (pointer)
  static bool hasCompression(const std::vector<uint8_t> &Data, size_t Offset);

  /// Get the wire length of an encoded name
  static size_t getEncodedLength(const std::vector<uint8_t> &Data, size_t Offset);

  /// Generate valid DNS label variations
  static std::vector<std::string> generateLabelVariants(const std::string &Label);

  /// Generate valid domain name variations
  static std::vector<std::string> generateNameVariants(const std::string &Name);
};

/// DNS packet builder helper
class DNSPacketBuilder {
public:
  DNSPacketBuilder();

  /// Set transaction ID
  DNSPacketBuilder &setID(uint16_t ID);

  /// Set flags
  DNSPacketBuilder &setFlags(uint16_t Flags);

  /// Set as query (QR=0)
  DNSPacketBuilder &asQuery();

  /// Set as response (QR=1)
  DNSPacketBuilder &asResponse();

  /// Set recursion desired
  DNSPacketBuilder &setRecursionDesired(bool RD = true);

  /// Set authoritative answer
  DNSPacketBuilder &setAuthoritative(bool AA = true);

  /// Set recursion available
  DNSPacketBuilder &setRecursionAvailable(bool RA = true);

  /// Set response code (RCODE)
  DNSPacketBuilder &setRCode(uint8_t RCode);

  /// Add a question
  DNSPacketBuilder &addQuestion(const std::string &Name, uint16_t Type = 1,
                                 uint16_t Class = 1);

  /// Add an answer (for responses)
  DNSPacketBuilder &addAnswer(const std::string &Name, uint16_t Type,
                               uint16_t Class, uint32_t TTL,
                               const std::vector<uint8_t> &RData);

  /// Add authority record
  DNSPacketBuilder &addAuthority(const std::string &Name, uint16_t Type,
                                  uint16_t Class, uint32_t TTL,
                                  const std::vector<uint8_t> &RData);

  /// Add additional record
  DNSPacketBuilder &addAdditional(const std::string &Name, uint16_t Type,
                                   uint16_t Class, uint32_t TTL,
                                   const std::vector<uint8_t> &RData);

  /// Build the packet
  std::vector<uint8_t> build() const;

  /// Build a minimal valid query for the given domain
  static std::vector<uint8_t> buildQuery(const std::string &Domain,
                                          uint16_t Type = 1);

  /// Build a minimal valid response
  static std::vector<uint8_t> buildResponse(const std::string &Domain,
                                             const std::vector<uint8_t> &Answer);

  /// Build response from query (copies TxID and Question)
  static std::vector<uint8_t> buildResponseFromQuery(
      const std::vector<uint8_t> &Query,
      const std::vector<uint8_t> &AnswerRData,
      uint16_t AnswerType = 1,
      uint32_t TTL = 300);

private:
  uint16_t ID_ = 0;
  uint16_t Flags_ = 0;

  struct Question {
    std::string Name;
    uint16_t Type;
    uint16_t Class;
  };
  std::vector<Question> Questions_;

  struct ResourceRecord {
    std::string Name;
    uint16_t Type;
    uint16_t Class;
    uint32_t TTL;
    std::vector<uint8_t> RData;
  };
  std::vector<ResourceRecord> Answers_;
  std::vector<ResourceRecord> Authority_;
  std::vector<ResourceRecord> Additional_;
};

/// Generator for paired Query-Response DNS packets
class DNSQueryResponseGenerator {
public:
  struct Config {
    size_t MaxIterations = 1000;
    size_t HeaderBytesToPreserve = 12;
    size_t QuestionBytesToPreserve = 8;
    bool ExploreAnswerSection = true;
    bool ExploreAuthoritySection = false;
    bool ExploreAdditionalSection = false;
    unsigned TimeoutSec = 10;
  };

  struct QueryResponsePair {
    std::vector<uint8_t> Query;
    std::vector<uint8_t> Response;
  };

  DNSQueryResponseGenerator();
  explicit DNSQueryResponseGenerator(Config Cfg);

  void setRunner(std::shared_ptr<SymCCRunner> Runner);

  void addQuerySeed(const std::vector<uint8_t> &Query);

  std::vector<QueryResponsePair> generate();

  using PairCallback = std::function<void(const QueryResponsePair &)>;
  void setPairCallback(PairCallback Cb) { PairCb_ = std::move(Cb); }

private:
  Config Config_;
  std::shared_ptr<SymCCRunner> Runner_;
  std::vector<std::vector<uint8_t>> QuerySeeds_;
  PairCallback PairCb_;

  std::vector<uint8_t> generateResponseForQuery(const std::vector<uint8_t> &Query);
  std::vector<std::vector<uint8_t>> exploreResponseVariants(
      const std::vector<uint8_t> &BaseResponse,
      size_t PreserveBytes);
};

/// Hybrid generator that preserves header bytes and explores payload with SymCC
class HybridDNSGenerator {
public:
  struct Config {
    size_t PreserveHeaderBytes = 20;
    size_t MaxPayloadLength = 512;
    size_t MaxIterations = 1000;
    unsigned TimeoutSec = 10;
    bool IsResponse = true;
  };

  HybridDNSGenerator();
  explicit HybridDNSGenerator(Config Cfg);

  void setRunner(std::shared_ptr<SymCCRunner> Runner);
  void setConfig(Config Cfg) { Config_ = Cfg; }

  void addSeed(const std::vector<uint8_t> &Seed);

  std::vector<std::vector<uint8_t>> generate();

  using InputCallback = std::function<void(const std::vector<uint8_t> &)>;
  void setInputCallback(InputCallback Cb) { InputCb_ = std::move(Cb); }

private:
  Config Config_;
  std::shared_ptr<SymCCRunner> Runner_;
  std::vector<std::vector<uint8_t>> Seeds_;
  InputCallback InputCb_;

  std::vector<uint8_t> createHeaderFromSeed(const std::vector<uint8_t> &Seed);
  std::vector<std::vector<uint8_t>> explorePayload(
      const std::vector<uint8_t> &Header);
};

} // namespace geninput

#endif // GENINPUT_FORMATAWAREGENERATOR_H
