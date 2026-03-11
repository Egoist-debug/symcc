#include "../include/SymCCRunner.h"
#include "BinaryFormat.h"
#include "FormatAwareGenerator.h"
#include "ThreePhaseGenerator.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <queue>
#include <sstream>
#include <set>
#include <string>

namespace {

struct Options {
  std::string ProgramPath;
  std::string OutputDir = "/tmp/geninput_output";
  std::string SeedInput;
  std::string SeedFile;
  std::string Format;
  size_t MaxLength = 64;
  size_t MaxIterations = 1000;
  unsigned TimeoutSec = 10;
  size_t MaxByteDiff = 32;
  bool Verbose = false;
  bool PrintableOnly = true;
  size_t PreserveHeaderBytes = 20;
  bool HybridMode = false;
  bool ThreePhaseMode = false;
  bool FreezeDNSHeaderQuestion = false;
  size_t TailFocusLastBytes = 0;
  double TailFocusRatio = 0.0;
  std::vector<std::string> TailStrategies;
};

std::vector<std::string> splitCommaList(const std::string &Input) {
  std::vector<std::string> Result;
  std::stringstream Stream(Input);
  std::string Item;
  auto trim = [](std::string &Value) {
    const auto First = Value.find_first_not_of(" \t\n\r");
    if (First == std::string::npos) {
      Value.clear();
      return;
    }
    const auto Last = Value.find_last_not_of(" \t\n\r");
    Value = Value.substr(First, Last - First + 1);
  };
  while (std::getline(Stream, Item, ',')) {
    trim(Item);
    if (!Item.empty()) {
      Result.push_back(Item);
    }
  }
  return Result;
}

bool isSupportedTailStrategy(const std::string &Strategy) {
  static const std::set<std::string> Supported = {
      "truncate", "append", "bitflip", "rdlength-mismatch", "count-mismatch"};
  return Supported.count(Strategy) > 0;
}

bool looksLikeDnsPacket(const std::vector<uint8_t> &Input) {
  return Input.size() >= 12;
}

bool isDnsResponsePacket(const std::vector<uint8_t> &Input) {
  return looksLikeDnsPacket(Input) && (Input[2] & 0x80) != 0;
}

void printUsage(const char *ProgName) {
  std::cerr
      << "Usage: " << ProgName << " [options] <program>\n"
      << "\nOptions:\n"
      << "  -o, --output <dir>    Output directory (default: "
         "/tmp/geninput_output)\n"
      << "  -s, --seed <string>   Initial seed input\n"
      << "  --seed-file <path>    Initial seed input file (binary)\n"
      << "  -f, --format <name>   Binary format (dns, dns-response, dns-poison-response, dns-stateful-transcript, dns-header-question, tlv)\n"
      << "  --mode <name>         Generation mode (dns-header-question)\n"
      << "  -l, --max-length <n>  Maximum input length (default: 64)\n"
      << "  -i, --max-iter <n>    Maximum iterations (default: 1000)\n"
      << "  -t, --timeout <s>     SymCC execution timeout per run in seconds (default: 10)\n"
      << "  --max-byte-diff <n>   Maximum byte difference from parent testcase in format-aware mode (default: 32)\n"
      << "  --three-phase         Use three-phase algorithm (init → expand → complete)\n"
      << "  -a, --all-chars       Allow non-printable characters\n"
      << "  -v, --verbose         Verbose output\n"
      << "  --hybrid              Hybrid mode: preserve header, explore payload\n"
      << "  --preserve <n>        Bytes to preserve in hybrid mode (default: 20)\n"
      << "  --tail-focus-last <n> Tail-focused mutation window size in bytes\n"
      << "  --tail-focus-ratio <x> Tail-focused mutation ratio in [0.0,1.0]\n"
      << "  --tail-strategies <csv> Tail strategies (truncate,append,bitflip,rdlength-mismatch,count-mismatch)\n"
      << "  -h, --help            Show this help\n";
}

bool parseArgs(int Argc, char *Argv[], Options &Opts) {
  for (int I = 1; I < Argc; ++I) {
    std::string Arg = Argv[I];

    if (Arg == "-h" || Arg == "--help") {
      printUsage(Argv[0]);
      return false;
    }

    if (Arg == "-o" || Arg == "--output") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.OutputDir = Argv[I];
      continue;
    }

    if (Arg == "-s" || Arg == "--seed") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.SeedInput = Argv[I];
      continue;
    }

    if (Arg == "--seed-file") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.SeedFile = Argv[I];
      continue;
    }

    if (Arg == "-f" || Arg == "--format") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.Format = Argv[I];
      continue;
    }

    if (Arg == "--mode") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      const std::string Mode = Argv[I];
      if (Mode == "dns-header-question") {
        Opts.FreezeDNSHeaderQuestion = true;
        if (Opts.Format.empty()) {
          Opts.Format = "dns-response";
        }
      } else {
        std::cerr << "Error: Unknown mode '" << Mode << "'\n";
        return false;
      }
      continue;
    }

    if (Arg == "-l" || Arg == "--max-length") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.MaxLength = std::stoul(Argv[I]);
      continue;
    }

    if (Arg == "-i" || Arg == "--max-iter") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.MaxIterations = std::stoul(Argv[I]);
      continue;
    }

    if (Arg == "-t" || Arg == "--timeout") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.TimeoutSec = std::stoul(Argv[I]);
      continue;
    }

    if (Arg == "--max-byte-diff") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.MaxByteDiff = std::stoul(Argv[I]);
      continue;
    }

    if (Arg == "-a" || Arg == "--all-chars") {
      Opts.PrintableOnly = false;
      continue;
    }

    if (Arg == "-v" || Arg == "--verbose") {
      Opts.Verbose = true;
      continue;
    }

    if (Arg == "--hybrid") {
      Opts.HybridMode = true;
      continue;
    }

    if (Arg == "--three-phase") {
      Opts.ThreePhaseMode = true;
      continue;
    }

    if (Arg == "--preserve") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.PreserveHeaderBytes = std::stoul(Argv[I]);
      continue;
    }

    if (Arg == "--tail-focus-last") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.TailFocusLastBytes = std::stoul(Argv[I]);
      continue;
    }

    if (Arg == "--tail-focus-ratio") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.TailFocusRatio = std::stod(Argv[I]);
      if (Opts.TailFocusRatio < 0.0 || Opts.TailFocusRatio > 1.0) {
        std::cerr << "Error: --tail-focus-ratio must be in [0.0, 1.0]\n";
        return false;
      }
      continue;
    }

    if (Arg == "--tail-strategies") {
      if (++I >= Argc) {
        std::cerr << "Error: " << Arg << " requires an argument\n";
        return false;
      }
      Opts.TailStrategies = splitCommaList(Argv[I]);
      for (const auto &Strategy : Opts.TailStrategies) {
        if (!isSupportedTailStrategy(Strategy)) {
          std::cerr << "Error: Unsupported tail strategy '" << Strategy << "'\n";
          return false;
        }
      }
      continue;
    }

    if (Arg[0] == '-') {
      std::cerr << "Error: Unknown option " << Arg << "\n";
      return false;
    }

    if (Opts.ProgramPath.empty()) {
      Opts.ProgramPath = Arg;
    } else {
      std::cerr << "Error: Multiple programs specified\n";
      return false;
    }
  }

  if (Opts.ProgramPath.empty()) {
    std::cerr << "Error: No program specified\n";
    printUsage(Argv[0]);
    return false;
  }

  return true;
}

std::set<uint8_t> filterPrintable(const std::set<uint8_t> &Chars) {
  std::set<uint8_t> Result;
  for (uint8_t Ch : Chars) {
    if (Ch >= 0x20 && Ch <= 0x7E) {
      Result.insert(Ch);
    }
  }
  return Result;
}

std::vector<uint8_t> ensureResponseSeed(const std::vector<uint8_t> &Seed) {
  if (Seed.size() < 12) {
    return Seed;
  }

  bool IsResponse = (Seed[2] & 0x80) != 0;
  if (IsResponse) {
    return Seed;
  }

  std::vector<uint8_t> DefaultAnswer = {127, 0, 0, 1};
  auto Response = geninput::DNSPacketBuilder::buildResponseFromQuery(
      Seed, DefaultAnswer, 1, 300);
  if (!Response.empty()) {
    return Response;
  }

  return Seed;
}

}

int main(int Argc, char *Argv[]) {
  Options Opts;
  if (!parseArgs(Argc, Argv, Opts)) {
    return 1;
  }

  if (!Opts.SeedInput.empty() && !Opts.SeedFile.empty()) {
    std::cerr << "Error: --seed and --seed-file are mutually exclusive\n";
    return 1;
  }

  if (!Opts.SeedFile.empty()) {
    std::ifstream SeedStream(Opts.SeedFile, std::ios::binary);
    if (!SeedStream) {
      std::cerr << "Error: failed to open seed file '" << Opts.SeedFile
                << "'\n";
      return 1;
    }
    Opts.SeedInput.assign(std::istreambuf_iterator<char>(SeedStream),
                          std::istreambuf_iterator<char>());
    if (Opts.SeedInput.empty()) {
      std::cerr << "Error: seed file '" << Opts.SeedFile << "' is empty\n";
      return 1;
    }
  }

  geninput::RunConfig RunCfg;
  RunCfg.ProgramPath = Opts.ProgramPath;
  RunCfg.OutputDir = Opts.OutputDir;
  RunCfg.TimeoutSec = Opts.TimeoutSec;
  RunCfg.UseStdin = true;

  std::filesystem::create_directories(Opts.OutputDir);

  std::cerr << "Starting input generation for: " << Opts.ProgramPath << "\n";
  std::cerr << "Output directory: " << Opts.OutputDir << "\n";

  std::vector<std::vector<uint8_t>> ValidInputs;
  std::vector<std::vector<uint8_t>> AcceptedInputs;
  std::vector<std::vector<uint8_t>> GeneratedOnlyInputs;

  if (!Opts.Format.empty()) {
    auto Runner = std::make_shared<geninput::SymCCRunner>(RunCfg);

    if (Opts.Format == "dns-poison-response" ||
        Opts.Format == "dns-stateful-transcript") {
      geninput::StatefulDNSGenerator::Config StatefulCfg;
      size_t GeneratedCount = 0;
      StatefulCfg.MaxVariantsPerQuery =
          std::max<size_t>(4, std::min<size_t>(Opts.MaxIterations, 16));
      StatefulCfg.MaxTranscripts = std::max<size_t>(1, Opts.MaxIterations);
      StatefulCfg.MaxResponsesPerTranscript =
          std::min<size_t>(3, std::max<size_t>(2, Opts.MaxIterations));
      StatefulCfg.MaxRacePermutations =
          std::max<size_t>(4, std::min<size_t>(Opts.MaxIterations, 12));
      StatefulCfg.IncludePostCheck = true;
      StatefulCfg.GenerateResponseRaces = true;
      StatefulCfg.GenerateExtendedPoisonTemplates = true;

      geninput::StatefulDNSGenerator Generator(StatefulCfg);
      if (!Opts.SeedInput.empty()) {
        std::vector<uint8_t> Seed(Opts.SeedInput.begin(), Opts.SeedInput.end());
        if (isDnsResponsePacket(Seed)) {
          Generator.addResponseSeed(Seed);
        } else if (looksLikeDnsPacket(Seed)) {
          Generator.addQuerySeed(Seed);
        }
      }

      if (Opts.Verbose) {
        Generator.setInputCallback([&GeneratedCount](const std::vector<uint8_t> &) {
          std::cerr << "\rGenerated: " << ++GeneratedCount << std::flush;
        });
      }

      if (Opts.Format == "dns-poison-response") {
        std::cerr << "Using DNS poison response format\n";
        if (Opts.HybridMode) {
          geninput::HybridDNSGenerator::Config HybridCfg;
          HybridCfg.PreserveHeaderBytes = Opts.PreserveHeaderBytes;
          HybridCfg.MaxPayloadLength = Opts.MaxLength;
          HybridCfg.MaxIterations = Opts.MaxIterations;
          HybridCfg.TimeoutSec = Opts.TimeoutSec;
          HybridCfg.IsResponse = true;

          geninput::HybridDNSGenerator HybridGen(HybridCfg);
          HybridGen.setRunner(Runner);
          for (const auto &Seed : Generator.generatePoisonResponses()) {
            HybridGen.addSeed(ensureResponseSeed(Seed));
          }
          if (Opts.Verbose) {
            HybridGen.setInputCallback([&](const std::vector<uint8_t> &) {});
          }
          ValidInputs = HybridGen.generate();
        } else {
          ValidInputs = Generator.generatePoisonResponses();
        }
      } else {
        if (Opts.HybridMode) {
          std::cerr << "Error: dns-stateful-transcript does not support --hybrid\n";
          return 1;
        }
        std::cerr << "Using DNS stateful transcript format\n";
        ValidInputs = Generator.generateStatefulTranscripts();
      }

      for (const auto &Input : ValidInputs) {
        if (Runner->isAccepted(Input)) {
          AcceptedInputs.push_back(Input);
        } else {
          GeneratedOnlyInputs.push_back(Input);
        }
      }

      if (Opts.Verbose) {
        std::cerr << "\n";
      }

      const auto &RunStats = Runner->getStats();
      const double AcceptanceRate =
          RunStats.TotalRuns > 0
              ? (100.0 * static_cast<double>(RunStats.AcceptedRuns) /
                 static_cast<double>(RunStats.TotalRuns))
              : 0.0;
      std::cerr << "Generation complete:\n"
                << "  Total generated: " << ValidInputs.size() << "\n"
                << "  Accepted inputs: " << AcceptedInputs.size() << "\n"
                << "  Generated-only inputs: " << GeneratedOnlyInputs.size() << "\n"
                << "  SymCC runs: " << RunStats.TotalRuns << "\n"
                << "  Timeout runs: " << RunStats.TimeoutRuns << "\n"
                << "  SymCC acceptance rate: " << AcceptanceRate << "%\n";

      size_t AcceptedIndex = 0;
      for (const auto &Input : AcceptedInputs) {
        std::string Filename =
            Opts.OutputDir + "/accepted_" + std::to_string(AcceptedIndex++);
        std::ofstream Ofs(Filename, std::ios::binary);
        Ofs.write(reinterpret_cast<const char *>(Input.data()),
                  static_cast<std::streamsize>(Input.size()));
      }

      size_t GeneratedIndex = 0;
      for (const auto &Input : GeneratedOnlyInputs) {
        std::string Filename =
            Opts.OutputDir + "/generated_" + std::to_string(GeneratedIndex++);
        std::ofstream Ofs(Filename, std::ios::binary);
        Ofs.write(reinterpret_cast<const char *>(Input.data()),
                  static_cast<std::streamsize>(Input.size()));
      }

      std::cout << "Generated " << ValidInputs.size() << " inputs ("
                << AcceptedInputs.size() << " accepted, "
                << GeneratedOnlyInputs.size() << " generated-only) to "
                << Opts.OutputDir << "\n";
      return 0;
    }

    std::unique_ptr<geninput::BinaryFormat> Format;
    bool IsResponse = false;

    if (Opts.Format == "dns") {
      Format = std::make_unique<geninput::BinaryFormat>(
          geninput::BinaryFormatFactory::createDNS());
      std::cerr << "Using DNS query format\n";
    } else if (Opts.Format == "dns-header-question") {
      Format = std::make_unique<geninput::BinaryFormat>(
          geninput::BinaryFormatFactory::createDNSResponse());
      IsResponse = true;
      Opts.FreezeDNSHeaderQuestion = true;
      std::cerr << "Using DNS header-question semantic freeze mode\n";
    } else if (Opts.Format == "dns-response") {
      Format = std::make_unique<geninput::BinaryFormat>(
          geninput::BinaryFormatFactory::createDNSResponse());
      IsResponse = true;
      std::cerr << "Using DNS response format\n";
    } else if (Opts.Format == "tlv") {
      Format = std::make_unique<geninput::BinaryFormat>(
          geninput::BinaryFormatFactory::createTLV());
      std::cerr << "Using TLV format\n";
    } else {
      std::cerr << "Error: Unknown format '" << Opts.Format << "'\n";
      std::cerr << "Available formats: dns, dns-response, dns-poison-response, dns-stateful-transcript, dns-header-question, tlv\n";
      return 1;
    }

    if (Opts.HybridMode) {
      std::cerr << "Using hybrid mode (preserve " << Opts.PreserveHeaderBytes
                << " header bytes)\n";

      geninput::HybridDNSGenerator::Config HybridCfg;
      HybridCfg.PreserveHeaderBytes = Opts.PreserveHeaderBytes;
      HybridCfg.MaxPayloadLength = Opts.MaxLength;
      HybridCfg.MaxIterations = Opts.MaxIterations;
      HybridCfg.TimeoutSec = Opts.TimeoutSec;
      HybridCfg.IsResponse = IsResponse;

      geninput::HybridDNSGenerator HybridGen(HybridCfg);
      HybridGen.setRunner(Runner);

      if (!Opts.SeedInput.empty()) {
        std::vector<uint8_t> Seed(Opts.SeedInput.begin(), Opts.SeedInput.end());
        if (IsResponse) {
          Seed = ensureResponseSeed(Seed);
          if (Seed.size() < Opts.PreserveHeaderBytes) {
            std::cerr << "Error: response seed must be at least "
                      << Opts.PreserveHeaderBytes << " bytes\n";
            return 1;
          }
        }
        HybridGen.addSeed(Seed);
      }

      if (Opts.Verbose) {
        size_t Count = 0;
        HybridGen.setInputCallback([&Count](const std::vector<uint8_t> &) {
          std::cerr << "\rGenerated: " << ++Count << std::flush;
        });
      }

      ValidInputs = HybridGen.generate();
      for (const auto &Input : ValidInputs) {
        if (Runner->isAccepted(Input)) {
          AcceptedInputs.push_back(Input);
        } else {
          GeneratedOnlyInputs.push_back(Input);
        }
      }

      if (Opts.Verbose) {
        std::cerr << "\n";
      }

      std::cerr << "Hybrid generation complete:\n"
                << "  Total generated: " << ValidInputs.size() << "\n"
                << "  Accepted inputs: " << AcceptedInputs.size() << "\n"
                << "  Generated-only inputs: " << GeneratedOnlyInputs.size() << "\n";

      const auto &RunStats = Runner->getStats();
      const double AcceptanceRate =
          RunStats.TotalRuns > 0
              ? (100.0 * static_cast<double>(RunStats.AcceptedRuns) /
                 static_cast<double>(RunStats.TotalRuns))
              : 0.0;
      std::cerr << "  SymCC runs: " << RunStats.TotalRuns << "\n"
                << "  Timeout runs: " << RunStats.TimeoutRuns << "\n"
                << "  SymCC acceptance rate: " << AcceptanceRate << "%\n";
    } else if (Opts.ThreePhaseMode) {
      std::cerr << "Using three-phase algorithm (init -> expand -> complete)\n";

      geninput::GeneratorConfig GenCfg;
      GenCfg.MaxIterations = Opts.MaxIterations;
      // Phase budget: 10% init, 40% expand, 50% complete (prevents Phase 3 starvation)
      GenCfg.Phase1MaxIterations = std::max<size_t>(1, Opts.MaxIterations / 10);
      GenCfg.Phase2MaxIterations = std::max<size_t>(1, Opts.MaxIterations * 4 / 10);
      GenCfg.MaxInputLength = Opts.MaxLength;
      GenCfg.OnlyPrintable = Opts.PrintableOnly;

      geninput::ThreePhaseGenerator Generator(GenCfg);
      Generator.setRunner(Runner);

      if (!Opts.SeedInput.empty()) {
        std::vector<uint8_t> Seed(Opts.SeedInput.begin(), Opts.SeedInput.end());
        Generator.addSeed(Seed);
      } else {
        Generator.addSeed(Format->createSeed());
      }

      if (Opts.Verbose) {
        Generator.setProgressCallback(
            [](size_t Iter, size_t QueueSize, size_t ValidCount) {
              std::cerr << "\rIteration: " << Iter << ", Queue: " << QueueSize
                        << ", Valid: " << ValidCount << std::flush;
            });
      }

      ValidInputs = Generator.run();
      AcceptedInputs = ValidInputs;

      if (Opts.Verbose) {
        std::cerr << "\n";
      }

      const auto &Stats = Generator.getStats();
      std::cerr << "Three-phase generation complete:\n"
                << "  Phase 1 iterations: " << Stats.Phase1Iterations << "\n"
                << "  Phase 2 iterations: " << Stats.Phase2Iterations << "\n"
                << "  Phase 3 iterations: " << Stats.Phase3Iterations << "\n"
                << "  Stems collected: " << Stats.TotalStemsCollected << "\n"
                << "  Stem injections: " << Stats.StemInjections << "\n"
                << "  Valid inputs found: " << ValidInputs.size() << "\n";

      const auto &RunStats = Runner->getStats();
      const double AcceptanceRate =
          RunStats.TotalRuns > 0
              ? (100.0 * static_cast<double>(RunStats.AcceptedRuns) /
                 static_cast<double>(RunStats.TotalRuns))
              : 0.0;
      std::cerr << "  SymCC runs: " << RunStats.TotalRuns << "\n"
                << "  Timeout runs: " << RunStats.TimeoutRuns << "\n"
                << "  SymCC acceptance rate: " << AcceptanceRate << "%\n";
    } else {
      geninput::FormatGeneratorConfig GenCfg;
      GenCfg.MaxIterations = Opts.MaxIterations;
      GenCfg.MaxInputLength = Opts.MaxLength;
      GenCfg.TimeoutSec = Opts.TimeoutSec;
      GenCfg.MaxByteDiff = Opts.MaxByteDiff;
      GenCfg.FreezeDNSHeaderQuestion = Opts.FreezeDNSHeaderQuestion;
      GenCfg.TailFocusLastBytes = Opts.TailFocusLastBytes;
      GenCfg.TailFocusRatio = Opts.TailFocusRatio;
      GenCfg.TailStrategies = Opts.TailStrategies;
      if (GenCfg.TailFocusLastBytes > 0 && GenCfg.TailStrategies.empty()) {
        GenCfg.TailStrategies = {
            "truncate", "append", "bitflip", "rdlength-mismatch", "count-mismatch"};
      }
      if (GenCfg.TailFocusLastBytes > 0 && GenCfg.ControlledMalformationBudget == 0) {
        GenCfg.ControlledMalformationBudget =
            std::max<size_t>(1, static_cast<size_t>(
                                   static_cast<double>(Opts.MaxIterations) *
                                   std::min(GenCfg.TailFocusRatio, 1.0) * 0.5));
      }

      geninput::FormatAwareGenerator Generator(*Format, GenCfg);
      Generator.setRunner(Runner);

      if (!Opts.SeedInput.empty()) {
        std::vector<uint8_t> Seed(Opts.SeedInput.begin(), Opts.SeedInput.end());
        Generator.addSeed(Seed);
      }

      if (Opts.Verbose) {
        Generator.setProgressCallback(
            [](size_t Iter, size_t QueueSize, size_t ValidCount) {
              std::cerr << "\rIteration: " << Iter << ", Queue: " << QueueSize
                        << ", Valid: " << ValidCount << std::flush;
            });
      }

      auto Result = Generator.run();
      ValidInputs = std::move(Result.ValidInputs);
      AcceptedInputs = std::move(Result.AcceptedInputs);

      if (Opts.Verbose) {
        std::cerr << "\n";
      }

      const auto &Stats = Generator.getStats();
      const auto &RunStats = Runner->getStats();
      const double AcceptanceRate =
          Stats.TotalSymCCRuns > 0
              ? (100.0 * static_cast<double>(AcceptedInputs.size()) /
                 static_cast<double>(Stats.TotalSymCCRuns))
              : 0.0;
      const double SymCCPerAccepted =
          AcceptedInputs.empty()
              ? static_cast<double>(Stats.TotalSymCCRuns)
              : (static_cast<double>(Stats.TotalSymCCRuns) /
                 static_cast<double>(AcceptedInputs.size()));

      std::cerr << "Generation complete:\n"
                << "  Total iterations: " << Stats.TotalIterations << "\n"
                << "  Total SymCC runs: " << Stats.TotalSymCCRuns << "\n"
                << "  Timeout runs: " << RunStats.TimeoutRuns << "\n"
                << "  Field mutations: " << Stats.FieldMutations << "\n"
                << "  Format violations: " << Stats.FormatViolations << "\n"
                << "  Accepted inputs found: " << AcceptedInputs.size() << "\n"
                << "  Acceptance rate: " << AcceptanceRate << "%\n"
                << "  SymCC runs per accepted input: " << SymCCPerAccepted
                << "\n"
                << "  Valid inputs found: " << ValidInputs.size() << "\n";
    }
  } else {
    geninput::SymCCRunner Runner(RunCfg);

    std::queue<std::vector<uint8_t>> Queue;
    std::set<std::vector<uint8_t>> Seen;

    std::vector<uint8_t> Seed;
    if (!Opts.SeedInput.empty()) {
      Seed.assign(Opts.SeedInput.begin(), Opts.SeedInput.end());
    }
    Queue.push(Seed);
    Seen.insert(Seed);

    size_t Iterations = 0;
    const uint8_t Placeholder = '~';

    while (!Queue.empty() && Iterations < Opts.MaxIterations) {
      auto Current = Queue.front();
      Queue.pop();
      Iterations++;

      if (Opts.Verbose) {
        std::cerr << "\rIteration: " << Iterations << ", Queue: " << Queue.size()
                  << ", Valid: " << ValidInputs.size() << std::flush;
      }

      if (Current.size() >= Opts.MaxLength) {
        continue;
      }

      if (Runner.isAccepted(Current) && !Current.empty()) {
        if (Seen.find(Current) == Seen.end() ||
            std::find(ValidInputs.begin(), ValidInputs.end(), Current) ==
                ValidInputs.end()) {
          ValidInputs.push_back(Current);
          if (Opts.Verbose) {
            std::cerr << "\nFound valid input: "
                      << std::string(Current.begin(), Current.end()) << "\n";
          }
        }
      }

      auto Extensions = Runner.findValidExtensions(Current, Placeholder);

      if (Opts.PrintableOnly) {
        Extensions = filterPrintable(Extensions);
      }

      for (uint8_t Byte : Extensions) {
        std::vector<uint8_t> NewInput = Current;
        NewInput.push_back(Byte);

        if (Seen.find(NewInput) == Seen.end()) {
          Seen.insert(NewInput);
          Queue.push(NewInput);
        }
      }
    }

    if (Opts.Verbose) {
      std::cerr << "\n";
    }

    const auto &Stats = Runner.getStats();
    AcceptedInputs = ValidInputs;
    const double AcceptanceRate =
        Stats.TotalRuns > 0
            ? (100.0 * static_cast<double>(Stats.AcceptedRuns) /
               static_cast<double>(Stats.TotalRuns))
            : 0.0;
    const double SymCCPerAccepted =
        AcceptedInputs.empty()
            ? static_cast<double>(Stats.TotalRuns)
            : (static_cast<double>(Stats.TotalRuns) /
               static_cast<double>(AcceptedInputs.size()));
    std::cerr << "Generation complete:\n"
              << "  Total iterations: " << Iterations << "\n"
              << "  Total SymCC runs: " << Stats.TotalRuns << "\n"
              << "  Timeout runs: " << Stats.TimeoutRuns << "\n"
              << "  SymCC acceptance rate: " << AcceptanceRate << "%\n"
              << "  SymCC runs per accepted input: " << SymCCPerAccepted
              << "\n"
              << "  Test cases generated: " << Stats.TotalTestCasesGenerated
              << "\n"
              << "  Valid inputs found: " << ValidInputs.size() << "\n";
  }

  if (Opts.HybridMode && !Opts.Format.empty()) {
    size_t AcceptedIndex = 0;
    for (const auto &Input : AcceptedInputs) {
      std::string Filename =
          Opts.OutputDir + "/accepted_" + std::to_string(AcceptedIndex++);
      std::ofstream Ofs(Filename, std::ios::binary);
      Ofs.write(reinterpret_cast<const char *>(Input.data()),
                static_cast<std::streamsize>(Input.size()));
    }

    size_t GeneratedIndex = 0;
    for (const auto &Input : GeneratedOnlyInputs) {
      std::string Filename =
          Opts.OutputDir + "/generated_" + std::to_string(GeneratedIndex++);
      std::ofstream Ofs(Filename, std::ios::binary);
      Ofs.write(reinterpret_cast<const char *>(Input.data()),
                static_cast<std::streamsize>(Input.size()));
    }

    std::cout << "Generated " << ValidInputs.size() << " hybrid inputs ("
              << AcceptedInputs.size() << " accepted, "
              << GeneratedOnlyInputs.size() << " generated-only) to "
              << Opts.OutputDir << "\n";
  } else {
    size_t Index = 0;
    for (const auto &Input : ValidInputs) {
      std::string Filename = Opts.OutputDir + "/valid_" + std::to_string(Index++);
      std::ofstream Ofs(Filename, std::ios::binary);
      Ofs.write(reinterpret_cast<const char *>(Input.data()),
                static_cast<std::streamsize>(Input.size()));
    }

    std::cout << "Generated " << ValidInputs.size() << " valid inputs to "
              << Opts.OutputDir << "\n";
  }

  return 0;
}
