#include "SymCCRunner.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <queue>
#include <set>
#include <string>

namespace {

struct Options {
  std::string ProgramPath;
  std::string OutputDir = "/tmp/geninput_output";
  std::string SeedInput;
  size_t MaxLength = 64;
  size_t MaxIterations = 1000;
  unsigned TimeoutSec = 10;
  bool Verbose = false;
  bool PrintableOnly = true;
};

void printUsage(const char *ProgName) {
  std::cerr
      << "Usage: " << ProgName << " [options] <program>\n"
      << "\nOptions:\n"
      << "  -o, --output <dir>    Output directory (default: "
         "/tmp/geninput_output)\n"
      << "  -s, --seed <string>   Initial seed input\n"
      << "  -l, --max-length <n>  Maximum input length (default: 64)\n"
      << "  -i, --max-iter <n>    Maximum iterations (default: 1000)\n"
      << "  -t, --timeout <s>     Execution timeout in seconds (default: 10)\n"
      << "  -a, --all-chars       Allow non-printable characters\n"
      << "  -v, --verbose         Verbose output\n"
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

    if (Arg == "-a" || Arg == "--all-chars") {
      Opts.PrintableOnly = false;
      continue;
    }

    if (Arg == "-v" || Arg == "--verbose") {
      Opts.Verbose = true;
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

}

int main(int Argc, char *Argv[]) {
  Options Opts;
  if (!parseArgs(Argc, Argv, Opts)) {
    return 1;
  }

  geninput::RunConfig RunCfg;
  RunCfg.ProgramPath = Opts.ProgramPath;
  RunCfg.OutputDir = Opts.OutputDir;
  RunCfg.TimeoutSec = Opts.TimeoutSec;
  RunCfg.UseStdin = true;

  std::filesystem::create_directories(Opts.OutputDir);

  geninput::SymCCRunner Runner(RunCfg);

  std::cerr << "Starting input generation for: " << Opts.ProgramPath << "\n";
  std::cerr << "Output directory: " << Opts.OutputDir << "\n";

  std::queue<std::vector<uint8_t>> Queue;
  std::set<std::vector<uint8_t>> Seen;
  std::vector<std::vector<uint8_t>> ValidInputs;

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
  std::cerr << "Generation complete:\n"
            << "  Total iterations: " << Iterations << "\n"
            << "  Total SymCC runs: " << Stats.TotalRuns << "\n"
            << "  Test cases generated: " << Stats.TotalTestCasesGenerated
            << "\n"
            << "  Valid inputs found: " << ValidInputs.size() << "\n";

  size_t Index = 0;
  for (const auto &Input : ValidInputs) {
    std::string Filename = Opts.OutputDir + "/valid_" + std::to_string(Index++);
    std::ofstream Ofs(Filename, std::ios::binary);
    Ofs.write(reinterpret_cast<const char *>(Input.data()),
              static_cast<std::streamsize>(Input.size()));
  }

  std::cout << "Generated " << ValidInputs.size() << " valid inputs to "
            << Opts.OutputDir << "\n";

  return 0;
}
