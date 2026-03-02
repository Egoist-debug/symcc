#ifndef GENINPUT_SYMCCRUNNER_H
#define GENINPUT_SYMCCRUNNER_H

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace geninput {

struct RunConfig {
  std::string ProgramPath;
  std::string OutputDir;
  unsigned TimeoutSec = 30;
  bool UseStdin = true;
};

struct RunResult {
  bool Accepted = false;
  int ExitCode = -1;
  std::vector<std::vector<uint8_t>> GeneratedTestCases;
};

class SymCCRunner {
public:
  explicit SymCCRunner(RunConfig Config);

  RunResult run(const std::vector<uint8_t> &Input);

  std::set<uint8_t> findValidExtensions(const std::vector<uint8_t> &Prefix,
                                         uint8_t Placeholder);

  bool isAccepted(const std::vector<uint8_t> &Input);

  struct Stats {
    size_t TotalRuns = 0;
    size_t AcceptedRuns = 0;
    size_t TimeoutRuns = 0;
    size_t TotalTestCasesGenerated = 0;
  };

  const Stats &getStats() const { return Stats_; }

private:
  RunConfig Config_;
  Stats Stats_;
  size_t RunCounter_ = 0;

  std::string prepareOutputDir();
  std::vector<std::vector<uint8_t>> collectTestCases(const std::string &Dir);
  void cleanupOutputDir(const std::string &Dir);
};

}

#endif
