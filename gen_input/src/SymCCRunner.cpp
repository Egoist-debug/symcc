#include "SymCCRunner.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace geninput {

SymCCRunner::SymCCRunner(RunConfig Config) : Config_(std::move(Config)) {}

std::string SymCCRunner::prepareOutputDir() {
  std::string Dir = Config_.OutputDir + "/run_" + std::to_string(RunCounter_++);
  mkdir(Dir.c_str(), 0755);
  return Dir;
}

std::vector<std::vector<uint8_t>>
SymCCRunner::collectTestCases(const std::string &Dir) {
  std::vector<std::vector<uint8_t>> Results;

  DIR *DirPtr = opendir(Dir.c_str());
  if (!DirPtr)
    return Results;

  struct dirent *Entry;
  while ((Entry = readdir(DirPtr)) != nullptr) {
    if (Entry->d_name[0] == '.')
      continue;

    std::string Path = Dir + "/" + Entry->d_name;
    std::ifstream File(Path, std::ios::binary);
    if (!File)
      continue;

    std::vector<uint8_t> Data((std::istreambuf_iterator<char>(File)),
                               std::istreambuf_iterator<char>());
    if (!Data.empty()) {
      Results.push_back(std::move(Data));
    }
  }

  closedir(DirPtr);
  return Results;
}

void SymCCRunner::cleanupOutputDir(const std::string &Dir) {
  DIR *DirPtr = opendir(Dir.c_str());
  if (!DirPtr)
    return;

  struct dirent *Entry;
  while ((Entry = readdir(DirPtr)) != nullptr) {
    if (Entry->d_name[0] == '.')
      continue;
    std::string Path = Dir + "/" + Entry->d_name;
    unlink(Path.c_str());
  }

  closedir(DirPtr);
  rmdir(Dir.c_str());
}

RunResult SymCCRunner::run(const std::vector<uint8_t> &Input) {
  RunResult Result;
  Stats_.TotalRuns++;

  std::string OutputDir = prepareOutputDir();

  char TmpInput[] = "/tmp/symcc_input_XXXXXX";
  int InputFd = mkstemp(TmpInput);
  if (InputFd < 0) {
    return Result;
  }

  ssize_t Written = write(InputFd, Input.data(), Input.size());
  close(InputFd);
  if (Written != static_cast<ssize_t>(Input.size())) {
    unlink(TmpInput);
    return Result;
  }

  pid_t Pid = fork();
  if (Pid < 0) {
    unlink(TmpInput);
    return Result;
  }

  if (Pid == 0) {
    setenv("SYMCC_OUTPUT_DIR", OutputDir.c_str(), 1);

    int NullFd = open("/dev/null", O_WRONLY);
    if (NullFd >= 0) {
      dup2(NullFd, STDOUT_FILENO);
      dup2(NullFd, STDERR_FILENO);
      close(NullFd);
    }

    if (Config_.UseStdin) {
      int InFd = open(TmpInput, O_RDONLY);
      if (InFd >= 0) {
        dup2(InFd, STDIN_FILENO);
        close(InFd);
      }
    } else {
      setenv("SYMCC_INPUT_FILE", TmpInput, 1);
    }

    execl(Config_.ProgramPath.c_str(), Config_.ProgramPath.c_str(), nullptr);
    _exit(127);
  }

  int Status;
  waitpid(Pid, &Status, 0);

  unlink(TmpInput);

  if (WIFEXITED(Status)) {
    Result.ExitCode = WEXITSTATUS(Status);
    Result.Accepted = (Result.ExitCode == 0);
    if (Result.Accepted) {
      Stats_.AcceptedRuns++;
    }
  }

  Result.GeneratedTestCases = collectTestCases(OutputDir);
  Stats_.TotalTestCasesGenerated += Result.GeneratedTestCases.size();

  cleanupOutputDir(OutputDir);

  return Result;
}

std::set<uint8_t>
SymCCRunner::findValidExtensions(const std::vector<uint8_t> &Prefix,
                                  uint8_t Placeholder) {
  std::set<uint8_t> ValidBytes;

  std::vector<uint8_t> TestInput = Prefix;
  TestInput.push_back(Placeholder);

  auto Result = run(TestInput);

  size_t Pos = Prefix.size();
  for (const auto &TestCase : Result.GeneratedTestCases) {
    if (TestCase.size() > Pos) {
      uint8_t Byte = TestCase[Pos];
      if (Byte != Placeholder) {
        ValidBytes.insert(Byte);
      }
    }
  }

  return ValidBytes;
}

bool SymCCRunner::isAccepted(const std::vector<uint8_t> &Input) {
  auto Result = run(Input);
  return Result.Accepted;
}

}
