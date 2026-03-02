#include "../include/SymCCRunner.h"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
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

  int Status = 0;
  bool TimedOut = false;
  if (Config_.TimeoutSec == 0) {
    waitpid(Pid, &Status, 0);
  } else {
    const auto Timeout =
        std::chrono::seconds(static_cast<int64_t>(Config_.TimeoutSec));
    const auto StartTime = std::chrono::steady_clock::now();

    while (true) {
      pid_t WaitResult = waitpid(Pid, &Status, WNOHANG);
      if (WaitResult == Pid) {
        break;
      }
      if (WaitResult < 0) {
        break;
      }

      const auto Elapsed = std::chrono::steady_clock::now() - StartTime;
      if (Elapsed >= Timeout) {
        kill(Pid, SIGKILL);
        waitpid(Pid, &Status, 0);
        TimedOut = true;
        Stats_.TimeoutRuns++;
        break;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }

  unlink(TmpInput);

  if (TimedOut) {
    Result.ExitCode = -1;
    Result.Accepted = false;
  } else if (WIFEXITED(Status)) {
    Result.ExitCode = WEXITSTATUS(Status);
    Result.Accepted = (Result.ExitCode == 0);
    if (Result.Accepted) {
      Stats_.AcceptedRuns++;
    }
  } else if (WIFSIGNALED(Status)) {
    Result.ExitCode = -1;
    Result.Accepted = false;
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
