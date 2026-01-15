// SPDX-License-Identifier: GPL-3.0-or-later

#include "SymCCIntegration.h"
#include "InputPrefix.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace geninput {

namespace {

ConstraintCallback g_ConstraintCb;
FunctionCallCallback g_FunctionCallCb;
FunctionReturnCallback g_FunctionReturnCb;
z3::context *g_Context = nullptr;

}

SymCCIntegration::SymCCIntegration() = default;

SymCCIntegration::SymCCIntegration(SymCCConfig Config)
    : Config_(std::move(Config)) {}

SymCCIntegration::~SymCCIntegration() {
  if (Initialized_) {
    cleanup();
  }
}

ExecutionResult SymCCIntegration::execute(const std::vector<uint8_t> &Input) {
  auto Start = std::chrono::high_resolution_clock::now();
  Stats_.TotalExecutions++;

  std::string InputPath;
  if (!prepareInput(Input, InputPath)) {
    Stats_.FailedExecutions++;
    return ExecutionResult::Failure("Failed to prepare input");
  }

  std::array<int, 2> StdoutPipe{};
  std::array<int, 2> StderrPipe{};

  if (Config_.CaptureStdout && pipe(StdoutPipe.data()) != 0) {
    Stats_.FailedExecutions++;
    return ExecutionResult::Failure("Failed to create stdout pipe");
  }

  if (Config_.CaptureStderr && pipe(StderrPipe.data()) != 0) {
    if (Config_.CaptureStdout) {
      close(StdoutPipe[0]);
      close(StdoutPipe[1]);
    }
    Stats_.FailedExecutions++;
    return ExecutionResult::Failure("Failed to create stderr pipe");
  }

  pid_t Pid = fork();

  if (Pid < 0) {
    Stats_.FailedExecutions++;
    return ExecutionResult::Failure("Fork failed");
  }

  if (Pid == 0) {
    if (Config_.CaptureStdout) {
      close(StdoutPipe[0]);
      dup2(StdoutPipe[1], STDOUT_FILENO);
      close(StdoutPipe[1]);
    }

    if (Config_.CaptureStderr) {
      close(StderrPipe[0]);
      dup2(StderrPipe[1], STDERR_FILENO);
      close(StderrPipe[1]);
    }

    if (!Config_.OutputDir.empty()) {
      setenv("SYMCC_OUTPUT_DIR", Config_.OutputDir.c_str(), 1);
    }

    if (!Config_.UseStdin && !InputPath.empty()) {
      setenv("SYMCC_INPUT_FILE", InputPath.c_str(), 1);
    }

    std::vector<char *> Args;
    Args.push_back(const_cast<char *>(Config_.ProgramPath.c_str()));
    for (const auto &Arg : Config_.Args) {
      Args.push_back(const_cast<char *>(Arg.c_str()));
    }
    Args.push_back(nullptr);

    if (Config_.UseStdin) {
      int InputFd = open(InputPath.c_str(), O_RDONLY);
      if (InputFd >= 0) {
        dup2(InputFd, STDIN_FILENO);
        close(InputFd);
      }
    }

    execv(Config_.ProgramPath.c_str(), Args.data());
    _exit(127);
  }

  if (Config_.CaptureStdout) {
    close(StdoutPipe[1]);
  }
  if (Config_.CaptureStderr) {
    close(StderrPipe[1]);
  }

  ExecutionResult Result;
  Result.Success = true;

  if (Config_.CaptureStdout) {
    char Buffer[4096];
    ssize_t N;
    while ((N = read(StdoutPipe[0], Buffer, sizeof(Buffer))) > 0) {
      Result.Stdout.append(Buffer, static_cast<size_t>(N));
    }
    close(StdoutPipe[0]);
  }

  if (Config_.CaptureStderr) {
    char Buffer[4096];
    ssize_t N;
    while ((N = read(StderrPipe[0], Buffer, sizeof(Buffer))) > 0) {
      Result.Stderr.append(Buffer, static_cast<size_t>(N));
    }
    close(StderrPipe[0]);
  }

  int Status;
  waitpid(Pid, &Status, 0);

  if (WIFEXITED(Status)) {
    Result.ExitCode = WEXITSTATUS(Status);
    Result.Accepted = (Result.ExitCode == 0);
  } else {
    Result.ExitCode = -1;
    Result.Accepted = false;
  }

  auto End = std::chrono::high_resolution_clock::now();
  Stats_.TotalExecutionTimeMs +=
      std::chrono::duration<double, std::milli>(End - Start).count();

  if (Result.Accepted) {
    Stats_.AcceptedInputs++;
  } else {
    Stats_.RejectedInputs++;
  }

  Stats_.SuccessfulExecutions++;

  if (!InputPath.empty() && InputPath != Config_.InputFile) {
    unlink(InputPath.c_str());
  }

  return Result;
}

ExecutionResult SymCCIntegration::execute(const InputPrefix &Prefix) {
  return execute(Prefix.getData());
}

ExecutionResult SymCCIntegration::execute(const std::string &Input) {
  return execute(std::vector<uint8_t>(Input.begin(), Input.end()));
}

bool SymCCIntegration::isAccepted(const std::vector<uint8_t> &Input) {
  auto Result = execute(Input);
  return Result.Success && Result.Accepted;
}

bool SymCCIntegration::initialize() {
  if (Config_.ProgramPath.empty()) {
    return false;
  }

  if (access(Config_.ProgramPath.c_str(), X_OK) != 0) {
    return false;
  }

  if (!Config_.OutputDir.empty()) {
    if (access(Config_.OutputDir.c_str(), W_OK) != 0) {
      if (mkdir(Config_.OutputDir.c_str(), 0755) != 0) {
        return false;
      }
    }
  }

  Initialized_ = true;
  return true;
}

void SymCCIntegration::cleanup() { Initialized_ = false; }

void SymCCIntegration::resetStats() { Stats_ = Stats{}; }

bool SymCCIntegration::prepareInput(const std::vector<uint8_t> &Input,
                                     std::string &InputPath) {
  if (!Config_.InputFile.empty()) {
    InputPath = Config_.InputFile;
  } else {
    char TmpPath[] = "/tmp/geninput_XXXXXX";
    int Fd = mkstemp(TmpPath);
    if (Fd < 0) {
      return false;
    }
    InputPath = TmpPath;
    close(Fd);
  }

  std::ofstream Ofs(InputPath, std::ios::binary);
  if (!Ofs) {
    return false;
  }

  Ofs.write(reinterpret_cast<const char *>(Input.data()),
            static_cast<std::streamsize>(Input.size()));

  return Ofs.good();
}

std::vector<std::vector<uint8_t>> SymCCIntegration::parseGeneratedInputs() {
  std::vector<std::vector<uint8_t>> Inputs;

  if (Config_.OutputDir.empty()) {
    return Inputs;
  }

  DIR *Dir = opendir(Config_.OutputDir.c_str());
  if (!Dir) {
    return Inputs;
  }

  struct dirent *Entry;
  while ((Entry = readdir(Dir)) != nullptr) {
    if (Entry->d_name[0] == '.') {
      continue;
    }

    std::string FilePath = Config_.OutputDir + "/" + Entry->d_name;

    struct stat StatBuf;
    if (stat(FilePath.c_str(), &StatBuf) != 0 || !S_ISREG(StatBuf.st_mode)) {
      continue;
    }

    std::ifstream Ifs(FilePath, std::ios::binary);
    if (!Ifs) {
      continue;
    }

    std::vector<uint8_t> Content((std::istreambuf_iterator<char>(Ifs)),
                                  std::istreambuf_iterator<char>());
    if (!Content.empty()) {
      Inputs.push_back(std::move(Content));
    }
  }

  closedir(Dir);
  return Inputs;
}

namespace hooks {

void initialize(ConstraintCallback OnConstraint, FunctionCallCallback OnCall,
                FunctionReturnCallback OnReturn) {
  g_ConstraintCb = std::move(OnConstraint);
  g_FunctionCallCb = std::move(OnCall);
  g_FunctionReturnCb = std::move(OnReturn);
}

void cleanup() {
  g_ConstraintCb = nullptr;
  g_FunctionCallCb = nullptr;
  g_FunctionReturnCb = nullptr;
  g_Context = nullptr;
}

void onPathConstraint(void *Expr, bool Taken, uintptr_t SiteId) {
  if (g_ConstraintCb && g_Context && Expr) {
    z3::expr Z3Expr(*g_Context, static_cast<Z3_ast>(Expr));
    g_ConstraintCb(Z3Expr, Taken, SiteId);
  }
}

void onFunctionCall(const char *Name, uintptr_t SiteId) {
  if (g_FunctionCallCb && Name) {
    g_FunctionCallCb(Name, SiteId);
  }
}

void onFunctionReturn(uintptr_t SiteId) {
  if (g_FunctionReturnCb) {
    g_FunctionReturnCb(SiteId);
  }
}

z3::context *getContext() { return g_Context; }

void setContext(z3::context *Ctx) { g_Context = Ctx; }

}

}
