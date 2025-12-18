#include "process.hpp"

#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace symcc_fuzzing {

static void set_env(const std::map<std::string, std::string>& extra_env) {
  for (const auto& [k, v] : extra_env) {
    ::setenv(k.c_str(), v.c_str(), 1);
  }
}

ProcessResult run_process(const std::vector<std::string>& argv,
                          const std::map<std::string, std::string>& extra_env,
                          const std::optional<std::filesystem::path>& stdin_file,
                          bool capture_stderr) {
  ProcessResult out;

  int stderr_pipe[2] = {-1, -1};
  if (capture_stderr) {
    if (::pipe(stderr_pipe) != 0) {
      throw std::runtime_error("pipe() failed: " + std::string(std::strerror(errno)));
    }
  }

  pid_t pid = ::fork();
  if (pid < 0) {
    throw std::runtime_error("fork() failed: " + std::string(std::strerror(errno)));
  }

  if (pid == 0) {
    // Child
    set_env(extra_env);

    // stdout -> /dev/null
    int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDOUT_FILENO);
      ::close(devnull);
    }

    if (capture_stderr) {
      ::close(stderr_pipe[0]);
      ::dup2(stderr_pipe[1], STDERR_FILENO);
      ::close(stderr_pipe[1]);
    } else {
      int devnull2 = ::open("/dev/null", O_WRONLY);
      if (devnull2 >= 0) {
        ::dup2(devnull2, STDERR_FILENO);
        ::close(devnull2);
      }
    }

    if (stdin_file.has_value()) {
      int in = ::open(stdin_file->c_str(), O_RDONLY);
      if (in >= 0) {
        ::dup2(in, STDIN_FILENO);
        ::close(in);
      }
    } else {
      int devnull_in = ::open("/dev/null", O_RDONLY);
      if (devnull_in >= 0) {
        ::dup2(devnull_in, STDIN_FILENO);
        ::close(devnull_in);
      }
    }

    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);

    ::execvp(cargv[0], cargv.data());
    _exit(127);
  }

  // Parent
  if (capture_stderr) {
    ::close(stderr_pipe[1]);
    char buf[4096];
    ssize_t n = 0;
    while ((n = ::read(stderr_pipe[0], buf, sizeof(buf))) > 0) {
      out.stderr_output.append(buf, static_cast<std::size_t>(n));
    }
    ::close(stderr_pipe[0]);
  }

  int status = 0;
  if (::waitpid(pid, &status, 0) < 0) {
    throw std::runtime_error("waitpid() failed: " + std::string(std::strerror(errno)));
  }

  if (WIFEXITED(status)) {
    out.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    out.signaled = true;
    out.term_signal = WTERMSIG(status);
    out.exit_code = 128 + out.term_signal;
  }

  return out;
}

}  // namespace symcc_fuzzing
