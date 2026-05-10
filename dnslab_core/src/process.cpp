#include "dnslab_core/process.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>

namespace dnslab {

namespace {

std::string shellQuote(std::string_view Input) {
  std::string Output = "'";
  for (const char Ch : Input) {
    if (Ch == '\'') {
      Output += "'\\''";
    } else {
      Output.push_back(Ch);
    }
  }
  Output += "'";
  return Output;
}

std::filesystem::path makeTempFile(const std::string &Prefix) {
  std::string Template =
      (std::filesystem::temp_directory_path() / (Prefix + ".XXXXXX")).string();
  std::vector<char> Buffer(Template.begin(), Template.end());
  Buffer.push_back('\0');
  const int Fd = mkstemp(Buffer.data());
  if (Fd < 0) {
    throw std::runtime_error("mkstemp 失败");
  }
  close(Fd);
  return Buffer.data();
}

std::string readTextFile(const std::filesystem::path &InputPath) {
  std::ifstream Input(InputPath, std::ios::binary);
  if (!Input) {
    return "";
  }
  return std::string((std::istreambuf_iterator<char>(Input)),
                     std::istreambuf_iterator<char>());
}

} // namespace

CommandResult runProcess(const ProcessRequest &Request) {
  if (Request.Arguments.empty()) {
    throw std::invalid_argument("process arguments 不能为空");
  }

  const std::filesystem::path StdoutPath = makeTempFile("dnslab.stdout");
  const std::filesystem::path StderrPath = makeTempFile("dnslab.stderr");

  std::ostringstream Command;
  if (Request.WorkingDirectory.has_value()) {
    Command << "cd " << shellQuote(Request.WorkingDirectory->string()) << " && ";
  }
  for (const auto &[Key, Value] : Request.Environment) {
    Command << Key << "=" << shellQuote(Value) << ' ';
  }
  for (const auto &Argument : Request.Arguments) {
    Command << shellQuote(Argument) << ' ';
  }
  if (Request.StdinFile.has_value()) {
    Command << "< " << shellQuote(Request.StdinFile->string()) << ' ';
  }
  Command << "> " << shellQuote(StdoutPath.string()) << ' ';
  Command << "2> " << shellQuote(StderrPath.string());

  const int RawCode = std::system(Command.str().c_str());
  const int ExitCode = WIFEXITED(RawCode) ? WEXITSTATUS(RawCode) : RawCode;

  CommandResult Output;
  Output.ExitCode = ExitCode;
  Output.StdoutText = readTextFile(StdoutPath);
  Output.StderrText = readTextFile(StderrPath);

  std::filesystem::remove(StdoutPath);
  std::filesystem::remove(StderrPath);
  return Output;
}

} // namespace dnslab
