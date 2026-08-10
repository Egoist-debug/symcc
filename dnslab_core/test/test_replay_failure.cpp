#include "dnslab_core/replay_failure.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>

int main() {
  const auto Root = std::filesystem::temp_directory_path() /
                    "dnslab_replay_failure_test";
  std::filesystem::remove_all(Root);
  std::filesystem::create_directories(Root);

  dnslab::ReplayStageContext Context;
  Context.Resolver = "unbound";
  Context.Stage = "unbound.before";
  Context.StderrPath = "unbound.stderr";
  Context.ArtifactPath = Root / "unbound.before.cache.txt";
  Context.TimeoutSec = 1;
  Context.OkReturnCodes = {0, 1};

  dnslab::CommandResult Success;
  Success.ExitCode = 1;
  Success.ProcessStarted = true;
  assert(!dnslab::classifyReplayCommandResult(Context, Success).has_value());

  for (const int ReturnCode : {6, 124, 137}) {
    dnslab::CommandResult Timeout;
    Timeout.ExitCode = ReturnCode;
    Timeout.ProcessStarted = true;
    const auto Failure =
        dnslab::classifyReplayCommandResult(Context, Timeout);
    assert(Failure.has_value());
    assert(Failure->Reason == std::optional<std::string>("timeout"));
    assert(Failure->ExitCode ==
           std::optional<int>(dnslab::kReplayExitRuntimeFailure));
    assert(Failure->ReturnCode == std::optional<int>(ReturnCode));
    assert(Failure->TimeoutSec == std::optional<int>(1));
  }

  dnslab::CommandResult Failed;
  Failed.ExitCode = 42;
  Failed.ProcessStarted = true;
  const auto SubprocessFailure =
      dnslab::classifyReplayCommandResult(Context, Failed);
  assert(SubprocessFailure.has_value());
  assert(SubprocessFailure->Reason ==
         std::optional<std::string>("subprocess_failed"));
  assert(!SubprocessFailure->TimeoutSec.has_value());

  dnslab::CommandResult NotStarted;
  NotStarted.ExitCode = -1;
  const auto LaunchFailure =
      dnslab::classifyReplayCommandResult(Context, NotStarted);
  assert(LaunchFailure.has_value());
  assert(LaunchFailure->Reason ==
         std::optional<std::string>("subprocess_launch_error"));
  assert(LaunchFailure->ProcessStarted == std::optional<bool>(false));
  assert(!LaunchFailure->ReturnCode.has_value());

  const auto MissingArtifact =
      dnslab::classifyMissingReplayArtifact(Context, true);
  assert(MissingArtifact.has_value());
  assert(MissingArtifact->Reason ==
         std::optional<std::string>("missing_artifact"));
  assert(MissingArtifact->ArtifactPath ==
         std::optional<std::string>("unbound.before.cache.txt"));
  assert(!MissingArtifact->ReturnCode.has_value());

  std::ofstream(*Context.ArtifactPath) << "cache-entry\n";
  assert(!dnslab::classifyMissingReplayArtifact(Context, true).has_value());

  const auto MissingExecutable = dnslab::buildMissingExecutableFailure(
      "unbound", Root / "unbound-fuzzme", "unbound 可执行文件不可执行");
  assert(MissingExecutable.Reason ==
         std::optional<std::string>("missing_executable"));
  assert(MissingExecutable.ExitCode ==
         std::optional<int>(dnslab::kReplayExitMissingExecutable));
  assert(MissingExecutable.Stage ==
         std::optional<std::string>("unbound.preflight"));
  assert(MissingExecutable.ProcessStarted == std::optional<bool>(false));

  std::filesystem::remove_all(Root);
  return 0;
}
