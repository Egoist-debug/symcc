#include "dnslab_core/replay_failure.hpp"

#include <algorithm>

namespace dnslab {

namespace {

FailureEvidence makeReplayFailure(const ReplayStageContext &Context,
                                  const std::string &Reason,
                                  const std::string &Message, int ExitCode,
                                  bool ProcessStarted) {
  FailureEvidence Evidence;
  Evidence.Kind = "replay_error";
  Evidence.Reason = Reason;
  Evidence.Message = Message;
  Evidence.ExitCode = ExitCode;
  Evidence.Stage = Context.Stage;
  Evidence.Resolver = Context.Resolver;
  Evidence.ProcessStarted = ProcessStarted;
  if (!Context.StderrPath.empty()) {
    Evidence.StderrPath = Context.StderrPath.string();
  }
  if (Context.ExecutablePath.has_value()) {
    Evidence.ExecutablePath = Context.ExecutablePath->string();
  }
  return Evidence;
}

bool isTimeoutReturnCode(int ReturnCode) {
  return ReturnCode == 6 || ReturnCode == 124 || ReturnCode == 137;
}

} // namespace

FailureEvidence buildMissingExecutableFailure(
    const std::string &Resolver, const std::filesystem::path &ExecutablePath,
    const std::string &Message) {
  ReplayStageContext Context;
  Context.Resolver = Resolver;
  Context.Stage = Resolver + ".preflight";
  Context.ExecutablePath = ExecutablePath;
  return makeReplayFailure(Context, "missing_executable", Message,
                           kReplayExitMissingExecutable, false);
}

FailureEvidence buildReplayLaunchFailure(const ReplayStageContext &Context,
                                         const std::string &Message) {
  return makeReplayFailure(Context, "subprocess_launch_error", Message,
                           kReplayExitRuntimeFailure, false);
}

std::optional<FailureEvidence>
classifyReplayCommandResult(const ReplayStageContext &Context,
                            const CommandResult &Result) {
  if (!Result.ProcessStarted) {
    return buildReplayLaunchFailure(Context, Context.Stage + " 启动失败");
  }
  if (std::find(Context.OkReturnCodes.begin(), Context.OkReturnCodes.end(),
                Result.ExitCode) != Context.OkReturnCodes.end()) {
    return std::nullopt;
  }

  const bool TimedOut = isTimeoutReturnCode(Result.ExitCode);
  auto Evidence = makeReplayFailure(
      Context, TimedOut ? "timeout" : "subprocess_failed",
      Context.Stage + (TimedOut ? " 执行超时" : " 执行失败"),
      kReplayExitRuntimeFailure, true);
  Evidence.ReturnCode = Result.ExitCode;
  if (TimedOut) {
    Evidence.TimeoutSec = Context.TimeoutSec;
  }
  return Evidence;
}

std::optional<FailureEvidence>
classifyMissingReplayArtifact(const ReplayStageContext &Context,
                              bool ProcessStarted) {
  if (!Context.ArtifactPath.has_value()) {
    return std::nullopt;
  }

  std::error_code Error;
  const bool IsRegular =
      std::filesystem::is_regular_file(*Context.ArtifactPath, Error);
  const auto Size = IsRegular ? std::filesystem::file_size(*Context.ArtifactPath,
                                                           Error)
                              : 0;
  if (!Error && IsRegular && Size > 0) {
    return std::nullopt;
  }

  auto Evidence = makeReplayFailure(
      Context, "missing_artifact",
      Context.Stage + " 未生成有效文件: " +
          Context.ArtifactPath->filename().string(),
      kReplayExitMissingArtifact, ProcessStarted);
  Evidence.ArtifactPath = Context.ArtifactPath->filename().string();
  return Evidence;
}

} // namespace dnslab
