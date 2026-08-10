#pragma once

#include "dnslab_core/evidence_contract.hpp"
#include "dnslab_core/resolver_adapter.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace dnslab {

constexpr int kReplayExitMissingExecutable = 3;
constexpr int kReplayExitRuntimeFailure = 4;
constexpr int kReplayExitMissingArtifact = 5;

struct ReplayStageContext {
  std::string Resolver;
  std::string Stage;
  std::filesystem::path StderrPath;
  std::optional<std::filesystem::path> ArtifactPath;
  std::optional<std::filesystem::path> ExecutablePath;
  std::optional<int> TimeoutSec;
  std::vector<int> OkReturnCodes = {0};
};

FailureEvidence buildMissingExecutableFailure(
    const std::string &Resolver, const std::filesystem::path &ExecutablePath,
    const std::string &Message);
FailureEvidence buildReplayLaunchFailure(const ReplayStageContext &Context,
                                         const std::string &Message);
std::optional<FailureEvidence>
classifyReplayCommandResult(const ReplayStageContext &Context,
                            const CommandResult &Result);
std::optional<FailureEvidence>
classifyMissingReplayArtifact(const ReplayStageContext &Context,
                              bool ProcessStarted);

} // namespace dnslab
