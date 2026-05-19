#pragma once

#include "dnslab_core/json_value.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace dnslab {

struct FollowDiffRunArtifacts {
  std::filesystem::path WorkDir;
  std::filesystem::path FollowRoot;
  std::filesystem::path StatePath;
  std::filesystem::path WindowSummaryPath;
  std::string RunId;
  std::string ExitReason;
  int ExitCode = 0;
  size_t CompletedCount = 0;
  size_t FailedCount = 0;
  size_t ScannedCount = 0;
  std::optional<std::string> LastQueueEventId;
};

struct CampaignCloseArtifacts {
  std::filesystem::path WorkDir;
  std::filesystem::path FollowRoot;
  std::filesystem::path SummaryPath;
  std::filesystem::path WindowSummaryPath;
  std::string ExitReason;
  int ExitCode = 0;
  std::optional<std::string> RunId;
  size_t SampleCount = 0;
  size_t SemanticFrontierEntryCount = 0;
};

FollowDiffRunArtifacts runFollowDiffOnce();
FollowDiffRunArtifacts
runFollowDiffWindow(double BudgetSec, bool RetryFailed = false,
                    std::optional<std::string> QueueTailId = std::nullopt);
CampaignCloseArtifacts runCampaignClose(double BudgetSec);

json::Value toJson(const FollowDiffRunArtifacts &Input);
json::Value toJson(const CampaignCloseArtifacts &Input);

} // namespace dnslab
