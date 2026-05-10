#include "dnslab_core/resolver_lock.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>

int main() {
  const std::filesystem::path TempDir =
      std::filesystem::temp_directory_path() / "dnslab_core_lock_test";
  std::filesystem::create_directories(TempDir);
  const std::filesystem::path ManifestPath = TempDir / "manifest.tsv";

  {
    std::ofstream Output(ManifestPath);
    Output << "resolver\trepo_url\tdesired_tag\tcandidate_tags\tnote\n";
    Output << "unbound\thttps://example/unbound.git\trelease-1.24.2\t"
              "release-1.24.2\ttest\n";
    Output << "bind9\thttps://example/bind9.git\tv9.20.22\tv9.20.22\tbind9\n";
  }

  const auto Manifest = dnslab::loadResolverManifestTsv(ManifestPath);
  assert(Manifest.size() == 2U);
  assert(Manifest[0].Resolver == "unbound");
  assert(Manifest[1].DesiredTag == "v9.20.22");

  const auto Runner = [](const std::vector<std::string> &Arguments) {
    assert(Arguments.size() == 4U);
    dnslab::CommandOutput Output;
    Output.ExitCode = 0;
    if (Arguments[3].find("unbound") != std::string::npos) {
      Output.StdoutText =
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t"
          "refs/tags/release-1.24.2\n";
    } else {
      Output.StdoutText =
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t"
          "refs/tags/v9.20.22\n";
    }
    return Output;
  };

  const auto LockFile = dnslab::generateResolverLockFile(Manifest, Runner);
  assert(LockFile.Resolvers.size() == 2U);
  assert(LockFile.Resolvers[0].Status == dnslab::ResolverLockStatus::Locked);
  assert(LockFile.Resolvers[0].CommitSha.has_value());
  assert(*LockFile.Resolvers[1].ResolvedTag == "v9.20.22");
  assert(dnslab::defaultResolverLockFilePath(TempDir) ==
         TempDir / "experiments" / "resolvers.lock.json");

  const auto LockPath = TempDir / "resolvers.lock.json";
  dnslab::writeResolverLockFile(LockPath, LockFile);
  const auto Reloaded = dnslab::loadResolverLockFileJson(LockPath);
  assert(Reloaded.Resolvers.size() == 2U);
  const auto UnboundEntry = dnslab::findResolverLockEntry(Reloaded, "unbound");
  assert(UnboundEntry.has_value());
  assert(UnboundEntry->RepoUrl == "https://example/unbound.git");
  const auto Bind9Tag = dnslab::resolveLockedTag(Reloaded, "bind9");
  assert(Bind9Tag.has_value());
  assert(*Bind9Tag == "v9.20.22");
  assert(!dnslab::resolveLockedTag(Reloaded, "missing").has_value());

  std::filesystem::remove_all(TempDir);
  return 0;
}
