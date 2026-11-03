#include "GameInfoArguments.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <filesystem>
#include <vector>

int main() {
    const std::vector<std::string> defaults{"game"};
    auto info = game_info_from_arguments(defaults);
    assert(info.persist_root == ".klei/" &&
           info.config_dir == std::filesystem::path{"DoNotStarveTogether"});
    assert(info.cluster_name == std::filesystem::path{"Cluster_1"} &&
           info.shared_name == std::filesystem::path{"Master"});
    const std::vector<std::string> options{"game", "-persistent_storage_root", "/tmp/save files", "-config_dir", "custom", "-cluster=one", "-cluster", "two", "--shard=Caves"};
    info = game_info_from_arguments(options);
    assert(info.persist_root == "/tmp/save files" &&
           info.config_dir == std::filesystem::path{"custom"});
    assert(info.cluster_name == std::filesystem::path{"two"} &&
           info.shared_name == std::filesystem::path{"Caves"});
    const std::vector<std::string> invalid{"game", "-config_dir", "-cluster", "cluster", "-shard"};
    info = game_info_from_arguments(invalid);
    assert(info.config_dir == std::filesystem::path{"DoNotStarveTogether"} &&
           info.shared_name == std::filesystem::path{"Master"});
    assert(info.cluster_name == std::filesystem::path{"cluster"});
}
