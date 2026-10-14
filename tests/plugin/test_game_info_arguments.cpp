#include "GameInfoArguments.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <vector>

int main() {
    const std::vector<std::string> defaults{"game"};
    auto info = game_info_from_arguments(defaults);
    assert(info.persist_root == ".klei/" && info.config_dir == "DoNotStarveTogether");
    assert(info.cluster_name == "Cluster_1" && info.shared_name == "Master");
    const std::vector<std::string> options{"game", "-persistent_storage_root", "/tmp/save files", "-config_dir", "custom", "-cluster=one", "-cluster", "two", "--shard=Caves"};
    info = game_info_from_arguments(options);
    assert(info.persist_root == "/tmp/save files" && info.config_dir == "custom");
    assert(info.cluster_name == "two" && info.shared_name == "Caves");
    const std::vector<std::string> invalid{"game", "-config_dir", "-cluster", "cluster", "-shard"};
    info = game_info_from_arguments(invalid);
    assert(info.config_dir == "DoNotStarveTogether" && info.shared_name == "Master");
    assert(info.cluster_name == "cluster");
}
