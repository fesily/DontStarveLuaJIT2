#include "GameInfoArguments.hpp"
#include <filesystem>
#include <vector>
#include <doctest/doctest.h>

TEST_CASE("test_game_info_arguments/all") {
    const std::vector<std::string> defaults{"game"};
    auto info = game_info_from_arguments(defaults);
    REQUIRE_EQ(info.persist_root, ".klei/");
    REQUIRE_EQ(info.config_dir, std::filesystem::path{"DoNotStarveTogether"});
    REQUIRE_EQ(info.cluster_name, std::filesystem::path{"Cluster_1"});
    REQUIRE_EQ(info.shared_name, std::filesystem::path{"Master"});
    const std::vector<std::string> options{"game", "-persistent_storage_root", "/tmp/save files", "-config_dir", "custom", "-cluster=one", "-cluster", "two", "--shard=Caves"};
    info = game_info_from_arguments(options);
    REQUIRE_EQ(info.persist_root, "/tmp/save files");
    REQUIRE_EQ(info.config_dir, std::filesystem::path{"custom"});
    REQUIRE_EQ(info.cluster_name, std::filesystem::path{"two"});
    REQUIRE_EQ(info.shared_name, std::filesystem::path{"Caves"});
    const std::vector<std::string> invalid{"game", "-config_dir", "-cluster", "cluster", "-shard"};
    info = game_info_from_arguments(invalid);
    REQUIRE_EQ(info.config_dir, std::filesystem::path{"DoNotStarveTogether"});
    REQUIRE_EQ(info.shared_name, std::filesystem::path{"Master"});
    REQUIRE_EQ(info.cluster_name, std::filesystem::path{"cluster"});
}
