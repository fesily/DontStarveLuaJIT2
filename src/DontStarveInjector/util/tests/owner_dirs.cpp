#include <doctest/doctest.h>

#include "../../config/path/OwnerDirs.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>

namespace {

namespace fs = std::filesystem;

// A save folder can be named with the bytes of a GBK name stored one character
// per byte as Latin-1. Those code points are legal on NTFS but several of them
// have no CP936 mapping, so `fs::path::string()` throws
// ERROR_NO_UNICODE_TRANSLATION (1113) on a Chinese Windows. This is the shape
// that used to abort dedicated-server inject before core.vm loaded.
constexpr char8_t kUnrepresentableName[] =
    u8"\u00b7\u00e8\u00bf\u00f1\u00cc\u00cf\u00bb\u00a2\u00bb\u00fa";

struct TempRoot {
    fs::path path;

    TempRoot() {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        path = fs::temp_directory_path() /
               ("ds_owner_dirs_" + std::to_string(stamp) + "_" + std::to_string(std::rand()));
        std::error_code ec;
        fs::create_directories(path, ec);
    }
    ~TempRoot() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    TempRoot(const TempRoot &) = delete;
    TempRoot &operator=(const TempRoot &) = delete;
};

} // namespace

TEST_CASE("list_owner_dirs survives a save folder the ANSI code page cannot map") {
    TempRoot root;
    const fs::path weird = root.path / fs::path{std::u8string{kUnrepresentableName}};
    std::error_code ec;
    fs::create_directory(weird, ec);
    REQUIRE_MESSAGE(fs::is_directory(weird, ec), "cannot create the unrepresentable-name folder");
    fs::create_directories(root.path / "Cluster_1" / "Master", ec);

    bool narrow_throws = false;
    try {
        (void) weird.filename().string();
    } catch (const std::exception &) {
        narrow_throws = true;
    }

    std::vector<fs::path> dirs;
    CHECK_NOTHROW(dirs = ds::config::path::list_owner_dirs(root.path, "Cluster_1"));

    // The cluster dir hosts the shard directly; only the foreign folder remains.
    REQUIRE_EQ(dirs.size(), 1u);
    CHECK_EQ(dirs.front(), weird);
    if (!narrow_throws) {
        MESSAGE("active ANSI code page maps all test characters; "
                "only the no-throw contract is exercised here");
    }
}

TEST_CASE("list_owner_dirs returns an empty list for a missing root") {
    CHECK(ds::config::path::list_owner_dirs({}, "Cluster_1").empty());
    CHECK(ds::config::path::list_owner_dirs(fs::temp_directory_path() / "ds_owner_dirs_absent_dir",
                                            "Cluster_1")
              .empty());
}
