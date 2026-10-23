// Crash sentinel state machine (util/Unsafedata.hpp).
//
// allow_inject() must arm the record for the current boot, skip exactly one boot
// after a recorded crash, and never turn an empty (cleared) record into a skip.
#include "util/Unsafedata.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using namespace ds::unsafedata;

static fs::path make_temp(const char *name) {
    auto dir = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    return dir / "unsafedata" / "luajit_crash.json";
}

static void put(const fs::path &p, const char *content) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary | std::ios::trunc) << content;
}

int main() {
    // Missing record: inject and arm (directories created on demand).
    {
        auto p = make_temp("ds_crash_absent");
        assert(allow_inject(p));
        assert(read_sentinel(p) == std::string{kArmed});
    }

    // An unresolvable root (dedicated server, no save dir) must not block boot.
    {
        assert(allow_inject(fs::path{}));
    }

    // Recorded crash: skip exactly one boot, then retry.
    {
        auto p = make_temp("ds_crash_skip_once");
        put(p, kArmed);
        assert(!allow_inject(p));
        assert(read_sentinel(p) == std::string{kSkipped});
        assert(allow_inject(p));
        assert(read_sentinel(p) == std::string{kArmed});
    }

    // Cleared by the mod (empty file): a normal boot, not a crash.
    {
        auto p = make_temp("ds_crash_cleared");
        put(p, "");
        assert(allow_inject(p));
        assert(read_sentinel(p) == std::string{kArmed});
    }

    // Unknown content (older builds wrote plain crash payloads): treat as crash.
    {
        auto p = make_temp("ds_crash_legacy");
        put(p, "{crash}");
        assert(allow_inject(p));
        assert(read_sentinel(p) == std::string{kArmed});
    }

    std::puts("test_crash_sentinel: OK");
    return 0;
}
