#include "core/EnabledDstMods.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>
#include <doctest/doctest.h>

#if defined(_WIN32)
#  include <Windows.h>
#endif

namespace fs = std::filesystem;
using namespace ds::plugin;

namespace {

fs::path make_temp_dir(const char *name) {
    auto d = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d);
    return d;
}

void write_file(const fs::path &p, const std::string &body) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out << body;
}

void set_env(const char *k, const char *v) {
#if defined(_WIN32)
    _putenv_s(k, v ? v : "");
#else
    if (v) {
        setenv(k, v, 1);
    } else {
        unsetenv(k);
    }
#endif
}

// Restores the DS_LUAJIT_* variables a case mutates; a failed REQUIRE unwinds
// past the tail set_env("", ...) calls, so the restore runs from the destructor.
// Entry values are put back verbatim (including a value the user had set).
class EnvGuard {
public:
    explicit EnvGuard(std::initializer_list<const char *> names) {
        for (const char *n : names) {
            Entry e;
            e.name = n;
            if (const char *prev = std::getenv(n)) {
                e.had = true;
                e.value = prev;
            }
            saved_.push_back(std::move(e));
        }
    }
    ~EnvGuard() {
        for (const auto &e : saved_) {
            set_env(e.name.c_str(), e.had ? e.value.c_str() : nullptr);
        }
    }
    EnvGuard(const EnvGuard &) = delete;
    EnvGuard &operator=(const EnvGuard &) = delete;

private:
    struct Entry {
        std::string name;
        bool had = false;
        std::string value;
    };
    std::vector<Entry> saved_;
};

} // namespace

TEST_CASE("test_enabled_dst_mods/parse_modoverrides_enabled_only") {
    auto dir = make_temp_dir("ds_enabled_mods_ov");
    auto path = dir / "modoverrides.lua";
    write_file(path, R"lua(
return {
  ["workshop-111"] = { enabled = true, configuration_options = {} },
  ["localmod"] = { enabled = false },
  ["plain"] = { enabled = true },
  ["missing_flag"] = { configuration_options = {} },
}
)lua");
    auto names = parse_modoverrides_enabled_names(path);
    REQUIRE_EQ(names.size(), 2);
    bool has111 = false, hasplain = false, haslocal = false;
    for (const auto &n : names) {
        if (n == "workshop-111") {
            has111 = true;
        }
        if (n == "plain") {
            hasplain = true;
        }
        if (n == "localmod") {
            haslocal = true;
        }
    }
    REQUIRE(has111);
    REQUIRE(hasplain);
    REQUIRE_FALSE(haslocal);
}

TEST_CASE("test_enabled_dst_mods/parse_missing_file") {
    auto names = parse_modoverrides_enabled_names(
        fs::temp_directory_path() / "ds_enabled_mods_missing" / "nope.lua");
    REQUIRE(names.empty());
}

TEST_CASE("test_enabled_dst_mods/resolve_and_enumerate_server") {
    EnvGuard env{"DS_LUAJIT_MODS_ROOT", "DS_LUAJIT_MODOVERRIDES_PATH",
                "DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "DS_LUAJIT_CLIENT_ENABLED_MODS"};
    auto sandbox = make_temp_dir("ds_enabled_mods_enum");
    auto mods_root = sandbox / "mods";
    auto mod_a = mods_root / "workshop-111";
    auto mod_b = mods_root / "plain";
    fs::create_directories(mod_a);
    fs::create_directories(mod_b);
    auto ov = sandbox / "modoverrides.lua";
    write_file(ov, R"lua(
return {
  ["workshop-111"] = { enabled = true },
  ["plain"] = { enabled = false },
}
)lua");

    set_env("DS_LUAJIT_MODS_ROOT", mods_root.string().c_str());
    set_env("DS_LUAJIT_MODOVERRIDES_PATH", ov.string().c_str());
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "");
    set_env("DS_LUAJIT_CLIENT_ENABLED_MODS", "");

    auto list = enumerate_enabled_dst_mods(/*is_client=*/false);
    REQUIRE_EQ(list.size(), 1);
    REQUIRE_EQ(list[0].name, "workshop-111");
    REQUIRE_FALSE(list[0].root.empty());
    REQUIRE(fs::exists(list[0].root));
}

TEST_CASE("test_enabled_dst_mods/extra_roots_seam") {
    EnvGuard env{"DS_LUAJIT_MODS_ROOT", "DS_LUAJIT_MODOVERRIDES_PATH",
                "DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "DS_LUAJIT_CLIENT_ENABLED_MODS"};
    auto sandbox = make_temp_dir("ds_enabled_mods_extra");
    auto mod = sandbox / "my_pack";
    fs::create_directories(mod);
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", mod.string().c_str());
    set_env("DS_LUAJIT_MODOVERRIDES_PATH", "");
    set_env("DS_LUAJIT_CLIENT_ENABLED_MODS", "");
    auto list = enumerate_enabled_dst_mods(true);
    REQUIRE_EQ(list.size(), 1);
    REQUIRE_EQ(list[0].name, "my_pack");
}
