#include "SignatureModRoot.hpp"

#include <cstdio>
#include <filesystem>
#include <string>
#include <doctest/doctest.h>

namespace fs = std::filesystem;

static std::string g(const fs::path &p) {
    return p.lexically_normal().generic_string();
}

static void expect_root(const fs::path &module_dir, const fs::path &want, const char *tag) {
    const auto got = signature_mod_root_from_module_dir(module_dir);
    if (g(got) != g(want)) {
        std::fprintf(stderr, "FAIL %s: dir=%s got=%s want=%s\n", tag, g(module_dir).c_str(),
                     g(got).c_str(), g(want).c_str());
        REQUIRE_EQ(g(got), g(want));
    }
}

TEST_CASE("test_signature_mod_root/nested_pack_is_mod_root") {
    // plugin_core_vm.dll lives at <mod>/plugins/plugin_core_vm/plugin_core_vm.dll
    // module_dir is the DLL parent. Old walk stopped at <mod>/plugins.
    expect_root(fs::path("C:/Mod/plugins/plugin_core_vm"), fs::path("C:/Mod"), "win nested");
    expect_root(fs::path("/opt/Mod/plugins/plugin_core_vm"), fs::path("/opt/Mod"), "posix nested");
}

TEST_CASE("test_signature_mod_root/flat_plugins_dir_is_mod_root") {
    expect_root(fs::path("C:/Mod/plugins"), fs::path("C:/Mod"), "win flat");
    expect_root(fs::path("/opt/Mod/plugins"), fs::path("/opt/Mod"), "posix flat");
}

TEST_CASE("test_signature_mod_root/injector_at_mod_root") {
    expect_root(fs::path("C:/Mod"), fs::path("C:/Mod"), "win injector");
    expect_root(fs::path("/opt/Mod"), fs::path("/opt/Mod"), "posix injector");
}

TEST_CASE("test_signature_mod_root/legacy_shell_dirs") {
    expect_root(fs::path("C:/Mod/bin64/windows"), fs::path("C:/Mod"), "win shell");
    expect_root(fs::path("/opt/Mod/bin64/linux"), fs::path("/opt/Mod"), "linux shell");
    expect_root(fs::path("/opt/Mod/bin64/lib64"), fs::path("/opt/Mod"), "lib64 shell");
}

TEST_CASE("test_signature_mod_root/empty") {
    REQUIRE(signature_mod_root_from_module_dir({}).empty());
}
