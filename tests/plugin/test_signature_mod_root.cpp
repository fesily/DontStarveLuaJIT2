#include "SignatureModRoot.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

static std::string g(const fs::path &p) {
    return p.lexically_normal().generic_string();
}

static void expect_root(const fs::path &module_dir, const fs::path &want, const char *tag) {
    const auto got = signature_mod_root_from_module_dir(module_dir);
    if (g(got) != g(want)) {
        std::fprintf(stderr, "FAIL %s: dir=%s got=%s want=%s\n", tag, g(module_dir).c_str(),
                     g(got).c_str(), g(want).c_str());
        assert(g(got) == g(want));
    }
}

static void test_nested_pack_is_mod_root() {
    // plugin_core_vm.dll lives at <mod>/plugins/plugin_core_vm/plugin_core_vm.dll
    // module_dir is the DLL parent. Old walk stopped at <mod>/plugins.
    expect_root(fs::path("C:/Mod/plugins/plugin_core_vm"), fs::path("C:/Mod"), "win nested");
    expect_root(fs::path("/opt/Mod/plugins/plugin_core_vm"), fs::path("/opt/Mod"), "posix nested");
}

static void test_flat_plugins_dir_is_mod_root() {
    expect_root(fs::path("C:/Mod/plugins"), fs::path("C:/Mod"), "win flat");
    expect_root(fs::path("/opt/Mod/plugins"), fs::path("/opt/Mod"), "posix flat");
}

static void test_injector_at_mod_root() {
    expect_root(fs::path("C:/Mod"), fs::path("C:/Mod"), "win injector");
    expect_root(fs::path("/opt/Mod"), fs::path("/opt/Mod"), "posix injector");
}

static void test_legacy_shell_dirs() {
    expect_root(fs::path("C:/Mod/bin64/windows"), fs::path("C:/Mod"), "win shell");
    expect_root(fs::path("/opt/Mod/bin64/linux"), fs::path("/opt/Mod"), "linux shell");
    expect_root(fs::path("/opt/Mod/bin64/lib64"), fs::path("/opt/Mod"), "lib64 shell");
}

static void test_empty() {
    assert(signature_mod_root_from_module_dir({}).empty());
}

int main() {
    test_nested_pack_is_mod_root();
    test_flat_plugins_dir_is_mod_root();
    test_injector_at_mod_root();
    test_legacy_shell_dirs();
    test_empty();
    printf("ALL PASS signature_mod_root\n");
    return 0;
}
