#include "GraphSeed.hpp"
#include "ModuleSections.hpp"
#include "NucleusAdapter.hpp"
#include "ctx.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>

#define REQUIRE(condition) \
    do { \
        if (!(condition)) { \
            std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #condition, __FILE__, __LINE__); \
            std::abort(); \
        } \
    } while (0)

using function_relocation::ModuleSections;

static uintptr_t symbol(void *library, const char *name) {
    const auto address = reinterpret_cast<uintptr_t>(dlsym(library, name));
    REQUIRE(address != 0);
    return address;
}

static void analyze(const std::string &path, ModuleSections &module) {
    REQUIRE(function_relocation::init_module_signature(path.c_str(), 0, module));
    auto table = function_relocation::nucleus_analyze_file(path);
    REQUIRE(table);
    REQUIRE(function_relocation::apply_nucleus_function_table(module, table->table, table->image_base));
}

static uintptr_t runtime_import(const ModuleSections &module, const char *name) {
    for (const auto &[slot, imported]: module.import_slot_names) {
        if (imported != name) continue;
        uintptr_t address = 0;
        std::memcpy(&address, reinterpret_cast<const void *>(slot), sizeof(address));
        return address;
    }
    return 0;
}

static void check_calls(ModuleSections &module, uintptr_t caller, uintptr_t callee) {
    auto *function = module.find_function(caller);
    REQUIRE(function && function->size);
    const auto targets = function_relocation::collect_rel32_call_targets(module, caller, function->size);
    REQUIRE(std::find(targets.begin(), targets.end(), callee) != targets.end());
    REQUIRE(function_relocation::body_calls_entry(module, caller, function->size, callee));
}

int main(int argc, char **argv) {
    REQUIRE(argc == 5);
    gum_init_embedded();
    REQUIRE(function_relocation::init_ctx());
    auto *provider = dlopen(argv[3], RTLD_NOW | RTLD_GLOBAL);
    REQUIRE(provider);

    const auto collision_path = std::filesystem::absolute(argv[1]).string();
    auto *collision = dlopen(collision_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    REQUIRE(collision);
    ModuleSections module{};
    analyze(collision_path, module);
    for (const auto &[name, caller_name]: {std::pair{"plt_test_symbol", "plt_test_call_global"},
                                          std::pair{"plt_test_weak_symbol", "plt_test_call_global_weak"}}) {
        const auto own = symbol(collision, name);
        const auto interposed = symbol(provider, name);
        REQUIRE(own != interposed);
        REQUIRE(runtime_import(module, name) == interposed);
        // LOCAL symbols appear first in .symtab; the PLT refers to the defined
        // GLOBAL/WEAK dynamic symbol even while its GOT points at the provider.
        REQUIRE(module.own_definition_address(name) == own);
        check_calls(module, symbol(collision, caller_name), own);
    }

    // Only a LOCAL definition exists here. It must not substitute for the
    // genuinely external dynamic import, including after Nucleus names it.
    const auto external_path = std::filesystem::absolute(argv[2]).string();
    auto *external = dlopen(external_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    REQUIRE(external);
    analyze(external_path, module);
    const auto imported = symbol(provider, "plt_test_symbol");
    REQUIRE(module.own_definition_address("plt_test_symbol") == 0);
    REQUIRE(runtime_import(module, "plt_test_symbol") == imported);
    REQUIRE(module.known_functions.contains("plt_test_symbol"));
    REQUIRE(module.known_functions.at("plt_test_symbol")->address != imported);
    check_calls(module, symbol(external, "plt_test_call_external"), imported);

    // Real training-library self-import: the process GOT is interposed, but the
    // reference graph must still see luaL_loadstring -> its own luaL_loadbuffer.
    const auto training_path = std::filesystem::absolute(argv[4]).string();
    auto *training = dlopen(training_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    REQUIRE(training);
    analyze(training_path, module);
    const auto loadbuffer = symbol(training, "luaL_loadbuffer");
    const auto loadstring = symbol(training, "luaL_loadstring");
    REQUIRE(runtime_import(module, "luaL_loadbuffer") == symbol(provider, "luaL_loadbuffer"));
    REQUIRE(runtime_import(module, "luaL_loadbuffer") != loadbuffer);
    REQUIRE(module.own_definition_address("luaL_loadbuffer") == loadbuffer);
    check_calls(module, loadstring, loadbuffer);
    auto *caller = module.find_function(loadstring);
    REQUIRE(function_relocation::ensure_function_features(*caller));
    bool named_loadbuffer = false;
    for (auto address: caller->blocks) {
        for (auto target: module.address_blocks.at(address)->call_functions) {
            const auto *called = module.find_function(target);
            named_loadbuffer |= called && called->name == "luaL_loadbuffer";
        }
    }
    REQUIRE(named_loadbuffer);

    REQUIRE(dlclose(training) == 0);
    REQUIRE(dlclose(external) == 0);
    REQUIRE(dlclose(collision) == 0);
    REQUIRE(dlclose(provider) == 0);
    function_relocation::deinit_ctx();
    gum_deinit_embedded();
    std::puts("test_elf_plt_symbols: local/global/weak imports and interposition passed");
}
