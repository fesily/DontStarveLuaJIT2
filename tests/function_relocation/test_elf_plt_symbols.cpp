#include "GraphSeed.hpp"
#include "ModuleSections.hpp"
#include "NucleusAdapter.hpp"
#include "support/fr_context_env.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

using function_relocation::ModuleSections;

namespace {

// Closes a dlopen handle on scope exit; close() reports the dlclose result.
struct DlHandle {
    void *handle = nullptr;

    ~DlHandle() {
        if (handle != nullptr) dlclose(handle);
    }

    int close() {
        void *open = handle;
        handle = nullptr;
        return dlclose(open);
    }
};

}// namespace

// Four positional library paths from the CTest registration; doctest options
// may follow them.
static const char *g_collision_path = nullptr;
static const char *g_external_path = nullptr;
static const char *g_provider_path = nullptr;
static const char *g_training_path = nullptr;

static uintptr_t symbol(void *library, const char *name) {
    const auto address = reinterpret_cast<uintptr_t>(dlsym(library, name));
    REQUIRE_NE(address, 0);
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
    REQUIRE_NE(function, nullptr);
    REQUIRE(function->size != 0);
    const auto targets = function_relocation::collect_rel32_call_targets(module, caller, function->size);
    REQUIRE_NE(std::find(targets.begin(), targets.end(), callee), targets.end());
    REQUIRE(function_relocation::body_calls_entry(module, caller, function->size, callee));
}

TEST_CASE("test_elf_plt_symbols/local_global_weak_interposition") {
    REQUIRE(ensure_reloc_context());
    DlHandle provider_guard{dlopen(g_provider_path, RTLD_NOW | RTLD_GLOBAL)};
    REQUIRE_NE(provider_guard.handle, nullptr);
    auto *provider = provider_guard.handle;

    const auto collision_path = std::filesystem::absolute(g_collision_path).string();
    DlHandle collision_guard{dlopen(collision_path.c_str(), RTLD_NOW | RTLD_LOCAL)};
    REQUIRE_NE(collision_guard.handle, nullptr);
    auto *collision = collision_guard.handle;
    ModuleSections module{};
    analyze(collision_path, module);
    for (const auto &[name, caller_name]: {std::pair{"plt_test_symbol", "plt_test_call_global"},
                                          std::pair{"plt_test_weak_symbol", "plt_test_call_global_weak"}}) {
        const auto own = symbol(collision, name);
        const auto interposed = symbol(provider, name);
        REQUIRE_NE(own, interposed);
        REQUIRE_EQ(runtime_import(module, name), interposed);
        // LOCAL symbols appear first in .symtab; the PLT refers to the defined
        // GLOBAL/WEAK dynamic symbol even while its GOT points at the provider.
        REQUIRE_EQ(module.own_definition_address(name), own);
        check_calls(module, symbol(collision, caller_name), own);
    }

    // Only a LOCAL definition exists here. It must not substitute for the
    // genuinely external dynamic import, including after Nucleus names it.
    const auto external_path = std::filesystem::absolute(g_external_path).string();
    DlHandle external_guard{dlopen(external_path.c_str(), RTLD_NOW | RTLD_LOCAL)};
    REQUIRE_NE(external_guard.handle, nullptr);
    auto *external = external_guard.handle;
    analyze(external_path, module);
    const auto imported = symbol(provider, "plt_test_symbol");
    REQUIRE_EQ(module.own_definition_address("plt_test_symbol"), 0);
    REQUIRE_EQ(runtime_import(module, "plt_test_symbol"), imported);
    REQUIRE(module.known_functions.contains("plt_test_symbol"));
    REQUIRE(module.known_functions.at("plt_test_symbol")->address != imported);
    check_calls(module, symbol(external, "plt_test_call_external"), imported);

    // Real training-library self-import: the process GOT is interposed, but the
    // reference graph must still see luaL_loadstring -> its own luaL_loadbuffer.
    const auto training_path = std::filesystem::absolute(g_training_path).string();
    DlHandle training_guard{dlopen(training_path.c_str(), RTLD_NOW | RTLD_LOCAL)};
    REQUIRE_NE(training_guard.handle, nullptr);
    auto *training = training_guard.handle;
    analyze(training_path, module);
    const auto loadbuffer = symbol(training, "luaL_loadbuffer");
    const auto loadstring = symbol(training, "luaL_loadstring");
    REQUIRE_EQ(runtime_import(module, "luaL_loadbuffer"), symbol(provider, "luaL_loadbuffer"));
    REQUIRE_NE(runtime_import(module, "luaL_loadbuffer"), loadbuffer);
    REQUIRE_EQ(module.own_definition_address("luaL_loadbuffer"), loadbuffer);
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

    REQUIRE_EQ(training_guard.close(), 0);
    REQUIRE_EQ(external_guard.close(), 0);
    REQUIRE_EQ(collision_guard.close(), 0);
    REQUIRE_EQ(provider_guard.close(), 0);
}

int main(int argc, char **argv) {
    // Four positional library paths: collision, external, provider, training.
    // Doctest options (for example --test-case=...) may follow them.
    if (argc < 5) {
        std::fprintf(stderr,
                     "usage: %s <collision.so> <external.so> <provider.so> <training.so> [doctest options]\n",
                     argv[0]);
        return 2;
    }
    g_collision_path = argv[1];
    g_external_path = argv[2];
    g_provider_path = argv[3];
    g_training_path = argv[4];
    doctest::Context context;
    context.setOption("no-breaks", true);
    context.applyCommandLine(argc, argv);
    return context.run();
}
