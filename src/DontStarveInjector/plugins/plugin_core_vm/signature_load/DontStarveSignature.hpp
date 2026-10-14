#pragma once

#include <expected>
#include <vector>
#include <string>
#include <string_view>
#include <stdint.h>
#include <unordered_map>

#include "Signature.hpp"

using ListExports_t = std::vector<std::pair<std::string, uintptr_t>>;
bool is_lua_signature_export(std::string_view name);

struct Signatures {
    uintptr_t version;
    
    std::unordered_map<std::string, function_relocation::SignatureInfo> funcs;
};

// What create_or_update() may do with the stored DB. Auto reproduces the
// in-game behaviour (create when missing, fix when stale); the tool targets
// force one of the two so a run never silently skips work.
enum class SignatureMode {
    Auto,   // create when the DB is missing, update when stale, rewrite otherwise
    Create, // ignore the stored DB and rebuild every entry from scratch
    Update, // require a stored DB and re-resolve every entry, ignoring a version match
};

struct SignatureUpdater {
    Signatures signatures;
    ListExports_t exports;

    static std::expected<SignatureUpdater, std::string> create_or_update(
            bool isClient, uintptr_t luaModuleBaseAddress, std::string signatures_path = {},
            SignatureMode mode = SignatureMode::Auto);
    static std::expected<SignatureUpdater, std::string> create(uintptr_t luaModuleBaseAddress);
};

std::string update_signatures_from_disasm(Signatures &signatures, uintptr_t targetLuaModuleBase, const ListExports_t &exports);

namespace function_relocation {
    struct ModuleSections;
}
// Offline verification uses the same resolver on non-executable mapped ELF
// images. Callers supply already analyzed tables/features; no game runs.
std::string resolve_lua_signatures_from_modules(Signatures &signatures, uintptr_t base, const ListExports_t &exports,
                                                function_relocation::ModuleSections &train,
                                                function_relocation::ModuleSections &game);
