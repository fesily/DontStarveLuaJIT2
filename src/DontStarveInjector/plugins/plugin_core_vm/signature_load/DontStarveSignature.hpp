#pragma once

#include <expected>
#include <vector>
#include <string>
#include <stdint.h>
#include <unordered_map>

#include "Signature.hpp"

using ListExports_t = std::vector<std::pair<std::string, uintptr_t>>;

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

std::string update_signatures_from_disasm(Signatures &signatures, uintptr_t targetLuaModuleBase, const ListExports_t &exports,
                              uint32_t range = 512, bool updated = true);
