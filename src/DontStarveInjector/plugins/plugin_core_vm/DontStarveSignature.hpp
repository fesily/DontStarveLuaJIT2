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

struct SignatureUpdater {
    Signatures signatures;
    ListExports_t exports;

    static std::expected<SignatureUpdater, std::string> create_or_update(bool isClient, uintptr_t luaModuleBaseAddress);
    static std::expected<SignatureUpdater, std::string> create(uintptr_t luaModuleBaseAddress);
};

std::string update_signatures_from_disasm(Signatures &signatures, uintptr_t targetLuaModuleBase, const ListExports_t &exports,
                              uint32_t range = 512, bool updated = true);
