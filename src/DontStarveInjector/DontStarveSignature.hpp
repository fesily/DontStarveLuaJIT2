#pragma once
#include <expected>
#include <vector>
#include <string>
#include <tuple>
#include <stdint.h>
#include "util/Signature.hpp"
using ListExports_t = std::vector<std::pair<std::string, uintptr_t>>;
std::string update_signatures(Signatures &signatures, uintptr_t targetLuaModuleBase, const ListExports_t &exports, uint32_t range = 512, bool updated = true);