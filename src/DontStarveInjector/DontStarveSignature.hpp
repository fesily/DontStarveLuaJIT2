#pragma once
#include <expected>
#include <vector>
#include <string>
#include <tuple>
#include <stdint.h>
#include "Signature.hpp"
using ListExports_t = std::vector<std::pair<std::string, uintptr_t>>;
std::string update_signatures(Signatures &signatures, uintptr_t targetLuaModuleBase, const ListExports_t &exports);