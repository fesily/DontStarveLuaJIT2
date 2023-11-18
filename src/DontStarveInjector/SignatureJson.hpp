#pragma once
#include <optional>
#include "Signature.hpp"

struct SignatureJson
{
    static intptr_t current_version();
    static const char* version_path;
    bool isClient;
    std::optional<Signatures> read_from_signatures();
    void update_signatures(const Signatures &signatures);
};