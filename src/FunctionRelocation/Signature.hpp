#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace function_relocation {
    struct SignatureInfo {
        uintptr_t offset;
        std::string pattern;
        int pattern_offset;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(SignatureInfo, offset, pattern, pattern_offset);

    struct Signature {
        std::vector<std::string> asm_codes;

        std::string to_string(bool lineMode = true) const;

        bool operator==(const Signature &other) const;

        inline size_t size() const { return asm_codes.size(); }

        inline size_t empty() const { return asm_codes.empty(); }

        const std::string &operator[](size_t index) const { return asm_codes[index]; }
    };

    void release_signature_cache();
}