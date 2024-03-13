#pragma once

#include <string>
#include <vector>

namespace function_relocation
{
    struct Signature {
        std::vector<std::string> asm_codes;

        std::string to_string() const;

        bool operator==(const Signature& other) const;

        inline size_t size() const { return asm_codes.size(); }

        inline size_t empty() const { return asm_codes.empty(); }

        const std::string& operator[](size_t index) const { return asm_codes[index]; }
    };

    bool is_same_signature_fast(void* target, void* original);

    void release_signature_cache();
}