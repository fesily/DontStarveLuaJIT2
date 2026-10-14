#pragma once

#include "ModuleSections.hpp"
#include "Signature.hpp"

#include <span>

namespace function_relocation {

    // The common generation/cache scan domain: [lower_bound, .text end).
    // Invalid bounds produce an empty range, never a local-RVA fallback.
    FUNCTION_RELOCATION_API GumMemoryRange signature_search_range(
            const ModuleSections &module, uintptr_t lower_bound);

    // Scan every supplied range without using SignatureInfo::offset as a search
    // bound. Exactly one raw byte hit must map to expected_entry.
    FUNCTION_RELOCATION_API bool validate_unique_signature(
            std::span<const GumMemoryRange> search_ranges, const SignatureInfo &signature,
            uintptr_t expected_entry);

    // Certify the resolved target's stored pattern, or replace it with a unique
    // target-binary pattern. Relative fields inside the image may stay fixed:
    // their displacement is invariant under ASLR. Absolute addresses are masked.
    // Failure leaves the signature unchanged; callers must not publish it.
    FUNCTION_RELOCATION_API bool make_unique_signature(
            const ModuleSections &module, std::span<const GumMemoryRange> search_ranges,
            uintptr_t entry, SignatureInfo &signature);

}// namespace function_relocation
