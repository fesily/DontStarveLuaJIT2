#include "UniqueSignature.hpp"
#include "MemorySignature.hpp"
#include "support/fr_context_env.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstring>

using function_relocation::ModuleSections;
using function_relocation::SignatureInfo;
using function_relocation::make_unique_signature;
using function_relocation::validate_unique_signature;

static ModuleSections module_for(uint8_t *bytes, size_t size) {
    ModuleSections module{};
    module.text = module.details.range = {reinterpret_cast<uintptr_t>(bytes), size};
    return module;
}

TEST_CASE("test_unique_signature/cached_offset_does_not_hide_other_hits") {
    REQUIRE(ensure_reloc_context());
    std::array<uint8_t, 128> bytes{};
    const uint8_t body[] = {0x31, 0xc0, 0xc3};
    std::memcpy(bytes.data() + 16, body, sizeof(body));
    std::memcpy(bytes.data() + 80, body, sizeof(body));
    auto module = module_for(bytes.data(), bytes.size());
    const auto entry = module.text.base_address + 80;
    SignatureInfo signature{80, "31 c0 c3", 0};
    function_relocation::MemorySignature local{signature.pattern.c_str(), 0};
    local.log = false;
    REQUIRE_EQ(local.scan(entry, sizeof(body)), entry);
    REQUIRE_FALSE(validate_unique_signature({&module.text, 1}, signature, entry));
    // Both hits inside the same FDE still violate raw byte uniqueness.
    module.function_table.add({module.text.base_address, module.text.base_address + bytes.size()});
    REQUIRE_FALSE(validate_unique_signature({&module.text, 1}, signature, entry));
    const std::array<GumMemoryRange, 2> executable{{{module.text.base_address + 8, 32}, {module.text.base_address + 72, 32}}};
    REQUIRE_FALSE(validate_unique_signature(executable, signature, entry));
}

TEST_CASE("test_unique_signature/pattern_offset_maps_only_after_unique_scan") {
    REQUIRE(ensure_reloc_context());
    const uint8_t initial[] = {0x55, 0x90, 0xb8, 0x42, 0, 0, 0, 0xc3};
    std::array<uint8_t, sizeof(initial)> bytes{};
    std::memcpy(bytes.data(), initial, sizeof(initial));
    auto module = module_for(bytes.data(), bytes.size());
    SignatureInfo signature{0, "b8 42 00 00 00 c3", -2};
    REQUIRE(validate_unique_signature({&module.text, 1}, signature, module.text.base_address));
    REQUIRE_FALSE(validate_unique_signature({&module.text, 1}, signature, module.text.base_address + 1));
    signature.pattern_offset = 2;
    REQUIRE_FALSE(validate_unique_signature({&module.text, 1}, signature, module.text.base_address));
    REQUIRE_FALSE(validate_unique_signature({}, signature, module.text.base_address));
    signature.pattern = "?? ??";
    REQUIRE_FALSE(validate_unique_signature({&module.text, 1}, signature, module.text.base_address));
}

TEST_CASE("test_unique_signature/lua_base_defines_the_search_domain") {
    REQUIRE(ensure_reloc_context());
    std::array<uint8_t, 128> bytes{};
    const uint8_t body[] = {0x31, 0xc0, 0xc3};
    std::memcpy(bytes.data() + 16, body, sizeof(body));
    std::memcpy(bytes.data() + 80, body, sizeof(body));
    auto module = module_for(bytes.data(), bytes.size());
    const auto base = module.text.base_address + 64;
    const auto entry = module.text.base_address + 80;
    const auto range = function_relocation::signature_search_range(module, base);
    REQUIRE_EQ(range.base_address, base);
    REQUIRE_EQ(range.size, 64);
    SignatureInfo signature{16, "31 c0 c3", 0};
    // The duplicate before Lua base is outside the agreed search domain.
    REQUIRE(validate_unique_signature({&range, 1}, signature, entry));
    REQUIRE(make_unique_signature(module, {&range, 1}, entry, signature));
    REQUIRE_EQ(signature.pattern, "31 c0 c3");
    // A second raw match after Lua base must fail, even with a correct RVA.
    std::memcpy(bytes.data() + 96, body, sizeof(body));
    REQUIRE_FALSE(validate_unique_signature({&range, 1}, signature, entry));
    const auto end = module.text.base_address + module.text.size;
    REQUIRE_EQ(function_relocation::signature_search_range(module, end).size, 0);
    REQUIRE_EQ(function_relocation::signature_search_range(module, end + 1).size, 0);
    REQUIRE_EQ(function_relocation::signature_search_range(module, module.text.base_address - 1).size, 0);
}

TEST_CASE("test_unique_signature/ambiguous_wrappers_use_aslr_stable_relative_fields") {
    REQUIRE(ensure_reloc_context());
    std::array<uint8_t, 256> bytes;
    bytes.fill(0xcc);
    const uint8_t wrapper[] = {0xe8, 0, 0, 0, 0, 0xc3};
    for (size_t position: {size_t{16}, size_t{80}}) {
        std::memcpy(bytes.data() + position, wrapper, sizeof(wrapper));
        const int32_t rel = static_cast<int32_t>(160 - (position + 5));
        std::memcpy(bytes.data() + position + 1, &rel, sizeof(rel));
    }
    bytes[160] = 0xc3;
    auto module = module_for(bytes.data(), bytes.size());
    const auto entry = module.text.base_address + 80;
    module.function_table.add({entry, entry + sizeof(wrapper)});
    SignatureInfo signature{80, "e8 ?? ?? ?? ?? c3", 0};
    REQUIRE_FALSE(validate_unique_signature({&module.text, 1}, signature, entry));
    REQUIRE(make_unique_signature(module, {&module.text, 1}, entry, signature));
    REQUIRE_EQ(signature.offset, 80);
    REQUIRE_EQ(signature.pattern_offset, 0);
    REQUIRE_EQ(signature.pattern.find("??"), std::string::npos);
    REQUIRE(validate_unique_signature({&module.text, 1}, signature, entry));

    auto moved_bytes = bytes;
    auto moved = module_for(moved_bytes.data(), moved_bytes.size());
    REQUIRE(validate_unique_signature({&moved.text, 1}, signature, moved.text.base_address + 80));
}

TEST_CASE("test_unique_signature/identical_short_bodies_extend_context") {
    REQUIRE(ensure_reloc_context());
    std::array<uint8_t, 256> bytes;
    bytes.fill(0xcc);
    bytes[16] = bytes[80] = 0xc3;
    bytes[17] = 0x90;
    bytes[81] = 0x55;
    auto module = module_for(bytes.data(), bytes.size());
    const auto entry = module.text.base_address + 80;
    module.function_table.add({entry, entry + 1});
    SignatureInfo signature{80, "c3", 0};
    REQUIRE(make_unique_signature(module, {&module.text, 1}, entry, signature));
    REQUIRE(signature.pattern.starts_with("c3 55"));
    REQUIRE(validate_unique_signature({&module.text, 1}, signature, entry));
}

TEST_CASE("test_unique_signature/absolute_image_addresses_stay_masked") {
    REQUIRE(ensure_reloc_context());
    std::array<uint8_t, 128> bytes;
    bytes.fill(0xcc);
    bytes[16] = 0x48;
    bytes[17] = 0xb8;
    const auto pointer = reinterpret_cast<uintptr_t>(bytes.data() + 64);
    std::memcpy(bytes.data() + 18, &pointer, sizeof(pointer));
    bytes[26] = 0xc3;
    auto module = module_for(bytes.data(), bytes.size());
    const auto entry = module.text.base_address + 16;
    module.function_table.add({entry, entry + 11});
    SignatureInfo signature{16, {}, 0};
    REQUIRE(make_unique_signature(module, {&module.text, 1}, entry, signature));
    REQUIRE_EQ(signature.pattern, "48 b8 ?? ?? ?? ?? ?? ?? ?? ?? c3");
    auto moved_bytes = bytes;
    const auto moved_pointer = reinterpret_cast<uintptr_t>(moved_bytes.data() + 64);
    std::memcpy(moved_bytes.data() + 18, &moved_pointer, sizeof(moved_pointer));
    auto moved = module_for(moved_bytes.data(), moved_bytes.size());
    REQUIRE(validate_unique_signature({&moved.text, 1}, signature, moved.text.base_address + 16));
}

TEST_CASE("test_unique_signature/cannot_publish_identical_contexts") {
    REQUIRE(ensure_reloc_context());
    std::array<uint8_t, 2048> bytes;
    bytes.fill(0x90);
    auto module = module_for(bytes.data(), bytes.size());
    const auto entry = module.text.base_address + 1024;
    module.function_table.add({entry, entry + 1});
    SignatureInfo signature{1024, "90", 0};
    REQUIRE_FALSE(make_unique_signature(module, {&module.text, 1}, entry, signature));
    REQUIRE_EQ(signature.pattern, "90");
    REQUIRE_EQ(signature.offset, 1024);
    REQUIRE_EQ(signature.pattern_offset, 0);
}
