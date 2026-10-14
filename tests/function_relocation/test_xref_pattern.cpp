// unique_const must persist a scannable gum pattern from the string-xref
// insn (wildcard the disp32/imm32), not clear SignatureInfo::pattern.
//
// Header-only: XrefPattern.hpp, no frida-gum.

#include "XrefPattern.hpp"
#include "InstructionPattern.hpp"
#include "MemorySignature.hpp"
#include "ModuleSections.hpp"
#include "Signature.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#define REQUIRE(cond)                                                                          \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__);  \
            std::abort();                                                                      \
        }                                                                                      \
    } while (0)

static bool token_is_wildcard(const std::string &tok) { return tok == "??"; }

static std::vector<std::string> split_tokens(const std::string &pat) {
    std::vector<std::string> out;
    std::string cur;
    for (char c: pat) {
        if (c == ' ') {
            if (!cur.empty()) {
                out.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// RIP LEA at +8: 48 8d 05 disp32. Pattern must keep opcode/ModRM and
// wildcard exactly the 4 displacement bytes. pattern_offset maps window
// start back to entry (byte 0).
static void test_rip_lea_wildcards_disp32() {
    std::vector<uint8_t> body(40, 0x90); // nop pad
    // entry+0: 48 83 ec 28   sub rsp, 28h
    body[0] = 0x48;
    body[1] = 0x83;
    body[2] = 0xec;
    body[3] = 0x28;
    body[4] = 0x48;
    body[5] = 0x89;
    body[6] = 0x5c;
    body[7] = 0x24;
    // +8: 48 8d 05 11 22 33 44   lea rax, [rip+disp]
    body[8] = 0x48;
    body[9] = 0x8d;
    body[10] = 0x05;
    body[11] = 0x11;
    body[12] = 0x22;
    body[13] = 0x33;
    body[14] = 0x44;
    body[15] = 0x48;
    body[16] = 0x8b;
    body[17] = 0x00;

    const auto xp = function_relocation::make_xref_wildcard_pattern(
            std::span<const uint8_t>{body.data(), body.size()}, 8, /*pad=*/8);
    REQUIRE(!xp.pattern.empty());
    REQUIRE(xp.insn_len == 7);
    // window starts at 0 (xref 8, pad 8) -> pattern_offset 0

    const auto toks = split_tokens(xp.pattern);
    REQUIRE(toks.size() >= 15);
    REQUIRE(toks[8] == "48");
    REQUIRE(toks[9] == "8d");
    REQUIRE(toks[10] == "05");
    REQUIRE(token_is_wildcard(toks[11]));
    REQUIRE(token_is_wildcard(toks[12]));
    REQUIRE(token_is_wildcard(toks[13]));
    REQUIRE(token_is_wildcard(toks[14]));
    REQUIRE(toks[15] == "48");
    REQUIRE(!token_is_wildcard(toks[0]));
}

static void test_mov_imm32_wildcards_imm() {
    std::vector<uint8_t> body(24, 0x90);
    body[0] = 0x56; // push rsi
    body[1] = 0x57;
    // +2: be 00 c9 87 00   mov esi, imm32  (luaopen_io style)
    body[2] = 0xbe;
    body[3] = 0x00;
    body[4] = 0xc9;
    body[5] = 0x87;
    body[6] = 0x00;
    body[7] = 0x48;
    body[8] = 0x89;
    body[9] = 0xf1;

    const auto xp = function_relocation::make_xref_wildcard_pattern(
            std::span<const uint8_t>{body.data(), body.size()}, 2, /*pad=*/2);
    REQUIRE(!xp.pattern.empty());
    REQUIRE(xp.insn_len == 5);
    REQUIRE(xp.pattern_offset == 0);
    const auto toks = split_tokens(xp.pattern);
    REQUIRE(toks[2] == "be");
    REQUIRE(token_is_wildcard(toks[3]));
    REQUIRE(token_is_wildcard(toks[4]));
    REQUIRE(token_is_wildcard(toks[5]));
    REQUIRE(token_is_wildcard(toks[6]));
    REQUIRE(toks[7] == "48");
}

static void test_mid_body_xref_negative_pattern_offset() {
    std::vector<uint8_t> body(64, 0x90);
    body[24] = 0x48;
    body[25] = 0x8d;
    body[26] = 0x0d;
    body[27] = 0xaa;
    body[28] = 0xbb;
    body[29] = 0xcc;
    body[30] = 0xdd;
    const auto xp = function_relocation::make_xref_wildcard_pattern(
            std::span<const uint8_t>{body.data(), body.size()}, 24, /*pad=*/8);
    REQUIRE(!xp.pattern.empty());
    REQUIRE(xp.insn_len == 7);
    // window_start = 24-8 = 16, pattern_offset = -16 (entry is byte 0)
    REQUIRE(xp.pattern_offset == -16);
    const auto toks = split_tokens(xp.pattern);
    REQUIRE(toks[8] == "48");
    REQUIRE(toks[9] == "8d");
    REQUIRE(toks[10] == "0d");
    REQUIRE(token_is_wildcard(toks[11]));
}

static void test_unknown_insn_empty() {
    std::vector<uint8_t> body(16, 0x90);
    const auto xp = function_relocation::make_xref_wildcard_pattern(
            std::span<const uint8_t>{body.data(), body.size()}, 4);
    REQUIRE(xp.pattern.empty());
    REQUIRE(xp.insn_len == 0);
}

static void test_early_return_does_not_hide_type_check() {
    // Identical success paths, different type constants in the failure path.
    uint8_t train_bytes[] = {0x85, 0xf6, 0x74, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 4, 0, 0, 0, 0xc3};
    uint8_t target_bytes[96]{};
    std::memcpy(target_bytes + 16, train_bytes, sizeof(train_bytes));
    std::memcpy(target_bytes + 64, train_bytes, sizeof(train_bytes));
    target_bytes[16 + 11] = 3;
    const auto train_base = reinterpret_cast<uintptr_t>(train_bytes);
    const auto target_base = reinterpret_cast<uintptr_t>(target_bytes);
    function_relocation::ModuleSections train{}, target{};
    train.text = train.details.range = {train_base, sizeof(train_bytes)};
    target.text = target.details.range = {target_base, sizeof(target_bytes)};
    train.function_table.add({train_base, train_base + sizeof(train_bytes)});
    for (const size_t offset: {size_t{16}, size_t{64}}) {
        target.function_table.add({target_base + offset, target_base + offset + sizeof(train_bytes)});
        auto &fn = target.functions.emplace_back();
        fn.address = target_base + offset;
        fn.size = sizeof(train_bytes);
        fn.module = &target;
    }
    auto &original = train.functions.emplace_back();
    original.address = train_base;
    original.size = sizeof(train_bytes);
    original.name = "typed_check";
    original.module = &train;
    REQUIRE(function_relocation::ensure_function_features(original));
    REQUIRE(original.size == sizeof(train_bytes));
    function_relocation::SignatureInfo signature{};
    REQUIRE(target.try_fix_func_address(original, &signature, target_base + 1) == target_base + 64);
}

int main() {
    gum_init_embedded();
    REQUIRE(function_relocation::init_ctx());
    function_relocation::ModuleSections sections;
    sections.sections[".plt.sec"] = {0x1000, 0x100};
    sections.sections[".got"] = {0x2000, 0x100};
    REQUIRE(sections.in_plt(0x1000) && !sections.in_plt(0x1100));
    REQUIRE(sections.in_got_plt(0x2000) && !sections.in_got_plt(0x2100));
    uint8_t repeated[] = {0xaa, 0xbb, 0xcc, 0xaa, 0xbb, 0xcc};
    function_relocation::MemorySignature scan{"aa bb cc", 0};
    scan.log = false;
    REQUIRE(scan.scan(reinterpret_cast<uintptr_t>(repeated), sizeof(repeated)) == 0);
    REQUIRE(scan.targets.size() == 2);
    REQUIRE(scan.scan(reinterpret_cast<uintptr_t>(repeated), 3) == reinterpret_cast<uintptr_t>(repeated));
    REQUIRE(scan.targets.size() == 1);
    const uint8_t movabs[] = {0x49, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8};
    const auto wide = function_relocation::make_xref_wildcard_pattern(movabs, 0, 0);
    REQUIRE(wide.insn_len == 10 && wide.pattern == "49 b8 ?? ?? ?? ?? ?? ?? ?? ??");
    const uint8_t lea32[] = {0x8d, 0x05, 0, 0, 0, 0};
    const auto compact = function_relocation::make_xref_wildcard_pattern(lea32, 0, 0);
    REQUIRE(compact.insn_len == 6 && compact.pattern == "8d 05 ?? ?? ?? ??");
    const uint8_t prefixed[] = {0x66, 0x48, 0x8d, 0x05, 0, 0, 0, 0};
    auto decoded = function_relocation::disasm::get_insn(const_cast<uint8_t *>(prefixed), sizeof(prefixed));
    REQUIRE(decoded && function_relocation::instruction_pattern(*decoded) == "66 48 8d 05 ?? ?? ?? ??");
    decoded.reset();
    test_rip_lea_wildcards_disp32();
    test_mov_imm32_wildcards_imm();
    test_mid_body_xref_negative_pattern_offset();
    test_unknown_insn_empty();
    test_early_return_does_not_hide_type_check();
    std::puts("test_xref_pattern: ok");
    function_relocation::deinit_ctx();
    gum_deinit_embedded();
    return 0;
}
