// test_net_stats_decode.cpp — synthetic x86-64 code windows for
// ds::net_stats::decode_net_stats (network.stats plugin, plan step 2).
//
// The windows are hand-assembled from the *shape* of the real function
// (Windows MS-x64 and Linux SysV variants) — no game bytes are copied. RIP
// displacements are computed against fixed offsets inside the same buffer, so
// the fake global slot and the 1/N float constant are resolvable at decode time.

#include "ClientPingDecode.hpp"

#include "ctx.hpp"

#include <frida-gum.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <string>
#include <vector>

#if defined(_WIN32)
// Optional real-binary probe (NET_STATS_PROBE_EXE=<path>): maps the exe image and
// decodes the anchor window from actual game bytes. Skips silently when unset.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>

namespace {

constexpr size_t kBufSize = 0x800;
constexpr size_t kFakeGlobalOff = 0x700; // fake rakPeer-root global slot
constexpr size_t kFloatOff = 0x7F0;      // float constant referenced by MOVSS

[[noreturn]] void fail(const char *what, int line) {
    std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", what, __FILE__, line);
    std::abort();
}

#define REQUIRE(cond)                          \
    do {                                       \
        if (!(cond)) fail(#cond, __LINE__);    \
    } while (0)

#define REQUIRE_EQ(a, b)                                                                     \
    do {                                                                                     \
        const auto va = (a);                                                                 \
        const auto vb = (b);                                                                 \
        if (!(va == vb)) {                                                                   \
            std::fprintf(stderr, "REQUIRE_EQ failed: %s == %s (%s:%d): %lld vs %lld\n", #a,  \
                         #b, __FILE__, __LINE__, (long long)va, (long long)vb);              \
            std::abort();                                                                    \
        }                                                                                    \
    } while (0)

struct Code {
    std::vector<uint8_t> bytes;

    Code() { bytes.reserve(kBufSize); }

    size_t pos() const { return bytes.size(); }

    void put(std::initializer_list<int> b) {
        for (int v : b) bytes.push_back(static_cast<uint8_t>(v));
    }

    void put32(int32_t v) {
        const auto *p = reinterpret_cast<const uint8_t *>(&v);
        bytes.insert(bytes.end(), p, p + 4);
    }

    // Emit the disp32 of a RIP-relative operand targeting `target_off` inside
    // this same buffer (disp = target - end_of_instruction).
    void put_rip_disp(size_t target_off) {
        const int64_t end = static_cast<int64_t>(bytes.size()) + 4;
        put32(static_cast<int32_t>(static_cast<int64_t>(target_off) - end));
    }

    void put_float(float v) {
        if (bytes.size() < kFloatOff + 4) bytes.resize(kFloatOff + 4, 0x90);
        std::memcpy(bytes.data() + kFloatOff, &v, 4);
    }

    // Pad the window and materialize the fake rakPeer-root global slot.
    void pad_to_window() {
        if (bytes.size() < kBufSize) bytes.resize(kBufSize, 0x90);
        for (size_t i = 0; i < 8; ++i) bytes[kFakeGlobalOff + i] = 0;
    }
};

struct BuildOpts {
    uint32_t ring_n = 60;
    float float_const = 1.0f / 60.0f;
    bool clamp_second = true;          // second clamp constant present
    bool arg1_lea = true;              // 2nd call arg defined by LEA [rsp+disp]
    bool guid_word_disp_ok = true;     // word pair at qword+8 (else qword+0x10)
    bool extra_listing_candidate = false;
    bool slot_def = true;              // Linux register form: MOV R,[vt+slot]
    bool slot_def_twice = false;       // Linux register form: two definitions
    bool window_bleed = false;         // conflicting candidate after RET (next function)
};

// ---------------------------------------------------------------------------
// Windows MS-x64 shape: this=RCX->RBX, call [R11+0x158], arg1=RDX,
// listing arg0=RCX, chain [rip+global] -> [rax+0x2b0] -> vtable.
// ---------------------------------------------------------------------------
Code build_windows(const BuildOpts &o) {
    Code c;
    c.put({0x48, 0x8B, 0xD9});                                     // mov rbx, rcx
    c.put({0x48, 0x8B, 0x05}); c.put_rip_disp(kFakeGlobalOff);      // mov rax, [rip+global]
    c.put({0x48, 0x8B, 0xB0, 0xB0, 0x02, 0x00, 0x00});              // mov rsi, [rax+0x2b0]
    c.put({0x48, 0x85, 0xF6});                                      // test rsi, rsi
    // GUID pair loads.
    c.put({0x4C, 0x8B, 0x9B, 0xA0, 0x01, 0x00, 0x00});              // mov r11, [rbx+0x1a0]
    if (o.guid_word_disp_ok) {
        c.put({0x0F, 0xB7, 0x83, 0xA8, 0x01, 0x00, 0x00});          // movzx eax, word [rbx+0x1a8]
    } else {
        c.put({0x0F, 0xB7, 0x83, 0xB0, 0x01, 0x00, 0x00});          // movzx eax, word [rbx+0x1b0]
    }
    c.put({0x4C, 0x89, 0x5C, 0x24, 0x40});                          // mov [rsp+0x40], r11
    c.put({0x66, 0x89, 0x44, 0x24, 0x48});                          // mov [rsp+0x48], ax
    // vtable + slot call.
    c.put({0x4C, 0x8B, 0x1E});                                      // mov r11, [rsi]
    if (o.arg1_lea) {
        c.put({0x48, 0x8D, 0x54, 0x24, 0x40});                      // lea rdx, [rsp+0x40]
    } else {
        c.put({0x48, 0x89, 0xF2});                                  // mov rdx, rsi
    }
    c.put({0x48, 0x8B, 0xCE});                                      // mov rcx, rsi
    c.put({0x41, 0xFF, 0x93, 0x58, 0x01, 0x00, 0x00});              // call [r11+0x158]
    // Clamp compare.
    c.put({0x85, 0xC0});                                            // test eax, eax
    c.put({0xBF, 0x9F, 0x86, 0x01, 0x00});                          // mov edi, 0x1869f
    c.put({0x3B, 0xC7});                                            // cmp eax, edi
    if (o.clamp_second) {
        c.put({0xBF, 0x9F, 0x86, 0x01, 0x00});                      // mov edi, 0x1869f
    }
    // Listing pointer feeding a direct call's 1st argument.
    c.put({0x48, 0x8D, 0x8B, 0xC0, 0x01, 0x00, 0x00});              // lea rcx, [rbx+0x1c0]
    c.put({0xE8, 0x00, 0x00, 0x00, 0x00});                          // call rel32
    if (o.extra_listing_candidate) {
        c.put({0x48, 0x8D, 0x8B, 0xD0, 0x01, 0x00, 0x00});          // lea rcx, [rbx+0x1d0]
        c.put({0xE8, 0x00, 0x00, 0x00, 0x00});                      // call rel32
    }
    // Ring trio.
    c.put({0x48, 0x8B, 0x93, 0x30, 0x03, 0x00, 0x00});              // mov rdx, [rbx+0x330]
    c.put({0x48, 0x8B, 0x8B, 0x38, 0x03, 0x00, 0x00});              // mov rcx, [rbx+0x338]
    c.put({0x0F, 0xB6, 0x83, 0x40, 0x03, 0x00, 0x00});              // movzx eax, byte [rbx+0x340]
    c.put({0x88, 0x83, 0x40, 0x03, 0x00, 0x00});                    // mov [rbx+0x340], al
    c.put({0x6B, 0xFF, static_cast<int>(o.ring_n)});                // imul edi, edi, N
    c.put({0x89, 0x39});                                            // mov [rcx], edi
    c.put({0x01, 0x01});                                            // add [rcx], eax
    c.put({0x42, 0x89, 0x3C, 0xC2});                                // mov [rdx+r8*8], edi
    c.put({0x66, 0x44, 0x89, 0x4C, 0xC2, 0x04});                    // mov [rdx+r8*8+4], r9w
    c.put({0x44, 0x88, 0x4C, 0xC2, 0x06});                          // mov [rdx+r8*8+6], r9b
    c.put({0xF3, 0x0F, 0x10, 0x05}); c.put_rip_disp(kFloatOff);     // movss xmm0, [rip+flt]
    c.put({0xC3});                                                  // ret
    if (o.window_bleed) {
        // The next function in .text uses the same registers and would fool a
        // window-only scan; reachability must prune it.
        c.put({0x48, 0x8D, 0x8B, 0x08, 0x00, 0x00, 0x00});          // lea rcx, [rbx+8]
        c.put({0xE8, 0x00, 0x00, 0x00, 0x00});                      // call rel32
    }
    c.put_float(o.float_const);
    c.pad_to_window();
    return c;
}

// ---------------------------------------------------------------------------
// Linux SysV shape: this=RDI->RBX, MOV R13,[RAX+0x160]; CALL R13, arg1=RSI,
// listing arg0=RDI, chain [rip+global] -> [rax+0x1a0] -> [rbp] -> vtable.
// ---------------------------------------------------------------------------
Code build_linux(const BuildOpts &o) {
    Code c;
    c.put({0x48, 0x89, 0xFB});                                      // mov rbx, rdi
    c.put({0x48, 0x8B, 0x05}); c.put_rip_disp(kFakeGlobalOff);      // mov rax, [rip+global]
    c.put({0x48, 0x8B, 0xA8, 0xA0, 0x01, 0x00, 0x00});              // mov rbp, [rax+0x1a0]
    c.put({0x48, 0x85, 0xED});                                      // test rbp, rbp
    // GUID pair loads.
    c.put({0x4C, 0x8B, 0x9B, 0xA0, 0x01, 0x00, 0x00});              // mov r11, [rbx+0x1a0]
    if (o.guid_word_disp_ok) {
        c.put({0x0F, 0xB7, 0x83, 0xA8, 0x01, 0x00, 0x00});          // movzx eax, word [rbx+0x1a8]
    } else {
        c.put({0x0F, 0xB7, 0x83, 0xB0, 0x01, 0x00, 0x00});          // movzx eax, word [rbx+0x1b0]
    }
    c.put({0x4C, 0x89, 0x9C, 0x24, 0x10, 0x01, 0x00, 0x00});        // mov [rsp+0x110], r11
    c.put({0x66, 0x89, 0x84, 0x24, 0x18, 0x01, 0x00, 0x00});        // mov [rsp+0x118], ax
    // vtable + slot call.
    c.put({0x48, 0x8B, 0x45, 0x00});                                // mov rax, [rbp]
    if (o.slot_def) {
        c.put({0x4C, 0x8B, 0xA8, 0x60, 0x01, 0x00, 0x00});          // mov r13, [rax+0x160]
    }
    if (o.slot_def_twice) {
        c.put({0x4C, 0x8B, 0xA8, 0x60, 0x01, 0x00, 0x00});          // second def (ambiguous)
    }
    if (o.arg1_lea) {
        c.put({0x48, 0x8D, 0xB4, 0x24, 0x10, 0x01, 0x00, 0x00});    // lea rsi, [rsp+0x110]
    } else {
        c.put({0x48, 0x89, 0xEE});                                  // mov rsi, rbp
    }
    c.put({0x48, 0x89, 0xEF});                                      // mov rdi, rbp
    c.put({0x41, 0xFF, 0xD5});                                      // call r13
    // Clamp compare.
    c.put({0x41, 0xBD, 0x9F, 0x86, 0x01, 0x00});                    // mov r13d, 0x1869f
    c.put({0x3D, 0x9E, 0x86, 0x01, 0x00});                          // cmp eax, 0x1869e
    if (o.clamp_second) {
        c.put({0x41, 0xBD, 0x9F, 0x86, 0x01, 0x00});                // mov r13d, 0x1869f
    }
    // Listing pointer feeding a direct call's 1st argument.
    c.put({0x48, 0x8D, 0xBB, 0xC0, 0x01, 0x00, 0x00});              // lea rdi, [rbx+0x1c0]
    c.put({0xE8, 0x00, 0x00, 0x00, 0x00});                          // call rel32
    if (o.extra_listing_candidate) {
        c.put({0x48, 0x8D, 0xBB, 0xD0, 0x01, 0x00, 0x00});          // lea rdi, [rbx+0x1d0]
        c.put({0xE8, 0x00, 0x00, 0x00, 0x00});                      // call rel32
    }
    // Ring trio (same field layout as Windows).
    c.put({0x48, 0x8B, 0x93, 0x30, 0x03, 0x00, 0x00});              // mov rdx, [rbx+0x330]
    c.put({0x48, 0x8B, 0x8B, 0x38, 0x03, 0x00, 0x00});              // mov rcx, [rbx+0x338]
    c.put({0x0F, 0xB6, 0x83, 0x40, 0x03, 0x00, 0x00});              // movzx eax, byte [rbx+0x340]
    c.put({0x88, 0x83, 0x40, 0x03, 0x00, 0x00});                    // mov [rbx+0x340], al
    c.put({0x6B, 0xFF, static_cast<int>(o.ring_n)});                // imul edi, edi, N
    c.put({0x89, 0x39});                                            // mov [rcx], edi
    c.put({0x01, 0x01});                                            // add [rcx], eax
    c.put({0x42, 0x89, 0x3C, 0xC2});                                // mov [rdx+r8*8], edi
    c.put({0x66, 0x44, 0x89, 0x4C, 0xC2, 0x04});                    // mov [rdx+r8*8+4], r9w
    c.put({0x44, 0x88, 0x4C, 0xC2, 0x06});                          // mov [rdx+r8*8+6], r9b
    c.put({0xF3, 0x0F, 0x10, 0x05}); c.put_rip_disp(kFloatOff);     // movss xmm0, [rip+flt]
    c.put({0xC3});                                                  // ret
    if (o.window_bleed) {
        c.put({0x48, 0x8D, 0xBB, 0x08, 0x00, 0x00, 0x00});          // lea rdi, [rbx+8]
        c.put({0xE8, 0x00, 0x00, 0x00, 0x00});                      // call rel32
    }
    c.put_float(o.float_const);
    c.pad_to_window();
    return c;
}

std::expected<ds::net_stats::NetStatsLayout, std::string> decode(Code &c,
                                                                ds::net_stats::PingCallConv conv) {
    return ds::net_stats::decode_net_stats(reinterpret_cast<uintptr_t>(c.bytes.data()), conv);
}

using ds::net_stats::PingCallConv;

void require_layout(const std::expected<ds::net_stats::NetStatsLayout, std::string> &layout,
                    const char *what) {
    if (!layout) {
        std::fprintf(stderr, "decode failed for %s: %s\n", what, layout.error().c_str());
    }
    REQUIRE(layout.has_value());
}

void expect_hard_failure(Code &c, PingCallConv conv, const char *needle) {
    const auto layout = decode(c, conv);
    if (layout) {
        std::fprintf(stderr, "expected failure containing '%s', got a layout\n", needle);
        std::abort();
    }
    if (layout.error().find(needle) == std::string::npos) {
        std::fprintf(stderr, "expected failure reason containing '%s', got '%s'\n", needle,
                     layout.error().c_str());
        std::abort();
    }
}

void check_windows_shape() {
    BuildOpts o;
    Code c = build_windows(o);
    const auto layout = decode(c, PingCallConv::MsX64);
    require_layout(layout, "windows shape");
    REQUIRE_EQ(layout->listingOff, 0x1C0u);
    REQUIRE_EQ(layout->ringPtrOff, 0x330u);
    REQUIRE_EQ(layout->indexOff, 0x340u);
    REQUIRE_EQ(layout->ringWindow, 60u);
    REQUIRE_EQ(layout->ringStride, 8u);
}

void check_linux_shape() {
    BuildOpts o;
    Code c = build_linux(o);
    const auto layout = decode(c, PingCallConv::SysV);
    require_layout(layout, "linux shape");
    REQUIRE_EQ(layout->listingOff, 0x1C0u);
    REQUIRE_EQ(layout->ringWindow, 60u);
    REQUIRE_EQ(layout->ringStride, 8u);
}

// Slot count is derived, not hardcoded: N=30 must come back as 30.
void check_derived_slot_count() {
    for (bool win : {true, false}) {
        BuildOpts o;
        o.ring_n = 30;
        o.float_const = 1.0f / 30.0f;
        Code c = win ? build_windows(o) : build_linux(o);
        const auto layout = decode(c, win ? PingCallConv::MsX64 : PingCallConv::SysV);
        REQUIRE(layout.has_value());
        REQUIRE_EQ(layout->ringWindow, 30u);
    }
}

// Float cross-check mismatch: the 1/N divisor disagrees with the derived slot
// count, so the ring cannot be trusted and the decode fails closed.
void check_ring_float_mismatch_fails() {
    BuildOpts o;
    o.ring_n = 30;
    o.float_const = 1.0f / 60.0f; // stale divisor
    Code c = build_windows(o);
    expect_hard_failure(c, PingCallConv::MsX64, "ring layout");
}

// Regression for the real-binary layout: the next function in .text uses the
// same registers (its own [rbx+disp] argument setups). Those bytes sit inside
// the 0x800 window but are unreachable — they must not create ambiguity.
void check_window_bleed_is_pruned() {
    for (bool win : {true, false}) {
        BuildOpts o;
        o.window_bleed = true;
        Code c = win ? build_windows(o) : build_linux(o);
        const auto conv = win ? PingCallConv::MsX64 : PingCallConv::SysV;
        const auto layout = decode(c, conv);
        require_layout(layout, win ? "windows shape (bleed)" : "linux shape (bleed)");
        REQUIRE_EQ(layout->listingOff, 0x1C0u);
        REQUIRE_EQ(layout->ringWindow, 60u);
    }
}

void check_negative_cases() {
    { // clamp constant family only once
        BuildOpts o;
        o.clamp_second = false;
        Code c = build_windows(o);
        expect_hard_failure(c, PingCallConv::MsX64, "clamp constants");
    }
    { // GUID word pair does not sit at qword+8
        BuildOpts o;
        o.guid_word_disp_ok = false;
        Code c = build_windows(o);
        expect_hard_failure(c, PingCallConv::MsX64, "guid");
    }
    { // listing candidates disagree
        BuildOpts o;
        o.extra_listing_candidate = true;
        Code c = build_windows(o);
        expect_hard_failure(c, PingCallConv::MsX64, "listing candidates");
    }
}

} // namespace

#if defined(_WIN32)
namespace {

// Optional real-binary probe: NET_STATS_PROBE_EXE=<path to a DST exe> maps the
// PE image at its preferred base, scans .text for the anchor signature and runs
// the decoder on the actual game bytes. Prints the decoded layout; asserts the
// shape invariants. Unset env var => silent skip.
constexpr const char *kProbePattern =
    "4C 8B DC 53 56 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 8B D9 48 8B B0 B0 02 00 00 48 85 F6";

bool parse_pattern(const char *pattern, std::vector<int> *bytes) {
    int hi = -1;
    for (const char *p = pattern; *p != '\0';) {
        if (p[0] == '?') {
            bytes->push_back(-1);
            p += (p[1] == '?') ? 2 : 1;
        } else if (std::isxdigit(static_cast<unsigned char>(p[0])) && std::isxdigit(static_cast<unsigned char>(p[1]))) {
            const auto hex = [](char c) { return (c <= '9') ? c - '0' : (c | 0x20) - 'a' + 10; };
            bytes->push_back(hex(p[0]) * 16 + hex(p[1]));
            p += 2;
        } else {
            ++p;
        }
    }
    return !bytes->empty();
}

uintptr_t scan_pattern(const uint8_t *data, size_t size, const std::vector<int> &pattern) {
    for (size_t i = 0; i + pattern.size() <= size; ++i) {
        bool ok = true;
        for (size_t k = 0; k < pattern.size() && ok; ++k) {
            ok = pattern[k] < 0 || data[i + k] == static_cast<uint8_t>(pattern[k]);
        }
        if (ok) {
            return reinterpret_cast<uintptr_t>(data + i);
        }
    }
    return 0;
}

void run_real_probe() {
    const char *path = std::getenv("NET_STATS_PROBE_EXE");
    if (path == nullptr || *path == '\0') {
        return;
    }
    std::fprintf(stderr, "probe: %s\n", path);

    FILE *f = std::fopen(path, "rb");
    if (!f) {
        std::fprintf(stderr, "probe: SKIP (cannot open)\n");
        return;
    }
    std::fseek(f, 0, SEEK_END);
    const long file_size = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> file(static_cast<size_t>(file_size));
    const size_t got = std::fread(file.data(), 1, file.size(), f);
    std::fclose(f);
    REQUIRE(got == file.size());

    REQUIRE(file.size() > 0x40);
    const uint32_t pe_off = *reinterpret_cast<const uint32_t *>(file.data() + 0x3C);
    REQUIRE(std::memcmp(file.data() + pe_off, "PE\0\0", 4) == 0);
    const auto *coff = file.data() + pe_off + 4;
    const uint16_t section_count = *reinterpret_cast<const uint16_t *>(coff + 2);
    const uint16_t opt_size = *reinterpret_cast<const uint16_t *>(coff + 16);
    const auto *opt = coff + 20;
    const uint64_t image_base = *reinterpret_cast<const uint64_t *>(opt + 24);
    const uint32_t image_size = *reinterpret_cast<const uint32_t *>(opt + 56);

    void *mapped = VirtualAlloc(reinterpret_cast<void *>(image_base), image_size,
                                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!mapped) {
        std::fprintf(stderr, "probe: SKIP (image base 0x%llx unavailable)\n",
                    static_cast<unsigned long long>(image_base));
        return;
    }
    std::memcpy(mapped, file.data(), std::min<size_t>(file.size(), opt_size + 20 + 4));

    const auto *sh = opt + opt_size;
    uintptr_t text_va = 0;
    size_t text_size = 0;
    for (uint16_t i = 0; i < section_count; ++i) {
        const auto *s = sh + i * 40;
        const uint32_t vsize = *reinterpret_cast<const uint32_t *>(s + 8);
        const uint32_t vaddr = *reinterpret_cast<const uint32_t *>(s + 12);
        const uint32_t raw_size = *reinterpret_cast<const uint32_t *>(s + 16);
        const uint32_t raw_ptr = *reinterpret_cast<const uint32_t *>(s + 20);
        if (raw_ptr + raw_size > file.size()) {
            continue;
        }
        std::memcpy(reinterpret_cast<uint8_t *>(image_base + vaddr), file.data() + raw_ptr,
                    std::min<size_t>(vsize, raw_size));
        if (std::memcmp(s, ".text", 5) == 0) {
            text_va = image_base + vaddr;
            text_size = vsize;
        }
    }
    REQUIRE(text_va != 0);

    std::vector<int> pattern;
    REQUIRE(parse_pattern(kProbePattern, &pattern));
    const uintptr_t anchor = scan_pattern(reinterpret_cast<const uint8_t *>(text_va), text_size, pattern);
    REQUIRE(anchor != 0);

    const auto layout = ds::net_stats::decode_net_stats(anchor, ds::net_stats::PingCallConv::Host);
    if (!layout) {
        std::fprintf(stderr, "probe: decode FAILED: %s\n", layout.error().c_str());
        std::abort();
    }
    std::fprintf(stderr, "probe: anchor=0x%llx listing=+0x%x ring=+0x%x/+0x%x n=%u stride=%u\n",
                static_cast<unsigned long long>(anchor), layout->listingOff, layout->ringPtrOff,
                layout->indexOff, layout->ringWindow, layout->ringStride);
    // Shape invariants that must hold for any game build with this pattern.
    REQUIRE(layout->listingOff > 0);
    REQUIRE(layout->ringStride >= 2);
    REQUIRE(layout->ringWindow >= 2 && layout->ringWindow <= 4096);
    std::fprintf(stderr, "probe: OK\n");
}

} // namespace
#endif

int main() {
    gum_init_embedded();
    if (!function_relocation::init_ctx()) {
        std::fprintf(stderr, "function_relocation::init_ctx failed\n");
        return 1;
    }

    check_windows_shape();
    check_linux_shape();
    check_derived_slot_count();
    check_ring_float_mismatch_fails();
    check_window_bleed_is_pruned();
    check_negative_cases();
#if defined(_WIN32)
    run_real_probe();
#endif

    function_relocation::deinit_ctx();
    std::printf("net_stats_decode: all cases passed\n");
    return 0;
}
