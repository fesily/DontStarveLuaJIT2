// Caller-graph seed: intersect unclaimed CALL targets across resolved
// callers. lua_isnumber is the unique common callee of luaL_checknumber
// and luaL_checkinteger even when Nucleus merged it into a parent span.

#include "GraphSeed.hpp"
#include "ModuleSections.hpp"
#include "ctx.hpp"
#include <frida-gum.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_set>
#include <vector>
#ifdef __linux__
#include <sys/mman.h>
#include <unistd.h>
#endif

#define REQUIRE(cond)                                                                          \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__);  \
            std::abort();                                                                      \
        }                                                                                      \
    } while (0)

static void test_rel32_collects_call_target() {
    unsigned char buf[16] = {};
    // e8 06 00 00 00  nop...  → call to buf+5+6 = buf+11
    buf[0] = 0xe8;
    buf[1] = 0x06;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00;
    const auto start = reinterpret_cast<uint64_t>(buf);
    const auto tgts = function_relocation::collect_rel32_call_targets(start, sizeof(buf));
    REQUIRE(tgts.size() == 1);
    REQUIRE(tgts[0] == start + 11);
}

static void test_intersect_unique_common_callee() {
    // checknumber callees: tonumber, isnumber, argerror
    // checkinteger callees: tointeger, isnumber, argerror
    // claimed: tonumber, tointeger, argerror
    // intersection of unclaimed = {isnumber}
    const uint64_t tonumber = 0x1000;
    const uint64_t isnumber = 0x1100;
    const uint64_t tointeger = 0x1200;
    const uint64_t argerror = 0x1300;
    std::unordered_set<uint64_t> claimed{tonumber, tointeger, argerror};

    std::unordered_set<uint64_t> checknumber{tonumber, isnumber, argerror};
    std::unordered_set<uint64_t> checkinteger{tointeger, isnumber, argerror};
    function_relocation::erase_claimed(checknumber, claimed);
    function_relocation::erase_claimed(checkinteger, claimed);

    const auto hit = function_relocation::intersect_callee_sets({checknumber, checkinteger});
    REQUIRE(hit.size() == 1);
    REQUIRE(hit[0] == isnumber);
}

static void test_intersect_empty_when_inlined() {
    std::unordered_set<uint64_t> a{0x1, 0x2};
    std::unordered_set<uint64_t> b{0x3, 0x4};
    const auto hit = function_relocation::intersect_callee_sets({a, b});
    REQUIRE(hit.empty());
}

static void test_intersect_two_commons_need_fingerprint() {
    std::unordered_set<uint64_t> a{0x10, 0x20, 0x30};
    std::unordered_set<uint64_t> b{0x20, 0x30, 0x40};
    auto hit = function_relocation::intersect_callee_sets({a, b});
    std::sort(hit.begin(), hit.end());
    REQUIRE(hit.size() == 2);
    REQUIRE(hit[0] == 0x20);
    REQUIRE(hit[1] == 0x30);
}

static void test_reloc_free_prefix_stops_at_rip_lea() {
    unsigned char loadbuffer[] = {
            0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x34, 0x24,
            0x48, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00,
    };
    REQUIRE(function_relocation::reloc_free_prefix_len(loadbuffer, sizeof(loadbuffer)) == 8);
}

static void test_first_rel32_callee_picks_loadbuffer() {
    unsigned char loadbuffer[64];
    std::memset(loadbuffer, 0x90, sizeof(loadbuffer));
    unsigned char loadstring[64];
    std::memset(loadstring, 0x90, sizeof(loadstring));
    loadbuffer[21] = 0xe8;
    const auto lb = reinterpret_cast<uint64_t>(loadbuffer);
    const int32_t rel = 0x10;
    std::memcpy(loadbuffer + 22, &rel, 4);
    const uint64_t lua_load = lb + 21 + 5 + rel;
    loadstring[0] = 0x55;
    loadstring[5] = 0xe8; // first call elsewhere
    const int32_t rel2 = 0x20;
    std::memcpy(loadstring + 6, &rel2, 4);
    const auto hit = function_relocation::filter_by_first_rel32_callee(
            {lb, reinterpret_cast<uint64_t>(loadstring)}, lua_load);
    REQUIRE(hit.size() == 1);
    REQUIRE(hit[0] == lb);
}

static void test_filter_prefix_picks_loadbuffer_shape() {
    unsigned char a[32] = {0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x34, 0x24, 0x90};
    unsigned char b[32] = {0x55, 0x48, 0x89, 0xfd, 0x48, 0x89, 0xf7, 0x53, 0x90};
    const auto hit = function_relocation::filter_by_reloc_free_prefix(
            {reinterpret_cast<uint64_t>(a), reinterpret_cast<uint64_t>(b)}, a, 8);
    REQUIRE(hit.size() == 1);
    REQUIRE(hit[0] == reinterpret_cast<uint64_t>(a));
}

struct PltFixture {
    std::array<uint8_t, 512> bytes;
    function_relocation::ModuleSections module{};

    uint64_t address(size_t offset) const { return reinterpret_cast<uint64_t>(bytes.data() + offset); }

    void branch(size_t offset, size_t target, uint8_t opcode = 0xe8) {
        bytes[offset] = opcode;
        const int32_t displacement = static_cast<int32_t>(target) - static_cast<int32_t>(offset + 5);
        std::memcpy(bytes.data() + offset + 1, &displacement, sizeof(displacement));
    }

    void slot(size_t offset, uint64_t target) {
        std::memcpy(bytes.data() + offset, &target, sizeof(target));
    }

    PltFixture() {
        bytes.fill(0x90);
        branch(0, 256);
        branch(16, 288, 0xe9);
        branch(32, 160);
        branch(64, 128);
        bytes[128] = bytes[160] = 0xc3;
        // Plain PLT and CET/NOP-prefixed PLT entries use distinct GOT slots
        // pointing at the same exact callee, inside a coarser FunctionTable span.
        bytes[256] = 0xff;
        bytes[257] = 0x25;
        const int32_t plain_disp = 384 - 262;
        std::memcpy(bytes.data() + 258, &plain_disp, sizeof(plain_disp));
        const uint8_t prefixed[] = {0xf3, 0x0f, 0x1e, 0xfa, 0x90, 0x66, 0x90, 0xff, 0x25};
        std::memcpy(bytes.data() + 288, prefixed, sizeof(prefixed));
        const int32_t cet_disp = 392 - 301;
        std::memcpy(bytes.data() + 297, &cet_disp, sizeof(cet_disp));
        slot(384, address(128));
        slot(392, address(128));
        module.details.range = {address(0), bytes.size()};
        module.text = {address(0), 256};
        module.plt = {address(256), 96};
        module.got_plt = {address(384), 16};
        module.function_table.add({address(112), address(144)});
    }
};

static void test_plt_call_targets_and_consumers() {
    PltFixture fixture;
    auto &module = fixture.module;
    const auto callee = fixture.address(128);
    const auto raw = function_relocation::collect_rel32_call_targets(fixture.address(0), 8);
    const auto first = function_relocation::collect_rel32_call_targets(module, fixture.address(0), 8);
    const auto second = function_relocation::collect_rel32_call_targets(module, fixture.address(16), 8);
    REQUIRE(raw == std::vector<uint64_t>{fixture.address(256)});
    REQUIRE(first == std::vector<uint64_t>{callee});
    REQUIRE(second == first);
    REQUIRE(module.function_table.containing(callee) != callee);
    REQUIRE(function_relocation::collect_rel32_call_targets(module, fixture.address(64), 8) == first);
    REQUIRE(function_relocation::body_calls_entry(module, fixture.address(0), 8, callee));
    REQUIRE(function_relocation::body_calls_entry(module, fixture.address(16), 8, callee));
    REQUIRE(!function_relocation::body_calls_entry(module, fixture.address(0), 8, fixture.address(160)));

    const auto common = function_relocation::intersect_callee_sets({{first.begin(), first.end()}, {second.begin(), second.end()}});
    REQUIRE(common == first);
    std::unordered_set<uint64_t> unclaimed(first.begin(), first.end());
    function_relocation::erase_claimed(unclaimed, {callee});
    REQUIRE(unclaimed.empty());
    const auto filtered = function_relocation::filter_by_first_rel32_callee(
            module, {fixture.address(0), fixture.address(32)}, callee, 8);
    REQUIRE(filtered == std::vector<uint64_t>{fixture.address(0)});

    auto &fn = module.functions.emplace_back(function_relocation::Function{fixture.address(0), 8});
    fn.module = &module;
    REQUIRE(function_relocation::ensure_function_features(fn));
    std::vector<uint64_t> feature_targets;
    for (const auto block: fn.blocks) {
        const auto &calls = module.address_blocks.at(block)->call_functions;
        feature_targets.insert(feature_targets.end(), calls.begin(), calls.end());
    }
    REQUIRE(feature_targets == first);

    // Also resolve section names used by newer linkers.
    module.plt = {};
    module.got_plt = {};
    module.sections[".plt.sec"] = {fixture.address(256), 96};
    module.sections[".got"] = {fixture.address(384), 16};
    REQUIRE(function_relocation::collect_rel32_call_targets(module, fixture.address(16), 8) == first);
    module.sections.erase(".plt.sec");
    module.sections[".plt.got"] = {fixture.address(256), 96};
    REQUIRE(function_relocation::collect_rel32_call_targets(module, fixture.address(0), 8) == first);
}

static void test_unbound_and_chained_plt_targets() {
    PltFixture fixture;
    auto &module = fixture.module;
    const auto raw = function_relocation::collect_rel32_call_targets(fixture.address(0), 8);
    fixture.slot(384, 0);
    REQUIRE(function_relocation::collect_rel32_call_targets(module, fixture.address(0), 8) == raw);
    module.function_table.add({fixture.address(128), fixture.address(352)});
    REQUIRE(!function_relocation::body_calls_entry(module, fixture.address(0), 8, fixture.address(128)));
    // An unresolved first call must retain its position for first-callee filters.
    fixture.branch(5, 128);
    const auto ordered = function_relocation::collect_rel32_call_targets(module, fixture.address(0), 10);
    REQUIRE((ordered == std::vector<uint64_t>{fixture.address(256), fixture.address(128)}));
    const auto filtered = function_relocation::filter_by_first_rel32_callee(
            module, {fixture.address(0), fixture.address(64)}, fixture.address(128), 10);
    REQUIRE(filtered == std::vector<uint64_t>{fixture.address(64)});
#ifndef _WIN32
    fixture.slot(384, fixture.address(288));
    REQUIRE(function_relocation::collect_rel32_call_targets(module, fixture.address(16), 8) == std::vector<uint64_t>{fixture.address(128)});
    REQUIRE(function_relocation::collect_rel32_call_targets(module, fixture.address(0), 5) == std::vector<uint64_t>{fixture.address(128)});
    fixture.slot(392, fixture.address(256));
    REQUIRE(function_relocation::collect_rel32_call_targets(module, fixture.address(0), 5) == raw);
    fixture.slot(384, fixture.address(262)); // lazy slot points to PLT's following instruction
    fixture.bytes[262] = 0x68;
    REQUIRE(function_relocation::collect_rel32_call_targets(module, fixture.address(0), 5) == raw);
#endif
}

#ifdef __linux__
static void test_unreadable_got_slot() {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *bytes = static_cast<uint8_t *>(mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(bytes != MAP_FAILED);
    std::memset(bytes, 0x90, page);
    bytes[0] = 0xe8;
    const int32_t call_disp = 32 - 5;
    std::memcpy(bytes + 1, &call_disp, sizeof(call_disp));
    bytes[32] = 0xff;
    bytes[33] = 0x25;
    const int32_t got_disp = static_cast<int32_t>(page - 38);
    std::memcpy(bytes + 34, &got_disp, sizeof(got_disp));
    REQUIRE(mprotect(bytes + page, page, PROT_NONE) == 0);
    function_relocation::ModuleSections module{};
    const auto address = reinterpret_cast<uint64_t>(bytes);
    module.details.range = {address, page * 2};
    module.plt = {address + 32, 16};
    module.got_plt = {address + page, page};
    REQUIRE(function_relocation::collect_rel32_call_targets(module, address, 5) == std::vector<uint64_t>{address + 32});
    // The thunk decoder must also handle a partially readable code prefix.
    bytes[page - 1] = 0xff;
    module.plt = {address + page - 1, 1};
    const int32_t end_disp = static_cast<int32_t>(page - 1 - 5);
    std::memcpy(bytes + 1, &end_disp, sizeof(end_disp));
    REQUIRE(function_relocation::collect_rel32_call_targets(module, address, 5) == std::vector<uint64_t>{address + page - 1});
    REQUIRE(munmap(bytes, page * 2) == 0);
}
#endif

int main() {
    gum_init_embedded();
    REQUIRE(function_relocation::init_ctx());
    // E8/E9 inside movabs's immediate are data, not direct calls.
    unsigned char embedded[] = {0x48, 0xb8, 0xe8, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3};
    REQUIRE(function_relocation::collect_rel32_call_targets(reinterpret_cast<uint64_t>(embedded), sizeof(embedded)).empty());
    unsigned char fake_reloc[] = {0x48, 0x81, 0xc1, 0xe8, 0xe9, 0x00, 0x00, 0xc3};
    REQUIRE(function_relocation::reloc_free_prefix_len(fake_reloc, sizeof(fake_reloc)) == sizeof(fake_reloc));
    test_rel32_collects_call_target();
    test_intersect_unique_common_callee();
    test_intersect_empty_when_inlined();
    test_intersect_two_commons_need_fingerprint();
    test_reloc_free_prefix_stops_at_rip_lea();
    test_filter_prefix_picks_loadbuffer_shape();
    test_first_rel32_callee_picks_loadbuffer();
    test_plt_call_targets_and_consumers();
    test_unbound_and_chained_plt_targets();
#ifdef __linux__
    test_unreadable_got_slot();
#endif
    std::puts("test_graph_seed: ok");
    function_relocation::deinit_ctx();
    gum_deinit_embedded();
    return 0;
}
