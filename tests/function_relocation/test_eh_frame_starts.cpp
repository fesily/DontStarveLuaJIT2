// Linux entry discovery: ELF `.eh_frame` FDE extents are the function-entry
// authority. The expectations below come from an independent libdwarf read of
// the same file, never from the discovery code under test.

#include "FunctionRanges.hpp"
#include "MemorySignature.hpp"
#include "GraphSeed.hpp"
#include "ModuleSections.hpp"
#include "support/fr_context_env.hpp"

#include <doctest/doctest.h>

#include <dlfcn.h>

#include <cstdint>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <dwarf.h>
#include <elf.h>
#include <fcntl.h>
#include <libdwarf.h>
#include <unistd.h>

using function_relocation::ModuleSections;

// Two single-instruction leaves placed side by side in this translation unit:
// the first is wrapped in CFI (so it owns an FDE), the second deliberately is
// not (so it must not become an entry of the FDE-derived table).
extern "C" void ds_test_fde_leaf();
extern "C" void ds_test_no_fde_leaf();

asm(R"(
    .text
    .globl ds_test_fde_leaf
    .type ds_test_fde_leaf, @function
ds_test_fde_leaf:
    .cfi_startproc
    ret
    .cfi_endproc
    .size ds_test_fde_leaf, .-ds_test_fde_leaf

    .globl ds_test_no_fde_leaf
    .type ds_test_no_fde_leaf, @function
ds_test_no_fde_leaf:
    ret
    .size ds_test_no_fde_leaf, .-ds_test_no_fde_leaf
)");

namespace {

    // Closes a dlopen handle on scope exit; close() reports the dlclose result.
    struct DlHandle {
        void *handle = nullptr;

        ~DlHandle() {
            if (handle != nullptr) dlclose(handle);
        }

        int close() {
            void *open = handle;
            handle = nullptr;
            return dlclose(open);
        }
    };

    struct FdeRange {
        uintptr_t start = 0;// preferred-VMA space
        uint64_t size = 0;
    };

    struct ElfFdes {
        uintptr_t preferred_base = 0;
        std::vector<FdeRange> ranges;
    };

    // Independent FDE reader (libdwarf on the file, PT_LOAD for the load bias).
    bool read_fdes(const std::filesystem::path &path, ElfFdes &out) {
        std::ifstream file(path, std::ios::binary);
        Elf64_Ehdr header{};
        file.read(reinterpret_cast<char *>(&header), sizeof(header));
        if (!file || std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
            header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_phentsize != sizeof(Elf64_Phdr)) {
            return false;
        }
        uintptr_t preferred_base = UINTPTR_MAX;
        file.seekg(header.e_phoff);
        for (size_t i = 0; i < header.e_phnum; ++i) {
            Elf64_Phdr ph{};
            file.read(reinterpret_cast<char *>(&ph), sizeof(ph));
            if (!file) return false;
            if (ph.p_type == PT_LOAD) {
                preferred_base = std::min(preferred_base, uintptr_t(ph.p_vaddr & ~uint64_t{0xfff}));
            }
        }
        if (preferred_base == UINTPTR_MAX) return false;
        out.preferred_base = preferred_base;

        const int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) return false;
        Dwarf_Debug debug = nullptr;
        Dwarf_Error error = nullptr;
        if (dwarf_init_b(fd, DW_GROUPNUMBER_ANY, nullptr, nullptr, &debug, &error) != DW_DLV_OK) {
            close(fd);
            return false;
        }
        Dwarf_Cie *cies = nullptr;
        Dwarf_Fde *fdes = nullptr;
        Dwarf_Signed cie_count = 0;
        Dwarf_Signed fde_count = 0;
        if (dwarf_get_fde_list_eh(debug, &cies, &cie_count, &fdes, &fde_count, &error) == DW_DLV_OK) {
            for (Dwarf_Signed i = 0; i < fde_count; ++i) {
                Dwarf_Addr start = 0;
                Dwarf_Unsigned size = 0;
                if (dwarf_get_fde_range(fdes[i], &start, &size, nullptr, nullptr, nullptr, nullptr,
                                        nullptr, &error) != DW_DLV_OK) {
                    continue;
                }
                out.ranges.push_back({static_cast<uintptr_t>(start), static_cast<uint64_t>(size)});
            }
            dwarf_dealloc_fde_cie_list(debug, cies, cie_count, fdes, fde_count);
        }
        dwarf_finish(debug);
        close(fd);
        return !out.ranges.empty();
    }

    const FdeRange *fde_at(const ElfFdes &fdes, uintptr_t preferred_start) {
        for (const auto &range: fdes.ranges) {
            if (range.start == preferred_start) return &range;
        }
        return nullptr;
    }

    std::filesystem::path repo_lua51_so() {
        std::filesystem::path p = "Mod/deps/liblua51.so";
        if (std::filesystem::exists(p)) return p;
        p = std::filesystem::path{".."} / "Mod" / "deps" / "liblua51.so";
        return p;
    }

    // File-semantics load: modules the test maps through the production path.
    bool load_module(const std::string &path, ModuleSections &module) {
        if (!function_relocation::init_module_signature(path.c_str(), 0, module)) return false;
        return function_relocation::discover_module_functions(module);
    }

}// namespace

TEST_CASE("test_eh_frame_starts/lua51_dump_yield_are_span_starts") {
    REQUIRE(ensure_reloc_context());
    const auto path = repo_lua51_so();
    if (!std::filesystem::exists(path)) {
        std::fprintf(stderr, "FAIL missing %s\n", path.string().c_str());
    }
    REQUIRE(std::filesystem::exists(path));
    const auto absolute = std::filesystem::absolute(path);
    DlHandle library{dlopen(absolute.c_str(), RTLD_NOW | RTLD_LOCAL)};
    REQUIRE_NE(library.handle, nullptr);
    const auto dump_va = reinterpret_cast<uintptr_t>(dlsym(library.handle, "lua_dump"));
    const auto yield_va = reinterpret_cast<uintptr_t>(dlsym(library.handle, "lua_yield"));
    REQUIRE_NE(dump_va, 0);
    REQUIRE_NE(yield_va, 0);
    REQUIRE_NE(dump_va, yield_va);

    ElfFdes fdes;
    REQUIRE(read_fdes(absolute, fdes));

    ModuleSections module{};
    REQUIRE(load_module(absolute.string(), module));
    const uintptr_t bias = module.details.range.base_address - fdes.preferred_base;

    for (const auto address: {dump_va, yield_va}) {
        const auto *range = fde_at(fdes, address - bias);
        REQUIRE_NE(range, nullptr);// the independent oracle sees an exact FDE start
        REQUIRE_GT(range->size, 0);
        const auto *span = module.function_table.span_containing(address);
        REQUIRE_NE(span, nullptr);
        REQUIRE_EQ(span->start, address);
        REQUIRE_EQ(span->end, address + range->size);// exact loaded end
    }
    std::printf("lua_dump=0x%lx lua_yield=0x%lx spans=%zu\n", static_cast<unsigned long>(dump_va),
                static_cast<unsigned long>(yield_va), module.function_table.spans().size());
    REQUIRE_EQ(library.close(), 0);
}

TEST_CASE("test_eh_frame_starts/own_module_fde_boundary") {
    REQUIRE(ensure_reloc_context());
    // Keep both leaves alive and adjacent in this image.
    void (*volatile with_fde)() = &ds_test_fde_leaf;
    void (*volatile without_fde)() = &ds_test_no_fde_leaf;
    REQUIRE_NE(reinterpret_cast<uintptr_t>(with_fde), reinterpret_cast<uintptr_t>(without_fde));

    ModuleSections module{};
    REQUIRE(function_relocation::get_module_sections(nullptr, module));
    REQUIRE(function_relocation::discover_module_functions(module));

    const auto covered = reinterpret_cast<uintptr_t>(&ds_test_fde_leaf);
    const auto uncovered = reinterpret_cast<uintptr_t>(&ds_test_no_fde_leaf);
    const auto *span = module.function_table.span_containing(covered);
    REQUIRE_NE(span, nullptr);
    REQUIRE_EQ(span->start, covered);
    REQUIRE_EQ(span->end, covered + 1);// one `ret`, no padding inside the FDE
    REQUIRE(module.function_table.span_containing(uncovered) == nullptr);
    REQUIRE(module.find_function(uncovered) == nullptr);
}

static void test_loaded_pic_lua_call(const std::string &path, void *library) {
    ModuleSections module{};
    REQUIRE(load_module(path, module));
    const auto caller = reinterpret_cast<uintptr_t>(dlsym(library, "luaL_checklstring"));
    const auto callee = reinterpret_cast<uintptr_t>(dlsym(library, "lua_tolstring"));
    REQUIRE_NE(caller, 0);
    REQUIRE_NE(callee, 0);
    auto *fn = module.find_function(caller);
    REQUIRE_NE(fn, nullptr);
    REQUIRE(fn->size != 0);
    const auto raw = function_relocation::collect_rel32_call_targets(caller, fn->size);
    const auto resolved = function_relocation::collect_rel32_call_targets(module, caller, fn->size);
    REQUIRE_EQ(raw.size(), resolved.size());
    bool saw_plt_call = false;
    for (size_t i = 0; i < raw.size(); ++i) {
        saw_plt_call |= module.in_plt(raw[i]) && resolved[i] == callee;
    }
    REQUIRE(saw_plt_call);
    REQUIRE(function_relocation::body_calls_entry(module, caller, fn->size, callee));
    REQUIRE(function_relocation::ensure_function_features(*fn));
    bool saw_feature_call = false;
    for (auto address: fn->blocks) {
        const auto &calls = module.address_blocks.at(address)->call_functions;
        saw_feature_call |= std::find(calls.begin(), calls.end(), callee) != calls.end();
    }
    REQUIRE(saw_feature_call);
    std::puts("loaded PIC luaL_checklstring -> lua_tolstring: GraphSeed/body/ScanCtx agree");
}

TEST_CASE("test_eh_frame_starts/loaded_pic_lua_call") {
    REQUIRE(ensure_reloc_context());
    const auto path = std::filesystem::absolute(repo_lua51_so()).string();
    DlHandle library{dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL)};
    REQUIRE_NE(library.handle, nullptr);
    test_loaded_pic_lua_call(path, library.handle);
    const auto entry = reinterpret_cast<uintptr_t>(dlsym(library.handle, "lua_gettop"));
    REQUIRE_NE(entry, 0);
    // The interior pattern still recovers the entry from the FDE boundary.
    function_relocation::MemorySignature signature{"48 8B 47 10 48 2B 47 18", 7};
    signature.log = false;
    const auto raw = signature.scan(path.c_str());
    REQUIRE_NE(raw, 0);
    REQUIRE_EQ(signature.scan_function(path.c_str()), entry);
    REQUIRE_EQ(signature.pattern_offset, 7);
    REQUIRE_EQ(signature.scan(path.c_str()), raw);
    REQUIRE_EQ(library.close(), 0);
}
