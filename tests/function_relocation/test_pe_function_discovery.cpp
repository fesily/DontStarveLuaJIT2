#include "CallTargetResolver.hpp"
#include "FunctionDiscovery.hpp"
#include "FunctionRanges.hpp"
#include "ModuleSections.hpp"
#include "support/fr_context_env.hpp"

#include <doctest/doctest.h>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

using function_relocation::FunctionSpan;
using function_relocation::ModuleSections;

namespace {

    // ------------------------------------------------------------------
    // Synthetic PE32+ x64 image, mapped RVA == offset from the allocation.
    // ------------------------------------------------------------------
    constexpr uint32_t kImageSize = 0x4000;
    constexpr uint32_t kTextRva = 0x1000;
    constexpr uint32_t kTextSize = 0x1000;
    constexpr uint32_t kPdataRva = 0x2000;
    constexpr uint32_t kPdataSize = 0x1000;
    constexpr uint32_t kRdataRva = 0x3000;
    constexpr uint32_t kRdataSize = 0x1000;
    constexpr uint64_t kPreferredBase = 0x180000000ull;

    constexpr uint32_t kExportDirOffset = 0x400;
    constexpr uint32_t kTlsDirOffset = 0x600;
    constexpr uint32_t kTlsCallbacksOffset = 0x640;
    constexpr uint32_t kIatOffset = 0x680;

    struct TlsCallback {
        uint64_t target = 0;
        bool relocated = false;
    };

    struct ExportSpec {
        uint32_t rva = 0;
        const char *name = nullptr;// nullptr: ordinal-only
        bool forwarded = false;
    };

    class PeScratch {
    public:
        explicit PeScratch(uint64_t preferred_base = kPreferredBase)
            : preferred_base_(preferred_base) {
            image_ = static_cast<uint8_t *>(VirtualAlloc(nullptr, kImageSize, MEM_COMMIT | MEM_RESERVE,
                                                        PAGE_READWRITE));
            REQUIRE_NE(image_, nullptr);
            std::memset(image_, 0, kImageSize);
            write_headers();
        }

        ~PeScratch() {
            if (image_ != nullptr) VirtualFree(image_, 0, MEM_RELEASE);
        }

        PeScratch(const PeScratch &) = delete;
        PeScratch &operator=(const PeScratch &) = delete;

        uint8_t *image() const { return image_; }
        uintptr_t base() const { return reinterpret_cast<uintptr_t>(image_); }
        uintptr_t va(uint32_t rva) const { return base() + rva; }
        uint32_t text_va_offset(uint32_t offset) const { return kTextRva + offset; }

        uint8_t *text() const { return image_ + kTextRva; }

        ModuleSections module() const {
            ModuleSections m{};
            m.details = {
                    .name = "synthetic.dll",
                    .range = {base(), kImageSize},
                    .path = "synthetic.dll",
            };
            m.text = {va(kTextRva), kTextSize};
            m.rodata = {va(kRdataRva), kRdataSize};
            m.sections[".text"] = m.text;
            m.sections[".pdata"] = {va(kPdataRva), kPdataSize};
            m.sections[".rdata"] = m.rodata;
            return m;
        }

        void bytes(uint32_t offset, std::initializer_list<uint8_t> code) {
            REQUIRE_LE(offset + code.size(), kTextSize);
            std::memcpy(text() + offset, code.begin(), code.size());
        }

        void write32(uint32_t offset, uint32_t value) {
            std::memcpy(text() + offset, &value, sizeof(value));
        }

        // E8 rel32 -> code at `target_offset` in .text; returns the code offset.
        uint32_t call(uint32_t offset, uint32_t target_offset) {
            bytes(offset, {0xe8, 0, 0, 0, 0});
            const int32_t relative = static_cast<int32_t>(text_va_offset(target_offset)) -
                                     static_cast<int32_t>(text_va_offset(offset) + 5);
            std::memcpy(text() + offset + 1, &relative, sizeof(relative));
            return offset;
        }

        uint32_t jmp(uint32_t offset, uint32_t target_offset) {
            bytes(offset, {0xe9, 0, 0, 0, 0});
            const int32_t relative = static_cast<int32_t>(text_va_offset(target_offset)) -
                                     static_cast<int32_t>(text_va_offset(offset) + 5);
            std::memcpy(text() + offset + 1, &relative, sizeof(relative));
            return offset;
        }

        // FF 25 [rip+disp32] -> the IAT slot at .rdata offset `slot_offset`.
        uint32_t iat_thunk(uint32_t offset, uint32_t slot_offset) {
            bytes(offset, {0xff, 0x25, 0, 0, 0, 0});
            const uint32_t slot_rva = kRdataRva + slot_offset;
            const int32_t disp = static_cast<int32_t>(slot_rva) -
                                 static_cast<int32_t>(text_va_offset(offset) + 6);
            std::memcpy(text() + offset + 2, &disp, sizeof(disp));
            return offset;
        }

        void iat_slot(uint32_t slot_offset, uint64_t value) {
            std::memcpy(image_ + kRdataRva + slot_offset, &value, sizeof(value));
        }

        uint32_t unwind_primary() {
            const uint32_t offset = rdata_cursor_;
            uint8_t *info = image_ + kRdataRva + offset;
            info[0] = 0x01;// version 1, no flags
            info[1] = 0x00;// SizeOfProlog
            info[2] = 0x00;// CountOfCodes
            info[3] = 0x00;
            rdata_cursor_ += 8;
            return kRdataRva + offset;
        }

        // CHAININFO with an odd CountOfCodes, so the embedded parent record sits
        // after the DWORD-aligned code slot array (4 + 2 * ((3 + 1) & ~1) = 12).
        uint32_t unwind_chained(uint32_t parent_begin_rva, uint32_t parent_end_rva,
                                uint32_t parent_unwind_rva, uint32_t count_of_codes = 3) {
            const uint32_t offset = rdata_cursor_;
            uint8_t *info = image_ + kRdataRva + offset;
            info[0] = 0x01 | 0x20;// version 1 | UNW_FLAG_CHAININFO
            info[1] = 0x00;
            info[2] = static_cast<uint8_t>(count_of_codes);
            info[3] = 0x00;
            const uint32_t chain_offset = 4 + 2 * ((count_of_codes + 1) & ~1u);
            std::memcpy(info + chain_offset, &parent_begin_rva, sizeof(uint32_t));
            std::memcpy(info + chain_offset + 4, &parent_end_rva, sizeof(uint32_t));
            std::memcpy(info + chain_offset + 8, &parent_unwind_rva, sizeof(uint32_t));
            rdata_cursor_ += chain_offset + 12;
            return kRdataRva + offset;
        }

        // Returns the .pdata record index.
        uint32_t pdata_record(uint32_t begin_offset, uint32_t end_offset, uint32_t unwind_rva) {
            const uint32_t index = pdata_count_;
            uint8_t *record = image_ + kPdataRva + pdata_count_ * 12;
            const uint32_t begin = text_va_offset(begin_offset);
            const uint32_t end = text_va_offset(end_offset);
            std::memcpy(record, &begin, sizeof(begin));
            std::memcpy(record + 4, &end, sizeof(end));
            std::memcpy(record + 8, &unwind_rva, sizeof(unwind_rva));
            ++pdata_count_;
            return index;
        }

        uint32_t pdata_record_rva(uint32_t index) const { return kPdataRva + index * 12; }

        void entry_point(uint32_t offset) { entry_point_ = text_va_offset(offset); }

        void exports(std::vector<ExportSpec> specs) { exports_ = std::move(specs); }

        void tls_callback(uint64_t value, bool relocated) {
            tls_callbacks_.push_back({value, relocated});
        }

        // Patch the directories that depend on absolute addresses.
        void finalize() {
            patch_u32(0x3c, 0x40);// e_lfanew
            patch_u16(0x40 + 4 + 2, 3);// NumberOfSections
            patch_u16(0x40 + 4 + 16, 240);// SizeOfOptionalHeader
            patch_u32(0x58 + 16, entry_point_);
            const uint64_t image_base = preferred_base_;
            std::memcpy(image_ + 0x58 + 24, &image_base, sizeof(image_base));
            patch_u32(0x58 + 32, 0x1000);// SectionAlignment
            patch_u32(0x58 + 36, 0x200);// FileAlignment
            patch_u32(0x58 + 56, kImageSize);// SizeOfImage
            patch_u32(0x58 + 60, 0x400);// SizeOfHeaders
            patch_u32(0x58 + 108, 16);// NumberOfRvaAndSizes

            write_section(0, ".text", kTextRva, kTextSize, 0x60000020);
            write_section(1, ".pdata", kPdataRva, pdata_count_ * 12, 0x40000040);
            write_section(2, ".rdata", kRdataRva, kRdataSize, 0x40000040);

            // directory[3] = exception table
            patch_u32(0x58 + 112 + 3 * 8, kPdataRva);
            patch_u32(0x58 + 112 + 3 * 8 + 4, pdata_count_ * 12);

            if (!exports_.empty()) build_exports();
            if (!tls_callbacks_.empty()) build_tls();
        }

    private:
        void patch_u16(uint32_t offset, uint16_t value) {
            std::memcpy(image_ + offset, &value, sizeof(value));
        }

        void patch_u32(uint32_t offset, uint32_t value) {
            std::memcpy(image_ + offset, &value, sizeof(value));
        }

        void write_section(uint32_t index, const char *name, uint32_t rva, uint32_t raw_size,
                           uint32_t characteristics) {
            const uint32_t table = 0x58 + 240;
            uint8_t *header = image_ + table + index * 40;
            std::memcpy(header, name, std::strlen(name));
            std::memcpy(header + 8, &raw_size, 4);// VirtualSize
            std::memcpy(header + 12, &rva, 4);
            std::memcpy(header + 16, &raw_size, 4);
            std::memcpy(header + 20, &rva, 4);// PointerToRawData == RVA (flat image)
            std::memcpy(header + 36, &characteristics, 4);
        }

        void write_headers() {
            image_[0] = 'M';
            image_[1] = 'Z';
            patch_u32(0x3c, 0x40);
            const uint32_t signature = 0x00004550;
            std::memcpy(image_ + 0x40, &signature, sizeof(signature));
            const uint16_t machine = 0x8664;
            patch_u16(0x44, machine);
            const uint16_t magic = 0x20b;
            patch_u16(0x58, magic);
        }

        void build_exports() {
            const uint32_t directory_rva = kRdataRva + kExportDirOffset;
            uint8_t *directory = image_ + kRdataRva + kExportDirOffset;
            const uint32_t eat_offset = kExportDirOffset + 0x40;
            const uint32_t names_offset = kExportDirOffset + 0x80;
            const uint32_t ordinals_offset = kExportDirOffset + 0xC0;
            const uint32_t strings_offset = kExportDirOffset + 0x140;
            uint32_t strings_cursor = strings_offset;

            size_t named = 0;
            for (const auto &spec: exports_) {
                if (spec.name != nullptr) ++named;
            }
            const uint32_t function_count = static_cast<uint32_t>(exports_.size());
            const uint32_t name_count = static_cast<uint32_t>(named);
            const uint32_t eat_rva = kRdataRva + eat_offset;
            const uint32_t names_rva = kRdataRva + names_offset;
            const uint32_t ordinals_rva = kRdataRva + ordinals_offset;
            std::memcpy(directory + 20, &function_count, 4);// NumberOfFunctions
            std::memcpy(directory + 24, &name_count, 4);    // NumberOfNames
            std::memcpy(directory + 28, &eat_rva, 4);       // AddressOfFunctions
            std::memcpy(directory + 32, &names_rva, 4);     // AddressOfNames
            std::memcpy(directory + 36, &ordinals_rva, 4);  // AddressOfNameOrdinals
            // Directory size covers the forwarder strings placed inside it.
            const uint32_t directory_size = 0x200;
            patch_u32(0x58 + 112, directory_rva);
            patch_u32(0x58 + 112 + 4, directory_size);

            size_t name_index = 0;
            for (size_t i = 0; i < exports_.size(); ++i) {
                const auto &spec = exports_[i];
                uint32_t rva = spec.forwarded ? directory_rva + 0x180 : spec.rva;
                std::memcpy(image_ + kRdataRva + eat_offset + i * 4, &rva, 4);
                if (spec.name == nullptr) continue;
                const uint32_t name_rva = kRdataRva + strings_cursor;
                std::memcpy(image_ + kRdataRva + names_offset + name_index * 4, &name_rva, 4);
                const uint16_t ordinal = static_cast<uint16_t>(i);
                std::memcpy(image_ + kRdataRva + ordinals_offset + name_index * 2, &ordinal, 2);
                const size_t length = std::strlen(spec.name);
                std::memcpy(image_ + kRdataRva + strings_cursor, spec.name, length + 1);
                strings_cursor += static_cast<uint32_t>(length + 1);
                ++name_index;
            }
            // A forwarder needs a target string inside the directory; it is never
            // installed as an entry.
            const char *forwarder = "other.dll.Symbol";
            std::memcpy(image_ + kRdataRva + 0x180, forwarder, std::strlen(forwarder) + 1);
        }

        void build_tls() {
            const uint32_t directory_rva = kRdataRva + kTlsDirOffset;
            const uint32_t callbacks_rva = kRdataRva + kTlsCallbacksOffset;
            patch_u32(0x58 + 112 + 9 * 8, directory_rva);
            patch_u32(0x58 + 112 + 9 * 8 + 4, 40);
            uint8_t *directory = image_ + kRdataRva + kTlsDirOffset;
            const uint64_t callbacks_va = tls_callbacks_.front().relocated
                                                  ? va(callbacks_rva)
                                                  : preferred_base_ + callbacks_rva;
            std::memcpy(directory + 24, &callbacks_va, sizeof(callbacks_va));
            for (size_t i = 0; i < tls_callbacks_.size(); ++i) {
                const auto &callback = tls_callbacks_[i];
                const uint64_t value = callback.relocated ? callback.target
                                                          : preferred_base_ + callback.target;
                std::memcpy(image_ + kRdataRva + kTlsCallbacksOffset + i * 8, &value, sizeof(value));
            }
        }

        uint8_t *image_ = nullptr;
        uint64_t preferred_base_ = kPreferredBase;
        uint32_t rdata_cursor_ = 0;
        uint32_t pdata_count_ = 0;
        uint32_t entry_point_ = 0;
        std::vector<ExportSpec> exports_;
        std::vector<TlsCallback> tls_callbacks_;
    };

    const FunctionSpan *span_at(const ModuleSections &module, uint64_t address) {
        for (const auto &span: module.function_table.spans()) {
            if (span.start == address) return &span;
        }
        return nullptr;
    }

    std::vector<uint32_t> span_rvas(const ModuleSections &module) {
        std::vector<uint32_t> out;
        out.reserve(module.function_table.spans().size());
        for (const auto &span: module.function_table.spans()) {
            out.push_back(static_cast<uint32_t>(span.start - module.details.range.base_address));
        }
        return out;
    }

}// namespace

TEST_CASE("test_pe_function_discovery/unwind_and_seeds") {
    REQUIRE(ensure_reloc_context());
    PeScratch scratch;
    // Adjacent primaries keep their own ends (no chain merge).
    scratch.bytes(0x000, {0xc3});
    scratch.bytes(0x001, {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc});
    scratch.bytes(0x010, {0xc3});
    scratch.bytes(0x011, {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc});
    // Parent of the chained fragments.
    scratch.bytes(0x040, {0xc3});
    scratch.bytes(0x041, {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc});
    scratch.bytes(0x060, {0xc3});
    scratch.bytes(0x070, {0xc3});
    scratch.bytes(0x080, {0xc3});
    scratch.bytes(0x090, {0xc3});
    scratch.bytes(0x0a0, {0xc3});
    scratch.bytes(0x0b0, {0xc3});
    scratch.bytes(0x0c0, {0xc3});
    scratch.bytes(0x0d0, {0xc3});
    scratch.bytes(0x0e0, {0xc3});
    scratch.bytes(0x0f0, {0xc3});
    // Leaves reached from the export / entry point / TLS callback code.
    scratch.bytes(0x100, {0x31, 0xc0, 0xc3});
    scratch.bytes(0x110, {0x31, 0xc9, 0xc3});
    scratch.bytes(0x120, {0x31, 0xd2, 0xc3});
    scratch.call(0x130, 0x100);// export body -> leaf 0x100
    scratch.bytes(0x135, {0xc3});
    scratch.call(0x140, 0x110);// entry point -> leaf 0x110
    scratch.bytes(0x145, {0xc3});
    scratch.call(0x150, 0x120);// TLS callback -> leaf 0x120
    scratch.bytes(0x155, {0xc3});
    // A data EAT entry (in .rdata) must be filtered, not installed.
    scratch.exports({
            {scratch.text_va_offset(0x130), "lua_export_code", false},
            {scratch.text_va_offset(0x100), nullptr, false},// ordinal-only code entry
            {scratch.text_va_offset(0x110), "forwarded_export", true},
            {kRdataRva + kIatOffset, "data_export", false},
    });
    scratch.entry_point(0x140);
    scratch.tls_callback(scratch.va(scratch.text_va_offset(0x150)), true);

    const uint32_t primary_a = scratch.unwind_primary();
    scratch.pdata_record(0x000, 0x010, primary_a);
    const uint32_t primary_b = scratch.unwind_primary();
    scratch.pdata_record(0x010, 0x020, primary_b);
    const uint32_t parent = scratch.unwind_primary();
    const uint32_t parent_index = scratch.pdata_record(0x040, 0x050, parent);

    const uint32_t parent_begin = scratch.text_va_offset(0x040);
    const uint32_t parent_end = scratch.text_va_offset(0x050);
    const uint32_t chained1 = scratch.unwind_chained(parent_begin, parent_end, parent);
    scratch.pdata_record(0x060, 0x070, chained1);
    const uint32_t chained2 = scratch.unwind_chained(parent_begin, parent_end, parent);
    scratch.pdata_record(0x080, 0x090, chained2);
    // Indirect: UnwindData points at the parent's RUNTIME_FUNCTION (low bit set).
    const uint32_t indirect = scratch.pdata_record_rva(parent_index) | 1u;
    scratch.pdata_record(0x0a0, 0x0b0, indirect);
    // Broken chain: the embedded parent has no .pdata record.
    const uint32_t broken = scratch.unwind_chained(0x9999, 0x9999 + 0x10, parent);
    scratch.pdata_record(0x0c0, 0x0d0, broken);
    // Self-loop: the embedded parent is the record itself.
    const uint32_t own_begin = scratch.text_va_offset(0x0e0);
    const uint32_t own_end = scratch.text_va_offset(0x0f0);
    const uint32_t self_rva = scratch.pdata_record_rva(7);
    const uint32_t self_loop = scratch.unwind_chained(own_begin, own_end, self_rva);
    scratch.pdata_record(0x0e0, 0x0f0, self_loop);
    scratch.finalize();

    auto module = scratch.module();
    REQUIRE(function_relocation::discover_module_functions(module));

    const auto *a = span_at(module, scratch.va(scratch.text_va_offset(0x000)));
    const auto *b = span_at(module, scratch.va(scratch.text_va_offset(0x010)));
    REQUIRE_NE(a, nullptr);
    REQUIRE_NE(b, nullptr);
    REQUIRE_EQ(a->end, scratch.va(scratch.text_va_offset(0x010)));
    REQUIRE_EQ(b->end, scratch.va(scratch.text_va_offset(0x020)));

    const uint64_t parent_va = scratch.va(scratch.text_va_offset(0x040));
    REQUIRE(span_at(module, parent_va) != nullptr);
    // Every chained fragment resolves to the same primary.
    for (const uint32_t offset: {0x060u, 0x080u, 0x0a0u}) {
        const uint64_t address = scratch.va(scratch.text_va_offset(offset));
        REQUIRE_EQ(module.function_table.containing(address), parent_va);
        REQUIRE(module.function_table.span_containing(address) == nullptr);
        REQUIRE(span_at(module, address) == nullptr);
    }
    // Orphans block scanning but name no entry.
    REQUIRE_EQ(module.function_table.containing(scratch.va(scratch.text_va_offset(0x0c0))), 0);
    REQUIRE_EQ(module.function_table.containing(scratch.va(scratch.text_va_offset(0x0e0))), 0);

    // Export ordinal, entry point and TLS callback code each call a leaf.
    for (const uint32_t leaf: {0x100u, 0x110u, 0x120u}) {
        REQUIRE(span_at(module, scratch.va(scratch.text_va_offset(leaf))) != nullptr);
    }
    // Forwarder and data EAT entries never become entries.
    REQUIRE(span_at(module, scratch.va(kRdataRva + kIatOffset)) == nullptr);
    REQUIRE(module.function_table.containing(scratch.va(kRdataRva + kIatOffset)) == 0);
}

TEST_CASE("test_pe_function_discovery/tls_relocated_and_preferred_match") {
    REQUIRE(ensure_reloc_context());
    const auto build = [](bool relocated) {
        PeScratch scratch;
        scratch.bytes(0x000, {0xc3});
        scratch.bytes(0x040, {0xc3});
        scratch.call(0x040, 0x000);
        scratch.bytes(0x045, {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc});
        if (relocated) {
            scratch.tls_callback(scratch.va(scratch.text_va_offset(0x040)), true);
        } else {
            // Preferred-base form: the table stores preferred VAs, so the seed
            // must be remapped through the preferred base.
            scratch.tls_callback(scratch.text_va_offset(0x040), false);
        }
        const uint32_t unwind = scratch.unwind_primary();
        scratch.pdata_record(0x000, 0x010, unwind);
        scratch.finalize();
        auto module = scratch.module();
        REQUIRE(function_relocation::discover_module_functions(module));
        return span_rvas(module);
    };
    const auto relocated = build(true);
    const auto preferred = build(false);
    REQUIRE_EQ(relocated, preferred);
    // The TLS-derived entry survives ASLR: same RVA set, and the callback's own
    // code is an entry in both forms.
    REQUIRE_EQ(std::count(relocated.begin(), relocated.end(), kTextRva + 0x40u), 1);
}

TEST_CASE("test_pe_function_discovery/exception_directory_out_of_bounds") {
    REQUIRE(ensure_reloc_context());
    PeScratch scratch;
    scratch.bytes(0x000, {0xc3});
    const uint32_t unwind = scratch.unwind_primary();
    scratch.pdata_record(0x000, 0x010, unwind);
    scratch.finalize();
    auto module = scratch.module();
    // Directory points past the mapped image.
    const uint32_t bogus_rva = 0x8000;
    const uint32_t bogus_size = 0x100;
    std::memcpy(scratch.image() + 0x58 + 112 + 3 * 8, &bogus_rva, 4);
    std::memcpy(scratch.image() + 0x58 + 112 + 3 * 8 + 4, &bogus_size, 4);
    REQUIRE_FALSE(function_relocation::discover_module_functions(module));
    REQUIRE(module.function_table.empty());
}

TEST_CASE("test_pe_function_discovery/descent_and_adoption") {
    REQUIRE(ensure_reloc_context());
    PeScratch scratch;
    // Primary P: a Jcc splits the body; the taken block starts after the
    // fall-through RET.
    scratch.bytes(0x000, {0x74, 0x06});// je +6 -> 0x008
    scratch.call(0x002, 0x100);// cold fragment entry (never an entry itself)
    scratch.bytes(0x007, {0xc3});// fall-through RET
    scratch.call(0x008, 0x120);// first-round leaf
    scratch.call(0x00d, 0x001);// negative: mid-instruction of the Jcc
    scratch.call(0x012, 0x010);// negative: interior label of the primary
    scratch.bytes(0x017, {0xc3});
    scratch.bytes(0x018, {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc});
    // Cold fragment of P; it calls a leaf that nothing else references.
    scratch.call(0x100, 0x130);
    scratch.bytes(0x105, {0xc3});
    scratch.bytes(0x120, {0x31, 0xc0, 0xc3});
    scratch.bytes(0x130, {0x31, 0xc9, 0xc3});
    // Two stubs to the same in-section leaf: no entry at either stub.
    scratch.jmp(0x140, 0x180);
    scratch.iat_thunk(0x150, kIatOffset);
    scratch.iat_slot(kIatOffset, scratch.va(scratch.text_va_offset(0x180)));
    scratch.bytes(0x180, {0x31, 0xd2, 0xc3});
    // Undecodable target byte (0x62 == BOUND, invalid in 64-bit mode).
    scratch.call(0x190, 0x1a0);
    scratch.bytes(0x1a0, {0x62, 0x62, 0x62, 0x62});
    scratch.bytes(0x195, {0xc3});
    // Tail jmp out of the body plus INT3 padding: no entry at the target, and
    // the padding after the jmp belongs to nothing.
    scratch.jmp(0x1b0, 0x1c0);
    scratch.bytes(0x1b5, {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc});
    scratch.bytes(0x1c0, {0x31, 0xdb, 0xc3});
    scratch.exports({{scratch.text_va_offset(0x140), "thunk_e9", false},
                     {scratch.text_va_offset(0x150), "thunk_iat", false},
                     {scratch.text_va_offset(0x190), "decode_gate", false}});

    const uint32_t primary = scratch.unwind_primary();
    scratch.pdata_record(0x000, 0x020, primary);
    const uint32_t cold = scratch.unwind_chained(scratch.text_va_offset(0x000),
                                                 scratch.text_va_offset(0x020), primary);
    scratch.pdata_record(0x100, 0x110, cold);
    scratch.finalize();

    auto module = scratch.module();
    REQUIRE(function_relocation::discover_module_functions(module));

    const uint64_t primary_va = scratch.va(scratch.text_va_offset(0x000));
    // Both branches decoded: the block behind the RET called a leaf.
    REQUIRE(span_at(module, scratch.va(scratch.text_va_offset(0x120))) != nullptr);
    // The cold fragment's callee was adopted in the next round.
    REQUIRE(span_at(module, scratch.va(scratch.text_va_offset(0x130))) != nullptr);
    // The cold fragment itself is owned by P and is not an entry.
    const uint64_t cold_va = scratch.va(scratch.text_va_offset(0x100));
    REQUIRE_EQ(module.function_table.containing(cold_va), primary_va);
    REQUIRE(module.function_table.span_containing(cold_va) == nullptr);
    // Thunks carry no entry; the real body appears exactly once.
    REQUIRE(span_at(module, scratch.va(scratch.text_va_offset(0x140))) == nullptr);
    REQUIRE(span_at(module, scratch.va(scratch.text_va_offset(0x150))) == nullptr);
    size_t body_entries = 0;
    for (const auto &span: module.function_table.spans()) {
        if (span.start == scratch.va(scratch.text_va_offset(0x180))) ++body_entries;
    }
    REQUIRE_EQ(body_entries, 1);
    // Negative cases.
    for (const uint32_t offset: {0x001u, 0x010u, 0x1a0u, 0x1c0u}) {
        REQUIRE(span_at(module, scratch.va(scratch.text_va_offset(offset))) == nullptr);
    }
    // Interior labels still resolve to the primary.
    REQUIRE_EQ(module.function_table.containing(scratch.va(scratch.text_va_offset(0x010))), primary_va);
    // The unreachable INT3 padding after the tail jmp is claimed by nothing.
    REQUIRE_EQ(module.function_table.containing(scratch.va(scratch.text_va_offset(0x1b5))), 0);

    // Same buffer, second run: identical entries and ends.
    const auto first_spans = module.function_table.spans();
    auto again = scratch.module();
    REQUIRE(function_relocation::discover_module_functions(again));
    REQUIRE_EQ(first_spans.size(), again.function_table.spans().size());
    for (size_t i = 0; i < first_spans.size(); ++i) {
        REQUIRE_EQ(first_spans[i].start, again.function_table.spans()[i].start);
        REQUIRE_EQ(first_spans[i].end, again.function_table.spans()[i].end);
    }
}

TEST_CASE("test_pe_function_discovery/tail_jump_ends_body") {
    REQUIRE(ensure_reloc_context());
    PeScratch scratch;
    scratch.jmp(0x000, 0x100);// tail call out of the body
    scratch.bytes(0x005, {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc});
    scratch.bytes(0x100, {0x31, 0xc0, 0xc3});
    const uint32_t unwind = scratch.unwind_primary();
    scratch.pdata_record(0x000, 0x010, unwind);
    scratch.entry_point(0x000);
    scratch.finalize();

    auto module = scratch.module();
    REQUIRE(function_relocation::discover_module_functions(module));
    REQUIRE(span_at(module, scratch.va(scratch.text_va_offset(0x100))) == nullptr);
    size_t covered = 0;
    for (const auto &span: module.function_table.fragments()) ++covered;
    REQUIRE_EQ(covered, 0);
}

// ---------------------------------------------------------------------------
// Real reference DLL: the production path (LoadLibrary + get_module_sections +
// discover_module_functions) against an independent .pdata/export oracle.
// ---------------------------------------------------------------------------
namespace {

    struct PeExport {
        uint32_t rva = 0;
        std::string name;
    };

    std::vector<char> read_file(const std::filesystem::path &path) {
        std::ifstream f(path, std::ios::binary);
        REQUIRE(static_cast<bool>(f));
        return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    }

    struct PeOracle {
        std::vector<char> data;

        uint16_t rd16(size_t off) const {
            REQUIRE_LE(off + 2, data.size());
            uint16_t v;
            std::memcpy(&v, data.data() + off, 2);
            return v;
        }

        uint32_t rd32(size_t off) const {
            REQUIRE_LE(off + 4, data.size());
            uint32_t v;
            std::memcpy(&v, data.data() + off, 4);
            return v;
        }

        uint64_t rd64(size_t off) const {
            REQUIRE_LE(off + 8, data.size());
            uint64_t v;
            std::memcpy(&v, data.data() + off, 8);
            return v;
        }

        size_t nt() const { return static_cast<size_t>(rd32(0x3c)); }
        uint16_t section_count() const { return rd16(nt() + 4 + 2); }
        size_t optional() const { return nt() + 4 + 20; }
        size_t section_table() const { return optional() + rd16(nt() + 4 + 16); }

        size_t rva_to_offset(uint32_t rva) const {
            for (uint16_t i = 0; i < section_count(); ++i) {
                const size_t sh = section_table() + static_cast<size_t>(i) * 40;
                const uint32_t vsize = rd32(sh + 8);
                const uint32_t va = rd32(sh + 12);
                const uint32_t raw_size = rd32(sh + 16);
                const uint32_t raw_ptr = rd32(sh + 20);
                const uint32_t span = vsize > raw_size ? vsize : raw_size;
                if (rva >= va && rva < va + span) return static_cast<size_t>(raw_ptr) + (rva - va);
            }
            return static_cast<size_t>(-1);
        }

        uint64_t image_base() const { return rd64(optional() + 24); }

        std::vector<PeExport> exports() const {
            std::vector<PeExport> out;
            const uint32_t export_rva = rd32(optional() + 112);
            if (export_rva == 0) return out;
            const size_t exp = rva_to_offset(export_rva);
            REQUIRE_NE(exp, static_cast<size_t>(-1));
            const uint32_t n_names = rd32(exp + 24);// NumberOfNames
            const size_t funcs = rva_to_offset(rd32(exp + 28));
            const size_t names = rva_to_offset(rd32(exp + 32));
            const size_t ords = rva_to_offset(rd32(exp + 36));
            REQUIRE_NE(funcs, static_cast<size_t>(-1));
            REQUIRE_NE(names, static_cast<size_t>(-1));
            REQUIRE_NE(ords, static_cast<size_t>(-1));
            for (uint32_t i = 0; i < n_names; ++i) {
                const size_t name_off = rva_to_offset(rd32(names + i * 4));
                if (name_off == static_cast<size_t>(-1) || name_off >= data.size()) continue;
                const char *s = data.data() + name_off;
                const size_t max_len = data.size() - name_off;
                if (std::find(s, s + max_len, '\0') == s + max_len) continue;
                const uint16_t ordinal = rd16(ords + i * 2);
                out.push_back({rd32(funcs + static_cast<size_t>(ordinal) * 4), std::string(s)});
            }
            return out;
        }

        uint32_t export_rva(std::string_view name) const {
            for (const auto &entry: exports()) {
                if (entry.name == name) return entry.rva;
            }
            return 0;
        }

        // Non-chained .pdata BeginAddress RVAs — the function-entry oracle.
        std::vector<uint32_t> primary_begins() const {
            std::vector<uint32_t> out;
            const size_t directory = optional() + 112 + 3 * 8;
            const uint32_t pdata_rva = rd32(directory);
            const uint32_t pdata_size = rd32(directory + 4);
            REQUIRE_NE(pdata_rva, 0);
            REQUIRE_GE(pdata_size, 12);
            const size_t pdata = rva_to_offset(pdata_rva);
            REQUIRE_NE(pdata, static_cast<size_t>(-1));
            for (size_t i = 0; i < pdata_size / 12; ++i) {
                const size_t rec = pdata + i * 12;
                if (rec + 12 > data.size()) break;
                const uint32_t begin = rd32(rec);
                const uint32_t end = rd32(rec + 4);
                const uint32_t unwind = rd32(rec + 8);
                if (begin == 0 || end <= begin) continue;
                if ((unwind & 1) != 0) continue;// indirect: fragment
                const size_t uoff = rva_to_offset(unwind);
                if (uoff != static_cast<size_t>(-1) && uoff < data.size()) {
                    const unsigned flags = (static_cast<unsigned char>(data[uoff]) >> 3) & 0x1f;
                    if (flags & 0x4) continue;// UNW_FLAG_CHAININFO
                }
                out.push_back(begin);
            }
            return out;
        }
    };

    std::filesystem::path repo_lua51() {
        std::filesystem::path p = "Mod/deps/lua51.dll";
        if (std::filesystem::exists(p)) return p;
        p = std::filesystem::path{".."} / "Mod" / "deps" / "lua51.dll";
        return p;
    }

}// namespace

TEST_CASE("test_pe_function_discovery/reference_dll_entries") {
    REQUIRE(ensure_reloc_context());
    const auto path = repo_lua51();
    if (!std::filesystem::exists(path)) {
        std::fprintf(stderr, "FAIL missing %s\n", path.string().c_str());
    }
    REQUIRE(std::filesystem::exists(path));
    const auto absolute = std::filesystem::absolute(path);
    const auto narrow = absolute.string();
    HMODULE library = LoadLibraryW(absolute.wstring().c_str());
    REQUIRE_NE(library, nullptr);
    struct LibraryGuard {
        HMODULE handle;
        ~LibraryGuard() {
            if (handle != nullptr) FreeLibrary(handle);
        }
    } guard{library};

    ModuleSections module{};
    REQUIRE(function_relocation::init_module_signature(narrow.c_str(), 0, module));
    REQUIRE(function_relocation::discover_module_functions(module));

    PeOracle oracle{read_file(absolute)};
    const uint64_t image_base = oracle.image_base();
    REQUIRE_NE(image_base, 0);// .pdata/export RVAs are relative to the preferred base

    // Every non-chained .pdata BeginAddress is a span entry.
    size_t miss = 0;
    uint32_t first_miss = 0;
    size_t compared = 0;
    for (const uint32_t rva: oracle.primary_begins()) {
        const uint64_t address = module.details.range.base_address + rva;
        if (!module.in_text(address)) continue;
        ++compared;
        if (span_at(module, address) == nullptr) {
            if (miss == 0) first_miss = rva;
            ++miss;
        }
    }
    std::printf("pdata primaries=%zu compared=%zu miss=%zu first_miss=0x%x spans=%zu\n",
                oracle.primary_begins().size(), compared, miss, first_miss,
                module.function_table.spans().size());
    REQUIRE_GT(compared, 0);
    REQUIRE_EQ(miss, 0);

    // Exported entries resolve through the unified thunk resolver.
    const auto entry_of = [&](std::string_view name) {
        const auto address = reinterpret_cast<uintptr_t>(GetProcAddress(library, std::string{name}.c_str()));
        REQUIRE_NE(address, 0);
        return function_relocation::resolve_pe_discovery_target(module, address);
    };
    const auto resume = entry_of("lua_resume");
    const auto yield = entry_of("lua_yield");
    REQUIRE_NE(resume, 0);
    REQUIRE_NE(yield, 0);
    REQUIRE_NE(resume, yield);
    REQUIRE_NE(span_at(module, resume), nullptr);
    REQUIRE_NE(span_at(module, yield), nullptr);

    const auto getstack = entry_of("lua_getstack");
    REQUIRE_NE(getstack, 0);
    const auto *stack_span = span_at(module, getstack);
    REQUIRE_NE(stack_span, nullptr);
    REQUIRE_GT(stack_span->end, stack_span->start);

    // The span must not swallow the next export (no unwind data here, so the
    // entry bound is the next known start).
    const uint32_t getstack_rva = oracle.export_rva("lua_getstack");
    REQUIRE_NE(getstack_rva, 0);
    uint32_t next_rva = 0;
    for (const auto &entry: oracle.exports()) {
        if (entry.rva > getstack_rva && (next_rva == 0 || entry.rva < next_rva)) next_rva = entry.rva;
    }
    REQUIRE_NE(next_rva, 0);
    const uint64_t next_va = module.details.range.base_address + next_rva;
    if (stack_span->end > next_va || stack_span->end - stack_span->start >= 0x120) {
        std::fprintf(stderr, "getstack span unhealthy: start=0x%llx end=0x%llx next_export=0x%llx\n",
                     static_cast<unsigned long long>(stack_span->start),
                     static_cast<unsigned long long>(stack_span->end),
                     static_cast<unsigned long long>(next_va));
    }
    REQUIRE(stack_span->end <= next_va);
}

#else

TEST_CASE("test_pe_function_discovery/windows_only") {
    CHECK(true);
}

#endif
