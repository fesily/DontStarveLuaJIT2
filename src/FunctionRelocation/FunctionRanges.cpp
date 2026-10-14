#include "FunctionRanges.hpp"
#include <algorithm>
#include <spdlog/spdlog.h>
#include "disasm.h"
#include <fstream>
#include <limits>
#include <cstring>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#elif defined(__linux__)
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <libdwarf.h>
#include <dwarf.h>
#endif

namespace function_relocation {

    bool enumerate_function_ranges_elf(const ModuleSections &m, std::vector<FuncRange> &out) {
        out.clear();
#if defined(__linux__)
        std::ifstream file(m.details.path, std::ios::binary);
        Elf64_Ehdr header{};
        file.read(reinterpret_cast<char *>(&header), sizeof(header));
        if (!file || std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
            header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
            header.e_phentsize != sizeof(Elf64_Phdr)) return false;
        uintptr_t preferred_base = std::numeric_limits<uintptr_t>::max();
        file.seekg(header.e_phoff);
        for (size_t i = 0; i < header.e_phnum; ++i) {
            Elf64_Phdr ph{};
            file.read(reinterpret_cast<char *>(&ph), sizeof(ph));
            if (!file) return false;
            if (ph.p_type == PT_LOAD) preferred_base = std::min(preferred_base, uintptr_t(ph.p_vaddr & ~uint64_t{0xfff}));
        }
        if (preferred_base == std::numeric_limits<uintptr_t>::max()) return false;
        const uintptr_t bias = m.details.range.base_address - preferred_base;
        const int fd = open(m.details.path.c_str(), O_RDONLY);
        if (fd < 0) return false;
        Dwarf_Debug debug = nullptr;
        Dwarf_Error error = nullptr;
        if (dwarf_init_b(fd, DW_GROUPNUMBER_ANY, nullptr, nullptr, &debug, &error) != DW_DLV_OK) {
            close(fd);
            return false;
        }
        Dwarf_Cie *cies = nullptr;
        Dwarf_Fde *fdes = nullptr;
        Dwarf_Signed cie_count = 0, fde_count = 0;
        if (dwarf_get_fde_list_eh(debug, &cies, &cie_count, &fdes, &fde_count, &error) == DW_DLV_OK) {
            for (Dwarf_Signed i = 0; i < fde_count; ++i) {
                Dwarf_Addr start = 0;
                Dwarf_Unsigned size = 0;
                if (dwarf_get_fde_range(fdes[i], &start, &size, nullptr, nullptr, nullptr, nullptr, nullptr, &error) != DW_DLV_OK) continue;
                const uintptr_t address = bias + start;
                if (size != 0 && m.in_text(address) && size <= m.text.base_address + m.text.size - address)
                    out.push_back({address, address + size, FuncRange::Source::EhFrame});
            }
            dwarf_dealloc_fde_cie_list(debug, cies, cie_count, fdes, fde_count);
        }
        dwarf_finish(debug);
        close(fd);
        std::ranges::sort(out, {}, &FuncRange::start);
        return !out.empty();
#else
        (void) m;
        return false;
#endif
    }

    uintptr_t resolve_function_entry(const ModuleSections &m, uintptr_t instruction_address) {
        std::vector<FuncRange> ranges;
        if (!enumerate_function_ranges_elf(m, ranges)) return 0;
        const auto *range = find_range_containing(ranges, instruction_address);
        if (!range) return 0;
        disasm code{reinterpret_cast<uint8_t *>(range->start), range->end - range->start};
        for (const auto &insn: code) {
            if (insn.address == instruction_address) return range->start;
            if (insn.address > instruction_address) break;
        }
        return 0;
    }

    const FuncRange *find_range_containing(const std::vector<FuncRange> &ranges, uintptr_t addr) {
        const auto it = std::upper_bound(ranges.begin(), ranges.end(), addr,
                                         [](uintptr_t value, const FuncRange &range) { return value < range.start; });
        if (it == ranges.begin()) return nullptr;
        const auto &range = *std::prev(it);
        return addr < range.end ? &range : nullptr;
    }

    bool enumerate_function_ranges_win(const ModuleSections &m, std::vector<FuncRange> &out) {
        out.clear();
#ifndef _WIN32
    (void)m;
    return false;
#else
    if (m.pdata.base_address == 0 || m.pdata.size < sizeof(RUNTIME_FUNCTION))
        return false;

    const auto image_base = m.details.range.base_address;
    auto* ptr = reinterpret_cast<const uint8_t*>(m.pdata.base_address);
    const auto* end = ptr + m.pdata.size;

    uintptr_t logical_begin = 0;
    uintptr_t logical_end = 0;
    bool open = false;

    auto flush = [&]() {
        if (!open) return;
        FuncRange r{};
        r.start = logical_begin;
        r.end = logical_end;
        r.source = FuncRange::Source::Pdata;
        out.push_back(r);
        open = false;
    };

    for (; ptr + sizeof(RUNTIME_FUNCTION) <= end; ptr += sizeof(RUNTIME_FUNCTION)) {
        const auto* rf = reinterpret_cast<const RUNTIME_FUNCTION*>(ptr);
        if (rf->BeginAddress == 0)
            break;

        const uintptr_t b = image_base + rf->BeginAddress;
        const uintptr_t e = image_base + rf->EndAddress;

        // Skip entries that do not land in text (best-effort).
        if (!m.in_text(b) || e < b) {
            continue;
        }

        if (open && b == logical_end) {
            // Adjacent chain: extend end.
            logical_end = e;
            continue;
        }

        flush();
        logical_begin = b;
        logical_end = e;
        open = true;
    }
    flush();

    std::sort(out.begin(), out.end(),
              [](const FuncRange& a, const FuncRange& b) { return a.start < b.start; });
    // Dedupe same start: keep longer end.
    std::vector<FuncRange> dedup;
    for (const auto& r : out) {
        if (!dedup.empty() && dedup.back().start == r.start) {
            dedup.back().end = std::max(dedup.back().end, r.end);
        } else {
            dedup.push_back(r);
        }
    }
    out.swap(dedup);
    return !out.empty();
#endif
    }

} // namespace function_relocation
