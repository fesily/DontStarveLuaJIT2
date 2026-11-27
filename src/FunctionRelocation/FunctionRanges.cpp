#include "FunctionRanges.hpp"
#include "FunctionDiscovery.hpp"
#include "config.hpp"
#include <algorithm>
#include <spdlog/spdlog.h>
#include "disasm.h"
#include <fstream>
#include <limits>
#include <cstring>

#if defined(_WIN32)
#elif defined(__linux__)
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <libdwarf.h>
#include <dwarf.h>
#elif defined(__APPLE__)
#include <mach-o/loader.h>
#include <mach/mach.h>
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
            const uintptr_t text_end = m.text.base_address + m.text.size;
            for (Dwarf_Signed i = 0; i < fde_count; ++i) {
                Dwarf_Addr start = 0;
                Dwarf_Unsigned size = 0;
                if (dwarf_get_fde_range(fdes[i], &start, &size, nullptr, nullptr, nullptr, nullptr, nullptr, &error) != DW_DLV_OK) continue;
                if (size == 0 || start > UINTPTR_MAX - bias) continue;
                const uintptr_t address = bias + start;
                if (!m.in_text(address) || address > text_end) continue;
                if (size > text_end - address) continue;
                out.push_back({address, address + static_cast<uintptr_t>(size)});
            }
            dwarf_dealloc_fde_cie_list(debug, cies, cie_count, fdes, fde_count);
        }
        dwarf_finish(debug);
        close(fd);
        std::ranges::sort(out, {}, &FuncRange::start);
        // Same start keeps the longest FDE; different starts keep their own end.
        std::vector<FuncRange> dedup;
        dedup.reserve(out.size());
        for (const auto &range: out) {
            if (!dedup.empty() && dedup.back().start == range.start) {
                dedup.back().end = std::max(dedup.back().end, range.end);
            } else {
                dedup.push_back(range);
            }
        }
        out.swap(dedup);
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
        if (ranges.empty()) return nullptr;
        // Exact entry first: an exact start always beats an enclosing range.
        const auto exact = std::lower_bound(ranges.begin(), ranges.end(), addr,
                                            [](const FuncRange &range, uintptr_t value) {
                                                return range.start < value;
                                            });
        if (exact != ranges.end() && exact->start == addr) return &*exact;
        // Interior: shortest containing range, ties keep the later start.
        const auto it = std::upper_bound(ranges.begin(), ranges.end(), addr,
                                         [](uintptr_t value, const FuncRange &range) { return value < range.start; });
        const FuncRange *best = nullptr;
        for (auto cursor = it; cursor != ranges.begin();) {
            --cursor;
            if (addr < cursor->start || addr >= cursor->end) continue;
            if (!best || (cursor->end - cursor->start) < (best->end - best->start) ||
                ((cursor->end - cursor->start) == (best->end - best->start) &&
                 cursor->start > best->start)) {
                best = &*cursor;
            }
        }
        return best;
    }

#if defined(__APPLE__)
    namespace {

        struct BlobList {
            std::vector<std::vector<uint8_t>> blobs;
        };

        bool push_blob(BlobList &list, GumAddress vm_address, guint32 size) {
            if (vm_address == 0 || size == 0) return true;
            const auto *bytes = reinterpret_cast<const void *>(vm_address);
            if (!gum_memory_is_readable(bytes, size)) return true;
            const auto *first = static_cast<const uint8_t *>(bytes);
            list.blobs.emplace_back(first, first + size);
            return true;
        }

#if defined(DS_GUM_HAS_MACHO_FUNCTION_STARTS) || defined(DS_GUM_HAS_DARWIN_FUNCTION_STARTS)
        // Private Gum seam: the relocated Mach-O module for the loaded slice.
        bool collect_gum_function_starts(const ModuleSections &m, BlobList &list) {
#if defined(DS_GUM_HAS_MACHO_FUNCTION_STARTS)
            GumMachoModule *module = gum_macho_module_new_from_memory(
                    m.details.path.c_str(), mach_task_self(), m.details.range.base_address,
                    GUM_MACHO_MODULE_FLAGS_NONE, nullptr);
            if (module == nullptr) return false;
            gum_macho_module_enumerate_function_starts(
                    module,
                    +[](const GumMachoFunctionStartsDetails *details, gpointer user_data) -> gboolean {
                        return push_blob(*static_cast<BlobList *>(user_data), details->vm_address,
                                         details->size)
                                       ? TRUE
                                       : FALSE;
                    },
                    &list);
            g_object_unref(module);
#else
            GumDarwinModule *module = gum_darwin_module_new_from_memory(
                    m.details.path.c_str(), mach_task_self(), m.details.range.base_address,
                    GUM_DARWIN_MODULE_FLAGS_NONE, nullptr);
            if (module == nullptr) return false;
            gum_darwin_module_enumerate_function_starts(
                    module,
                    +[](const GumDarwinFunctionStartsDetails *details, gpointer user_data) -> gboolean {
                        return push_blob(*static_cast<BlobList *>(user_data), details->vm_address,
                                         details->size)
                                       ? TRUE
                                       : FALSE;
                    },
                    &list);
            g_object_unref(module);
#endif
            return !list.blobs.empty();
        }
#endif

        // Native fallback: walk the loaded header's load commands and locate the
        // LC_FUNCTION_STARTS payload inside __LINKEDIT. Coordinate math follows
        // core/alloc/backend_macho.cpp::scan_image.
        bool collect_load_command_function_starts(const ModuleSections &m, BlobList &list) {
            if (m.details.range.size < sizeof(mach_header_64)) return false;
            const auto base = m.details.range.base_address;
            const auto *header = reinterpret_cast<const mach_header_64 *>(base);
            if (!gum_memory_is_readable(header, sizeof(mach_header_64))) return false;
            if (header->magic != MH_MAGIC_64 || header->cputype != CPU_TYPE_X86_64) return false;
            const uint64_t commands_end = sizeof(mach_header_64) + header->sizeofcmds;
            if (commands_end > m.details.range.size) return false;

            uint64_t text_vmaddr = 0;
            bool have_text = false;
            uint64_t linkedit_vmaddr = 0;
            uint64_t linkedit_fileoff = 0;
            uint64_t linkedit_filesize = 0;
            bool have_linkedit = false;
            const linkedit_data_command *function_starts = nullptr;
            size_t function_starts_count = 0;

            const char *cursor = reinterpret_cast<const char *>(header) + sizeof(mach_header_64);
            for (uint32_t i = 0; i < header->ncmds; ++i) {
                if (!gum_memory_is_readable(cursor, sizeof(load_command))) return false;
                const auto *command = reinterpret_cast<const load_command *>(cursor);
                if (command->cmdsize < sizeof(load_command)) return false;
                if (static_cast<uint64_t>(cursor - reinterpret_cast<const char *>(header)) +
                            command->cmdsize >
                    commands_end) {
                    return false;
                }
                switch (command->cmd) {
                    case LC_SEGMENT_64: {
                        if (command->cmdsize < sizeof(segment_command_64)) return false;
                        const auto *segment = reinterpret_cast<const segment_command_64 *>(command);
                        if (std::strcmp(segment->segname, "__TEXT") == 0 && segment->fileoff == 0) {
                            text_vmaddr = segment->vmaddr;
                            have_text = true;
                        } else if (std::strcmp(segment->segname, "__LINKEDIT") == 0) {
                            linkedit_vmaddr = segment->vmaddr;
                            linkedit_fileoff = segment->fileoff;
                            linkedit_filesize = segment->filesize;
                            have_linkedit = true;
                        }
                        break;
                    }
                    case LC_FUNCTION_STARTS:
                        if (command->cmdsize < sizeof(linkedit_data_command)) return false;
                        function_starts = reinterpret_cast<const linkedit_data_command *>(command);
                        ++function_starts_count;
                        break;
                    default:
                        break;
                }
                cursor += command->cmdsize;
            }

            if (!have_text || !have_linkedit || function_starts == nullptr) return false;
            if (function_starts_count != 1) return false;// ambiguous command set
            const auto dataoff = function_starts->dataoff;
            const auto datasize = function_starts->datasize;
            if (datasize == 0) return false;
            if (dataoff < linkedit_fileoff) return false;
            const uint64_t offset_in_linkedit = dataoff - linkedit_fileoff;
            if (offset_in_linkedit > linkedit_filesize ||
                datasize > linkedit_filesize - offset_in_linkedit) {
                return false;
            }
            const uint64_t slide = base - text_vmaddr;
            if (linkedit_vmaddr > std::numeric_limits<uint64_t>::max() - slide) return false;
            const uint64_t blob_address = slide + linkedit_vmaddr + offset_in_linkedit;
            if (blob_address > UINTPTR_MAX) return false;
            return push_blob(list, static_cast<GumAddress>(blob_address), datasize);
        }

    }// namespace

    bool discover_macho(const ModuleSections &m, std::vector<FunctionSpan> &spans) {
        spans.clear();
        if (m.details.range.base_address == 0 || m.text.size == 0) return false;
        BlobList list;
#if defined(DS_GUM_HAS_MACHO_FUNCTION_STARTS) || defined(DS_GUM_HAS_DARWIN_FUNCTION_STARTS)
        if (!collect_gum_function_starts(m, list))
#endif
        {
            if (!collect_load_command_function_starts(m, list)) return false;
        }

        const uint64_t text_end = m.text.base_address + m.text.size;
        std::vector<uint64_t> entries;
        for (const auto &blob: list.blobs) {
            std::vector<FunctionSpan> decoded;
            if (!detail::decode_macho_function_starts(m.details.range.base_address, m.text, blob,
                                                      decoded)) {
                continue;
            }
            for (const auto &span: decoded) entries.push_back(span.start);
        }
        if (entries.empty()) return false;
        std::sort(entries.begin(), entries.end());
        entries.erase(std::unique(entries.begin(), entries.end()), entries.end());
        spans.reserve(entries.size());
        for (size_t i = 0; i < entries.size(); ++i) {
            const uint64_t end = i + 1 < entries.size() ? entries[i + 1] : text_end;
            spans.push_back({entries[i], end});
        }
        return true;
    }
#endif

    bool discover_module_functions(ModuleSections &module) {
        std::vector<FunctionSpan> spans;
        std::vector<FunctionFragment> fragments;
        const char *source = "unknown";
        bool discovered = false;
#if defined(_WIN32)
        source = "pe-x64";
        discovered = detail::discover_pe_x64(module, spans, fragments);
#elif defined(__APPLE__)
        source = "macho-function-starts";
        discovered = discover_macho(module, spans);
#else
        source = "elf-eh-frame";
        std::vector<FuncRange> ranges;
        if (enumerate_function_ranges_elf(module, ranges)) {
            const uintptr_t text_end = module.text.base_address + module.text.size;
            spans.reserve(ranges.size());
            for (const auto &range: ranges) {
                if (range.end <= range.start) continue;
                if (!module.in_text(range.start) || range.end > text_end) continue;
                spans.push_back({range.start, range.end});
            }
            discovered = !spans.empty();
        }
#endif
        if (!discovered) {
            if (auto log = spdlog::get(logger_name)) {
                log->error("discover_module_functions: no function entries from {} ({})", source,
                           module.details.path);
            }
            return false;
        }
        return detail::install_function_spans(module, std::move(spans), std::move(fragments));
    }

}// namespace function_relocation
