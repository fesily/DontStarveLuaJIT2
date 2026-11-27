#include "FunctionDiscovery.hpp"
#include "CallTargetResolver.hpp"
#include "disasm.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <chrono>
#include <spdlog/spdlog.h>

#include "config.hpp"

namespace function_relocation::detail {
    namespace {

        uint64_t saturating_add(uint64_t value, uint64_t delta) {
            return delta > std::numeric_limits<uint64_t>::max() - value
                           ? std::numeric_limits<uint64_t>::max()
                           : value + delta;
        }

    }// namespace

    // ----------------------------------------------------------------------
    // Mach-O LC_FUNCTION_STARTS: ULEB128 deltas accumulated from the loaded
    // image base (frida-gum's gum_store_function_range_from_starts uses the
    // same origin), entries kept inside the __text range.
    // ----------------------------------------------------------------------
    bool decode_macho_function_starts(uintptr_t image_base, GumMemoryRange text,
                                      std::span<const uint8_t> blob,
                                      std::vector<FunctionSpan> &spans) {
        spans.clear();
        if (image_base == 0 || text.base_address == 0 || text.size == 0 || blob.empty()) return false;
        const uint64_t text_begin = text.base_address;
        const uint64_t text_end = saturating_add(text.base_address, text.size);

        std::vector<uint64_t> entries;
        uint64_t address = image_base;
        size_t cursor = 0;
        bool terminated = false;
        while (cursor < blob.size()) {
            uint64_t delta = 0;
            bool complete = false;
            // A ULEB128 value never spans more than ten bytes for 64 bits.
            for (int shift = 0; shift < 10; ++shift) {
                if (cursor >= blob.size()) return false;// truncated value
                const uint8_t byte = blob[cursor++];
                const uint64_t payload = byte & 0x7f;
                if (shift == 9 && payload > 0x01) return false;// 64-bit overflow
                delta |= payload << (7 * shift);
                if ((byte & 0x80) == 0) {
                    complete = true;
                    break;
                }
            }
            if (!complete) return false;// never terminated within ten bytes
            if (delta == 0) {
                terminated = true;
                break;// zero terminates the list
            }
            if (delta > std::numeric_limits<uint64_t>::max() - address) return false;
            address += delta;
            if (address >= text_begin && address < text_end) entries.push_back(address);
        }
        if (!terminated || entries.empty()) return false;

        spans.reserve(entries.size());
        for (size_t i = 0; i < entries.size(); ++i) {
            const uint64_t end = i + 1 < entries.size() ? entries[i + 1] : text_end;
            spans.push_back({entries[i], end});
        }
        return true;
    }

#if defined(_WIN32)

    namespace {

        // ------------------------------------------------------------------
        // Loaded-memory readers. Every PE read goes through these so an
        // unreadable address is a reported error, never a fault.
        // ------------------------------------------------------------------
        bool read_bytes(uintptr_t address, void *out, size_t size) {
            if (address == 0 || size == 0) return false;
            const auto *source = reinterpret_cast<const void *>(address);
            if (!gum_memory_is_readable(source, size)) return false;
            std::memcpy(out, source, size);
            return true;
        }

        template<class T>
        bool read_at(uintptr_t address, T &out) {
            return read_bytes(address, &out, sizeof(T));
        }

        // ------------------------------------------------------------------
        // PE32+ reader (explicit layouts: the enumerator must not depend on
        // windows.h packing/defines, and reads the LOADED image).
        // ------------------------------------------------------------------
        constexpr uint16_t kDosMagic = 0x5a4d;
        constexpr uint32_t kPeSignature = 0x00004550;
        constexpr uint16_t kMachineAmd64 = 0x8664;
        constexpr uint16_t kPe32PlusMagic = 0x20b;
        constexpr uint32_t kScnMemExecute = 0x20000000;
        constexpr size_t kDirectoryExport = 0;
        constexpr size_t kDirectoryException = 3;
        constexpr size_t kDirectoryTls = 9;
        constexpr size_t kDirectoryCount = 16;

        // docs/function-enumeration-without-pdb.md §4/§10.
        constexpr size_t kMaxChainHops = 8;
        constexpr int kMaxAdoptRounds = 8;
        constexpr size_t kMaxOwnerInstructions = 200000;
        constexpr uint64_t kUnwindFreeCap = 0x8000;
        constexpr size_t kMaxInstructionBytes = 15;

#pragma pack(push, 1)
        struct DosHeader {
            uint16_t e_magic;
            uint8_t reserved[0x3a];
            uint32_t e_lfanew;
        };

        struct FileHeader {
            uint16_t machine;
            uint16_t number_of_sections;
            uint32_t timestamp;
            uint32_t pointer_to_symbol_table;
            uint32_t number_of_symbols;
            uint16_t size_of_optional_header;
            uint16_t characteristics;
        };

        struct OptionalHeader64 {
            uint16_t magic;
            uint8_t major_linker_version;
            uint8_t minor_linker_version;
            uint32_t size_of_code;
            uint32_t size_of_initialized_data;
            uint32_t size_of_uninitialized_data;
            uint32_t address_of_entry_point;
            uint32_t base_of_code;
            uint64_t image_base;
            uint32_t section_alignment;
            uint32_t file_alignment;
            uint16_t major_os_version;
            uint16_t minor_os_version;
            uint16_t major_image_version;
            uint16_t minor_image_version;
            uint16_t major_subsystem_version;
            uint16_t minor_subsystem_version;
            uint32_t win32_version_value;
            uint32_t size_of_image;
            uint32_t size_of_headers;
            uint32_t checksum;
            uint16_t subsystem;
            uint16_t dll_characteristics;
            uint64_t size_of_stack_reserve;
            uint64_t size_of_stack_commit;
            uint64_t size_of_heap_reserve;
            uint64_t size_of_heap_commit;
            uint32_t loader_flags;
            uint32_t number_of_rva_and_sizes;
        };

        struct SectionHeader {
            char name[8];
            uint32_t virtual_size;
            uint32_t virtual_address;
            uint32_t size_of_raw_data;
            uint32_t pointer_to_raw_data;
            uint32_t pointer_to_relocations;
            uint32_t pointer_to_linenumbers;
            uint16_t number_of_relocations;
            uint16_t number_of_linenumbers;
            uint32_t characteristics;
        };

        struct RuntimeFunction {
            uint32_t begin_address;
            uint32_t end_address;
            uint32_t unwind_data;
        };

        struct ExportDirectory {
            uint32_t characteristics;
            uint32_t timestamp;
            uint16_t major_version;
            uint16_t minor_version;
            uint32_t name;
            uint32_t base;
            uint32_t number_of_functions;
            uint32_t number_of_names;
            uint32_t address_of_functions;
            uint32_t address_of_names;
            uint32_t address_of_name_ordinals;
        };

        struct TlsDirectory64 {
            uint64_t start_address_of_raw_data;
            uint64_t end_address_of_raw_data;
            uint64_t address_of_index;
            uint64_t address_of_callbacks;
            uint32_t size_of_zero_fill;
            uint32_t characteristics;
        };
#pragma pack(pop)

        static_assert(sizeof(DosHeader) == 0x40, "DOS header layout");
        static_assert(sizeof(FileHeader) == 20, "COFF header layout");
        static_assert(sizeof(OptionalHeader64) == 112, "PE32+ optional header layout");
        static_assert(sizeof(SectionHeader) == 40, "section header layout");
        static_assert(sizeof(RuntimeFunction) == 12, "RUNTIME_FUNCTION layout");
        static_assert(sizeof(ExportDirectory) == 40, "export directory layout");
        static_assert(sizeof(TlsDirectory64) == 40, "TLS directory layout");

        struct DirectoryRange {
            uint32_t rva = 0;
            uint32_t size = 0;
        };

        struct PeImage {
            uintptr_t base = 0;
            uint64_t image_size = 0;
            uint64_t preferred_base = 0;
            uint32_t address_of_entry_point = 0;

            struct Section {
                char name[9] = {};
                uint32_t rva = 0;
                uint64_t extent = 0;
                uint64_t va = 0;
                uint64_t end = 0;
                uint32_t characteristics = 0;

                bool executable() const { return (characteristics & kScnMemExecute) != 0; }
            };

            std::vector<Section> sections;
            std::vector<DirectoryRange> directories;

            int exec_section_of(uint64_t va) const {
                for (size_t i = 0; i < sections.size(); ++i) {
                    const auto &section = sections[i];
                    if (!section.executable()) continue;
                    if (va >= section.va && va < section.end) return static_cast<int>(i);
                }
                return -1;
            }

            bool rva_in_exec_section(uint32_t rva) const {
                for (const auto &section: sections) {
                    if (!section.executable()) continue;
                    if (rva >= section.rva && rva < section.rva + section.extent) return true;
                }
                return false;
            }
        };

        bool parse_pe_image(const ModuleSections &module, PeImage &image, std::string &error) {
            image.base = module.details.range.base_address;
            image.image_size = module.details.range.size;
            if (image.base == 0 || image.image_size < sizeof(DosHeader)) {
                error = "module range is smaller than a DOS header";
                return false;
            }
            DosHeader dos{};
            if (!read_at(image.base, dos) || dos.e_magic != kDosMagic) {
                error = "not a PE image (missing MZ)";
                return false;
            }
            if (dos.e_lfanew == 0 || dos.e_lfanew > image.image_size - 4 - sizeof(FileHeader)) {
                error = "invalid e_lfanew";
                return false;
            }
            const uintptr_t nt = image.base + dos.e_lfanew;
            uint32_t signature = 0;
            if (!read_at(nt, signature) || signature != kPeSignature) {
                error = "not a PE image (missing PE signature)";
                return false;
            }
            FileHeader file{};
            if (!read_at(nt + 4, file)) {
                error = "truncated COFF header";
                return false;
            }
            if (file.number_of_sections == 0 || file.number_of_sections > 96) {
                error = "invalid section count";
                return false;
            }
            const uintptr_t optional = nt + 4 + sizeof(FileHeader);
            if (file.size_of_optional_header < sizeof(OptionalHeader64)) {
                error = "optional header is too small for PE32+";
                return false;
            }
            OptionalHeader64 optional_header{};
            if (!read_at(optional, optional_header)) {
                error = "truncated optional header";
                return false;
            }
            if (optional_header.magic != kPe32PlusMagic || file.machine != kMachineAmd64) {
                error = "not a PE32+ AMD64 image";
                return false;
            }
            image.preferred_base = optional_header.image_base;
            image.address_of_entry_point = optional_header.address_of_entry_point;

            image.directories.assign(kDirectoryCount, {});
            const size_t directory_count =
                    (std::min)(static_cast<size_t>(optional_header.number_of_rva_and_sizes), kDirectoryCount);
            const uintptr_t directory_table = optional + sizeof(OptionalHeader64);
            for (size_t i = 0; i < directory_count; ++i) {
                DirectoryRange range{};
                if (!read_at(directory_table + i * sizeof(DirectoryRange), range)) {
                    error = "truncated data directory";
                    return false;
                }
                image.directories[i] = range;
            }

            const uintptr_t section_table = optional + file.size_of_optional_header;
            image.sections.reserve(file.number_of_sections);
            for (uint32_t i = 0; i < file.number_of_sections; ++i) {
                SectionHeader header{};
                if (!read_at(section_table + static_cast<uintptr_t>(i) * sizeof(SectionHeader), header)) {
                    error = "truncated section table";
                    return false;
                }
                PeImage::Section section;
                std::memcpy(section.name, header.name, 8);
                section.rva = header.virtual_address;
                section.extent = (std::max)(static_cast<uint64_t>(header.virtual_size),
                                            static_cast<uint64_t>(header.size_of_raw_data));
                section.characteristics = header.characteristics;
                if (section.extent == 0) continue;
                if (section.rva > image.image_size ||
                    section.extent > image.image_size - section.rva) {
                    error = std::string{"section "} + section.name + " lies outside the mapped image";
                    return false;
                }
                section.va = image.base + section.rva;
                section.end = section.va + section.extent;
                // Every byte the decoder may touch is validated here, so the
                // per-instruction path needs no readability probe.
                if (section.executable() &&
                    !gum_memory_is_readable(reinterpret_cast<const void *>(section.va),
                                            static_cast<size_t>(section.extent))) {
                    error = std::string{"executable section "} + section.name + " is not mapped";
                    return false;
                }
                image.sections.push_back(section);
            }
            if (image.sections.empty()) {
                error = "no mapped sections";
                return false;
            }
            return true;
        }

        struct PdataRecord {
            uint32_t begin = 0;
            uint32_t end = 0;
            uint32_t unwind = 0;
            uint32_t record_rva = 0;
        };

        enum class RecordKind { Primary,
                               Chained,
                               Indirect };

        // A record whose unwind header cannot be read is a structural defect of
        // the `.pdata` root; a broken parent chain is only an orphan fragment.
        bool classify_record(const PeImage &image, const PdataRecord &record, RecordKind &kind) {
            if (record.unwind == 0) {
                // Defensive: no unwind info at all behaves like a primary.
                kind = RecordKind::Primary;
                return true;
            }
            if ((record.unwind & 1) != 0) {
                kind = RecordKind::Indirect;
                return true;
            }
            unsigned char header[4]{};
            if (record.unwind > image.image_size ||
                sizeof(header) > image.image_size - record.unwind) {
                return false;
            }
            if (!read_bytes(image.base + record.unwind, header, sizeof(header))) return false;
            // byte0 bit5 == UNW_FLAG_CHAININFO (flags live in bits 3..7).
            kind = (header[0] & 0x20) != 0 ? RecordKind::Chained : RecordKind::Primary;
            return true;
        }

        // CHAININFO embeds the parent RUNTIME_FUNCTION after the unwind header and
        // its code slots, DWORD aligned: 4 + 2 * ((CountOfCodes + 1) & ~1).
        bool chained_parent(const PeImage &image, const PdataRecord &record, RuntimeFunction &parent) {
            unsigned char header[4]{};
            if (record.unwind == 0 || record.unwind > image.image_size ||
                sizeof(header) > image.image_size - record.unwind) {
                return false;
            }
            if (!read_bytes(image.base + record.unwind, header, sizeof(header))) return false;
            const uint32_t count_of_codes = header[2];
            const uint32_t offset = 4 + 2 * ((count_of_codes + 1) & ~1u);
            if (record.unwind > image.image_size ||
                offset > image.image_size - record.unwind ||
                sizeof(parent) > image.image_size - record.unwind - offset) {
                return false;
            }
            return read_at(image.base + record.unwind + offset, parent);
        }

        struct PdataTable {
            std::vector<PdataRecord> records;
            std::unordered_map<uint32_t, size_t> by_begin;
            std::unordered_map<uint32_t, size_t> by_record_rva;
        };

        bool read_pdata(const PeImage &image, PdataTable &table, std::string &error) {
            const auto directory = image.directories[kDirectoryException];
            if (directory.rva == 0 || directory.size < sizeof(RuntimeFunction)) {
                error = "no .pdata (exception directory)";
                return false;
            }
            if (directory.rva > image.image_size || directory.size > image.image_size - directory.rva) {
                error = "exception directory lies outside the mapped image";
                return false;
            }
            if (!gum_memory_is_readable(reinterpret_cast<const void *>(image.base + directory.rva),
                                        directory.size)) {
                error = "exception directory is unreadable";
                return false;
            }
            const size_t count = directory.size / sizeof(RuntimeFunction);
            table.records.reserve(count);
            for (size_t i = 0; i < count; ++i) {
                RuntimeFunction raw{};
                const uint32_t record_rva =
                        directory.rva + static_cast<uint32_t>(i * sizeof(RuntimeFunction));
                if (!read_at(image.base + record_rva, raw)) {
                    error = "truncated exception directory";
                    return false;
                }
                if (raw.begin_address == 0 && raw.end_address == 0 && raw.unwind_data == 0) {
                    continue;// zero padding
                }
                if (raw.begin_address == 0 || raw.end_address <= raw.begin_address) {
                    error = "invalid RUNTIME_FUNCTION bounds";
                    return false;
                }
                table.records.push_back({raw.begin_address, raw.end_address, raw.unwind_data, record_rva});
            }
            if (table.records.empty()) {
                error = "empty .pdata";
                return false;
            }

            std::sort(table.records.begin(), table.records.end(),
                      [](const PdataRecord &l, const PdataRecord &r) {
                          return l.begin < r.begin || (l.begin == r.begin && l.end < r.end);
                      });
            table.records.erase(std::unique(table.records.begin(), table.records.end(),
                                            [](const PdataRecord &l, const PdataRecord &r) {
                                                return l.begin == r.begin && l.end == r.end &&
                                                       l.unwind == r.unwind;
                                            }),
                                table.records.end());

            uint32_t previous_bounds = 0;
            for (size_t i = 0; i < table.records.size(); ++i) {
                const auto &record = table.records[i];
                if (i != 0) {
                    const auto &previous = table.records[i - 1];
                    if (record.begin == previous.begin) {
                        error = "two different .pdata records share a BeginAddress";
                        return false;
                    }
                    if (record.begin < previous_bounds) {
                        error = "overlapping .pdata records";
                        return false;
                    }
                }
                previous_bounds = record.end;
                table.by_begin.emplace(record.begin, i);
                table.by_record_rva.emplace(record.record_rva, i);
            }
            return true;
        }

        struct Classification {
            size_t primary_count = 0;
            size_t chained_merged = 0;
            size_t chained_orphan = 0;
            std::vector<FunctionSpan> primaries;
            std::vector<FunctionFragment> fragments;
        };

        // Walk one record's parent chain to the primary it belongs to.
        bool resolve_chain_root(const PeImage &image, const PdataTable &table, size_t start_index,
                               uint32_t &root_begin, uint32_t &root_end) {
            std::unordered_set<uint32_t> visited;
            uint32_t current_rva = table.records[start_index].record_rva;
            for (size_t hop = 0; hop < kMaxChainHops; ++hop) {
                if (!visited.insert(current_rva).second) return false;// cycle
                const auto found = table.by_record_rva.find(current_rva);
                if (found == table.by_record_rva.end()) return false;
                const auto &record = table.records[found->second];
                RecordKind kind = RecordKind::Primary;
                if (!classify_record(image, record, kind)) return false;
                if (kind == RecordKind::Primary) {
                    root_begin = record.begin;
                    root_end = record.end;
                    return true;
                }
                if (kind == RecordKind::Indirect) {
                    current_rva = record.unwind & ~1u;
                    continue;
                }
                RuntimeFunction parent{};
                if (!chained_parent(image, record, parent)) return false;
                const auto parent_index = table.by_begin.find(parent.begin_address);
                if (parent_index == table.by_begin.end()) return false;
                const auto &parent_record = table.records[parent_index->second];
                if (parent_record.end != parent.end_address ||
                    parent_record.unwind != parent.unwind_data) {
                    return false;// embedded copy disagrees with .pdata
                }
                current_rva = parent_record.record_rva;
            }
            return false;// chain deeper than the hop limit
        }

        bool classify_pdata(const PeImage &image, const PdataTable &table, Classification &out,
                            std::string &error) {
            for (size_t i = 0; i < table.records.size(); ++i) {
                const auto &record = table.records[i];
                if (!image.rva_in_exec_section(record.begin) ||
                    !image.rva_in_exec_section(record.end - 1)) {
                    // Not code we can decode; leave it out instead of failing the
                    // whole module on a stale record.
                    continue;
                }
                RecordKind kind = RecordKind::Primary;
                if (!classify_record(image, record, kind)) {
                    error = "unreadable unwind info in .pdata";
                    return false;
                }
                if (kind == RecordKind::Primary) {
                    out.primaries.push_back({image.base + record.begin, image.base + record.end});
                    ++out.primary_count;
                    continue;
                }
                FunctionFragment fragment;
                fragment.span = {image.base + record.begin, image.base + record.end};
                uint32_t root_begin = 0;
                uint32_t root_end = 0;
                if (resolve_chain_root(image, table, i, root_begin, root_end)) {
                    fragment.owner = image.base + root_begin;
                    ++out.chained_merged;
                } else {
                    fragment.owner = 0;
                    ++out.chained_orphan;
                }
                out.fragments.push_back(fragment);
            }
            if (out.primary_count == 0) {
                error = "no unwind primary in .pdata";
                return false;
            }

            std::sort(out.primaries.begin(), out.primaries.end(),
                      [](const FunctionSpan &l, const FunctionSpan &r) { return l.start < r.start; });
            out.primaries.erase(std::unique(out.primaries.begin(), out.primaries.end(),
                                            [](const FunctionSpan &l, const FunctionSpan &r) {
                                                return l.start == r.start && l.end == r.end;
                                            }),
                                out.primaries.end());
            std::sort(out.fragments.begin(), out.fragments.end(),
                      [](const FunctionFragment &l, const FunctionFragment &r) {
                          return l.span.start < r.span.start;
                      });
            return true;
        }

        // ------------------------------------------------------------------
        // Block-scoped recursive descent (docs §3.2).
        // ------------------------------------------------------------------
        size_t section_offset(const PeImage &image, int section, uint64_t va) {
            return static_cast<size_t>(va - image.sections[static_cast<size_t>(section)].va);
        }

        bool is_conditional_branch(const cs_insn &insn) {
            for (uint8_t i = 0; i < insn.detail->groups_count; ++i) {
                if (insn.detail->groups[i] == CS_GRP_BRANCH_RELATIVE) return true;
            }
            return false;
        }

        bool is_block_terminator(const cs_insn &insn) {
            switch (insn.id) {
                case X86_INS_RET:
                case X86_INS_RETF:
                case X86_INS_RETFQ:
                case X86_INS_IRET:
                case X86_INS_IRETD:
                case X86_INS_IRETQ:
                case X86_INS_INT3:
                case X86_INS_HLT:
                case X86_INS_UD0:
                case X86_INS_UD1:
                case X86_INS_UD2:
                    return true;
                default:
                    return false;
            }
        }

        struct Descender {
            const ModuleSections &module;
            const PeImage &image;
            cs_insn &instruction;
            // Per executable section: decoded bytes / bytes covered by unwind
            // metadata. reserved never stops a walk inside its own range; it
            // bounds unwind-free entries and rejects interior candidates.
            std::vector<std::vector<uint8_t>> claimed;
            std::vector<std::vector<uint8_t>> reserved;
            std::vector<uint64_t> pending;
            std::unordered_map<uint64_t, size_t> owner_instructions;
            size_t budget_trips = 0;
            size_t covered_bytes = 0;

            Descender(const ModuleSections &m, const PeImage &img, cs_insn &insn)
                : module(m), image(img), instruction(insn) {
                claimed.resize(image.sections.size());
                reserved.resize(image.sections.size());
                for (size_t i = 0; i < image.sections.size(); ++i) {
                    claimed[i].assign(static_cast<size_t>(image.sections[i].extent), 0);
                    reserved[i].assign(static_cast<size_t>(image.sections[i].extent), 0);
                }
            }

            bool claimed_at(uint64_t va) const {
                const int section = image.exec_section_of(va);
                if (section < 0) return true;// outside code: treat as taken
                return claimed[static_cast<size_t>(section)][section_offset(image, section, va)] != 0;
            }

            bool reserved_at(uint64_t va) const {
                const int section = image.exec_section_of(va);
                if (section < 0) return false;
                return reserved[static_cast<size_t>(section)][section_offset(image, section, va)] != 0;
            }

            void reserve_span(const FunctionSpan &span) {
                for (uint64_t va = span.start; va < span.end;) {
                    const int section = image.exec_section_of(va);
                    if (section < 0) break;
                    const auto &ranges = image.sections[static_cast<size_t>(section)];
                    auto &table = reserved[static_cast<size_t>(section)];
                    const uint64_t stop = (std::min)(span.end, ranges.end);
                    for (uint64_t cursor = va; cursor < stop; ++cursor) {
                        table[section_offset(image, section, cursor)] = 1;
                    }
                    va = stop;
                }
            }

            bool claim(uint64_t va, size_t size) {
                const int section = image.exec_section_of(va);
                if (section < 0) return false;
                const auto &ranges = image.sections[static_cast<size_t>(section)];
                if (va < ranges.va || va + size > ranges.end) return false;
                auto &table = claimed[static_cast<size_t>(section)];
                const size_t offset = section_offset(image, section, va);
                for (size_t i = 0; i < size; ++i) {
                    if (table[offset + i] != 0) return false;
                }
                for (size_t i = 0; i < size; ++i) {
                    table[offset + i] = 1;
                }
                return true;
            }

            // Section extents were validated as mapped in parse_pe_image, so the
            // hot path never probes protection: the byte window is bounded by the
            // owner range and the instruction length limit.
            bool decode_first(uint64_t va, size_t available) const {
                const auto *code = reinterpret_cast<const uint8_t *>(va);
                size_t left = (std::min)(available, kMaxInstructionBytes);
                uint64_t address = va;
                return left != 0 &&
                       cs_disasm_iter(get_ctx().hcs, &code, &left, &address, &instruction) != 0;
            }

            // Walk one owner's range. Returns the furthest claimed instruction
            // end (== start when nothing decoded).
            uint64_t walk(uint64_t start, uint64_t end, uint64_t owner) {
                const int section = image.exec_section_of(start);
                if (section < 0) return start;
                const auto &ranges = image.sections[static_cast<size_t>(section)];
                auto &claims = claimed[static_cast<size_t>(section)];
                const uint64_t section_va = ranges.va;
                end = (std::min)(end, ranges.end);
                uint64_t furthest = start;
                std::vector<uint64_t> work;
                work.push_back(start);
                while (!work.empty()) {
                    uint64_t pc = work.back();
                    work.pop_back();
                    bool next_block = false;
                    while (!next_block) {
                        if (pc < start || pc >= end) break;
                        const size_t offset = static_cast<size_t>(pc - section_va);
                        if (claims[offset] != 0) break;
                        const size_t available = static_cast<size_t>(end - pc);
                        if (!decode_first(pc, available)) break;
                        const uint64_t size = instruction.size;
                        if (size == 0 || size > end - pc ||
                            size > claims.size() - offset) {
                            break;
                        }
                        bool free = true;
                        for (uint64_t i = 0; i < size; ++i) {
                            if (claims[offset + i] != 0) {
                                free = false;
                                break;
                            }
                        }
                        if (!free) break;
                        for (uint64_t i = 0; i < size; ++i) claims[offset + i] = 1;
                        covered_bytes += static_cast<size_t>(size);
                        furthest = (std::max)(furthest, pc + size);
                        auto &count = owner_instructions[owner];
                        if (++count > kMaxOwnerInstructions) {
                            ++budget_trips;
                            if (auto log = spdlog::get(logger_name)) {
                                log->warn("discover_pe_x64: instruction budget exhausted at {} owner {}",
                                          (void *) pc, (void *) owner);
                            }
                            return furthest;
                        }
                        const auto &x86 = instruction.detail->x86;
                        const auto &op0 = x86.operands[0];
                        switch (instruction.id) {
                            case X86_INS_CALL:
                                if (op0.type == X86_OP_IMM) {
                                    const auto target = static_cast<uint64_t>(op0.imm);
                                    if (image.exec_section_of(target) >= 0) pending.push_back(target);
                                }
                                pc += size;// call falls through
                                break;
                            case X86_INS_JMP:
                                if (op0.type == X86_OP_IMM) {
                                    const auto target = static_cast<uint64_t>(op0.imm);
                                    if (target >= start && target < end && !claimed_at(target)) {
                                        work.push_back(target);
                                    }
                                }
                                next_block = true;// unconditional jmp ends the block
                                break;
                            default:
                                if (is_conditional_branch(instruction)) {
                                    if (op0.type == X86_OP_IMM) {
                                        const auto target = static_cast<uint64_t>(op0.imm);
                                        if (target >= start && target < end && !claimed_at(target)) {
                                            work.push_back(target);
                                        }
                                    }
                                    pc += size;
                                } else if (is_block_terminator(instruction)) {
                                    next_block = true;
                                } else {
                                    pc += size;
                                }
                                break;
                        }
                    }
                }
                return furthest;
            }
        };

        void insert_sorted(std::vector<uint64_t> &values, uint64_t value) {
            const auto it = std::lower_bound(values.begin(), values.end(), value);
            if (it != values.end() && *it == value) return;
            values.insert(it, value);
        }

        bool is_entry_thunk(const cs_insn &insn) {
            if (insn.id != X86_INS_JMP) return false;
            if (insn.size == 5 && insn.bytes[0] == 0xe9) return true;
            return insn.size == 6 && insn.bytes[0] == 0xff && insn.bytes[1] == 0x25;
        }

        // ------------------------------------------------------------------
        // Seeds: PE export table (incl. ordinal-only), AddressOfEntryPoint and
        // TLS callbacks.
        // ------------------------------------------------------------------
        std::vector<uint64_t> export_seeds(const PeImage &image) {
            std::vector<uint64_t> seeds;
            const auto directory = image.directories[kDirectoryExport];
            if (directory.rva == 0 || directory.size < sizeof(ExportDirectory)) return seeds;
            ExportDirectory exports{};
            if (!read_at(image.base + directory.rva, exports)) return seeds;
            if (exports.number_of_functions == 0 || exports.address_of_functions == 0) return seeds;
            // Forwarders are EAT entries whose RVA falls inside the export
            // directory itself.
            const uint64_t directory_end = static_cast<uint64_t>(directory.rva) + directory.size;
            seeds.reserve(exports.number_of_functions);
            for (uint32_t i = 0; i < exports.number_of_functions; ++i) {
                uint32_t rva = 0;
                const uint64_t slot = static_cast<uint64_t>(exports.address_of_functions) +
                                      static_cast<uint64_t>(i) * sizeof(uint32_t);
                if (slot > image.image_size || sizeof(uint32_t) > image.image_size - slot) return seeds;
                if (!read_at(image.base + slot, rva)) return seeds;
                if (rva == 0) continue;// unused ordinal
                if (rva >= directory.rva && rva < directory_end) continue;// forwarder
                if (!image.rva_in_exec_section(rva)) continue;
                    seeds.push_back(image.base + rva);
            }
            return seeds;
        }

        // The TLS callback array is a VA list. The loader relocates the directory
        // and the entries, so the current-base form is tried first; an unrelocated
        // (preferred-base) image yields the same addresses through the second
        // form. The whole table must validate: every entry and the terminating
        // zero readable, every non-zero entry inside this module's code.
        bool read_tls_seeds(const PeImage &image, std::vector<uint64_t> &seeds) {
            const auto directory = image.directories[kDirectoryTls];
            if (directory.rva == 0 || directory.size < sizeof(TlsDirectory64)) return false;
            if (directory.rva > image.image_size ||
                sizeof(TlsDirectory64) > image.image_size - directory.rva) {
                return false;
            }
            TlsDirectory64 tls{};
            if (!read_at(image.base + directory.rva, tls)) return false;
            if (tls.address_of_callbacks == 0) return false;

            const uint64_t bases[2] = {image.base, image.preferred_base};
            for (const uint64_t base: bases) {
                if (base == 0 || tls.address_of_callbacks < base) continue;
                const uint64_t table_rva = tls.address_of_callbacks - base;
                if (table_rva >= image.image_size) continue;
                const uint64_t table_va = image.base + table_rva;
                std::vector<uint64_t> collected;
                bool valid = true;
                for (size_t i = 0; i < 64; ++i) {
                    uint64_t value = 0;
                    if (!read_at(table_va + i * sizeof(uint64_t), value)) {
                        valid = false;
                        break;
                    }
                    if (value == 0) break;// terminator
                    if (value < base) {
                        valid = false;
                        break;
                    }
                    const uint64_t rva = value - base;
                    if (rva >= image.image_size ||
                        !image.rva_in_exec_section(static_cast<uint32_t>(rva))) {
                        valid = false;
                        break;
                    }
                    collected.push_back(image.base + rva);
                    if (i + 1 == 64) valid = false;// no terminator within the cap
                }
                if (valid && !collected.empty()) {
                    seeds.insert(seeds.end(), collected.begin(), collected.end());
                    return true;
                }
            }
            return false;
        }

    }// namespace

    bool discover_pe_x64(const ModuleSections &module, std::vector<FunctionSpan> &spans,
                         std::vector<FunctionFragment> &fragments) {
        spans.clear();
        fragments.clear();
        auto log = spdlog::get(logger_name);
        const auto path = module.details.path;
        const auto fail = [&](const std::string &why) {
            if (log) log->error("discover_pe_x64: {} ({})", why, path);
            return false;
        };

        const auto phase_start = std::chrono::steady_clock::now();
        const auto phase_ms = [&phase_start] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - phase_start).count();
        };
        PeImage image;
        std::string error;
        if (!parse_pe_image(module, image, error)) return fail(error);

        PdataTable pdata;
        if (!read_pdata(image, pdata, error)) return fail(error);
        const auto ms_pdata = phase_ms();

        Classification classification;
        if (!classify_pdata(image, pdata, classification, error)) return fail(error);
        const auto ms_classify = phase_ms();

        auto insn = disasm::malloc_insn(get_ctx().hcs);
        if (!insn) return fail("cannot allocate a capstone instruction");
        Descender descender{module, image, *insn};

        for (const auto &span: classification.primaries) descender.reserve_span(span);
        for (const auto &fragment: classification.fragments) descender.reserve_span(fragment.span);
        const auto ms_reserve = phase_ms();

        // Entry-order: primaries ascending with their owned fragments, then the
        // remaining seeds.
        std::unordered_map<uint64_t, std::vector<FunctionSpan>> fragments_by_owner;
        for (const auto &fragment: classification.fragments) {
            if (fragment.owner != 0) fragments_by_owner[fragment.owner].push_back(fragment.span);
        }
        for (auto &[owner, list]: fragments_by_owner) {
            (void) owner;
            std::sort(list.begin(), list.end(),
                      [](const FunctionSpan &l, const FunctionSpan &r) { return l.start < r.start; });
        }

        std::vector<uint64_t> known_starts;
        known_starts.reserve(classification.primaries.size() * 2 + 64);
        for (const auto &span: classification.primaries) known_starts.push_back(span.start);
        for (const auto &fragment: classification.fragments) known_starts.push_back(fragment.span.start);
        std::sort(known_starts.begin(), known_starts.end());
        known_starts.erase(std::unique(known_starts.begin(), known_starts.end()), known_starts.end());

        for (const auto &span: classification.primaries) {
            descender.walk(span.start, span.end, span.start);
            if (const auto owned = fragments_by_owner.find(span.start);
                owned != fragments_by_owner.end()) {
                for (const auto &fragment: owned->second) {
                    descender.walk(fragment.start, fragment.end, span.start);
                }
            }
        }

        const auto ms_primitives = phase_ms();
        // Seeds without unwind metadata: validate the first instruction, resolve
        // entry thunks, and only then accept the real body.
        std::vector<uint64_t> seed_entries;
        {
            std::vector<uint64_t> seed_pool = export_seeds(image);
            if (image.address_of_entry_point != 0 &&
                image.rva_in_exec_section(image.address_of_entry_point)) {
                seed_pool.push_back(image.base + image.address_of_entry_point);
            }
            size_t tls_seeds = 0;
            {
                std::vector<uint64_t> tls;
                if (read_tls_seeds(image, tls)) {
                    tls_seeds = tls.size();
                    seed_pool.insert(seed_pool.end(), tls.begin(), tls.end());
                } else if (image.directories[kDirectoryTls].rva != 0) {
                    if (log) {
                        log->warn("discover_pe_x64: unusable TLS callback table ({})", path);
                    }
                }
            }
            std::sort(seed_pool.begin(), seed_pool.end());
            seed_pool.erase(std::unique(seed_pool.begin(), seed_pool.end()), seed_pool.end());
            for (const uint64_t seed: seed_pool) {
                const int section = image.exec_section_of(seed);
                if (section < 0) continue;
                if (descender.reserved_at(seed)) continue;// unwind record start/interior
                if (descender.claimed_at(seed)) continue;
                const auto &ranges = image.sections[static_cast<size_t>(section)];
                if (!descender.decode_first(seed, static_cast<size_t>(ranges.end - seed))) continue;
                uint64_t entry = seed;
                if (is_entry_thunk(descender.instruction)) {
                    entry = resolve_pe_discovery_target(module, seed, descender.instruction);
                    if (entry == 0) continue;
                    if (entry != seed) {
                        if (descender.reserved_at(entry) || descender.claimed_at(entry)) continue;
                        if (image.exec_section_of(entry) < 0) continue;
                    }
                }
                seed_entries.push_back(entry);
            }
            std::sort(seed_entries.begin(), seed_entries.end());
            seed_entries.erase(std::unique(seed_entries.begin(), seed_entries.end()), seed_entries.end());
            if (log) {
                log->info("discover_pe_x64: {} seeds ({} TLS) ({})", seed_entries.size(), tls_seeds, path);
            }
        }

        std::vector<FunctionSpan> adopted;
        const auto entry_bound = [&](uint64_t entry) {
            const int section = image.exec_section_of(entry);
            uint64_t bound = (std::min)(image.sections[static_cast<size_t>(section)].end,
                                        saturating_add(entry, kUnwindFreeCap));
            const auto next = std::upper_bound(known_starts.begin(), known_starts.end(), entry);
            if (next != known_starts.end()) bound = (std::min)(bound, *next);
            return bound > entry ? bound : image.sections[static_cast<size_t>(section)].end;
        };
        const auto scan_entries = [&](const std::vector<uint64_t> &entries) {
            for (const uint64_t entry: entries) insert_sorted(known_starts, entry);
            for (const uint64_t entry: entries) {
                if (descender.claimed_at(entry) || descender.reserved_at(entry)) continue;
                const uint64_t end = descender.walk(entry, entry_bound(entry), entry);
                if (end > entry) adopted.push_back({entry, end});
            }
        };

        scan_entries(seed_entries);
        const auto ms_seeds = phase_ms();

        const auto collect_candidates = [&](std::vector<uint64_t> raw) {
            std::sort(raw.begin(), raw.end());
            raw.erase(std::unique(raw.begin(), raw.end()), raw.end());
            std::vector<uint64_t> accepted;
            accepted.reserve(raw.size());
            for (const uint64_t target: raw) {
                const int section = image.exec_section_of(target);
                if (section < 0) continue;// outside executable sections
                if (descender.claimed_at(target) || descender.reserved_at(target)) continue;
                const auto &ranges = image.sections[static_cast<size_t>(section)];
                if (!descender.decode_first(target, static_cast<size_t>(ranges.end - target))) continue;
                uint64_t entry = target;
                if (is_entry_thunk(descender.instruction)) {
                    entry = resolve_pe_discovery_target(module, target, descender.instruction);
                    if (entry == 0) continue;
                    if (entry != target) {
                        if (descender.claimed_at(entry) || descender.reserved_at(entry)) continue;
                        if (image.exec_section_of(entry) < 0) continue;
                    }
                }
                accepted.push_back(entry);
            }
            std::sort(accepted.begin(), accepted.end());
            accepted.erase(std::unique(accepted.begin(), accepted.end()), accepted.end());
            return accepted;
        };

        for (int round = 0; round < kMaxAdoptRounds; ++round) {
            std::vector<uint64_t> raw;
            raw.swap(descender.pending);
            if (raw.empty()) break;
            const auto candidates = collect_candidates(std::move(raw));
            if (candidates.empty()) break;
            scan_entries(candidates);
        }
        const auto ms_rounds = phase_ms();

        // Assemble: `.text` primaries keep their exact unwind bounds, adopted
        // entries end at their furthest decoded instruction, and only fragments of
        // installed primaries survive.
        for (const auto &span: classification.primaries) {
            if (module.in_text(span.start)) spans.push_back(span);
        }
        for (const auto &span: adopted) {
            if (!module.in_text(span.start)) continue;
            if (descender.reserved_at(span.start)) continue;
            spans.push_back(span);
        }
        std::sort(spans.begin(), spans.end(),
                  [](const FunctionSpan &l, const FunctionSpan &r) { return l.start < r.start; });
        spans.erase(std::unique(spans.begin(), spans.end(),
                                [](const FunctionSpan &l, const FunctionSpan &r) {
                                    return l.start == r.start;
                                }),
                    spans.end());

        for (const auto &fragment: classification.fragments) {
            if (fragment.owner == 0) continue;
            if (!module.in_text(fragment.owner)) continue;
            fragments.push_back(fragment);
        }

        if (log) {
            log->info("discover_pe_x64 timing: pdata={} classify={} reserve={} primaries={} seeds={} "
                      "rounds={} total={} ms", ms_pdata, ms_classify - ms_pdata,
                      ms_reserve - ms_classify, ms_primitives - ms_reserve, ms_seeds - ms_primitives,
                      ms_rounds - ms_seeds, phase_ms());
            log->info("discover_pe_x64: {} primaries, {} chained merged, {} orphan fragments, "
                      "{} seeds, {} adopted, {} spans, {} bytes covered, {} budget trips ({})",
                      classification.primary_count, classification.chained_merged,
                      classification.chained_orphan, seed_entries.size(), adopted.size(),
                      spans.size(), descender.covered_bytes, descender.budget_trips, path);
        }
        if (spans.empty()) return fail("no function entries discovered");
        return true;
    }

#else

    bool discover_pe_x64(const ModuleSections &module, std::vector<FunctionSpan> &spans,
                         std::vector<FunctionFragment> &fragments) {
        (void) module;
        spans.clear();
        fragments.clear();
        return false;
    }

#endif

}// namespace function_relocation::detail
