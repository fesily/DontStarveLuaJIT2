#include "DontStarveSignature.hpp"
#include "Signature.hpp"
#include "FunctionRanges.hpp"
#include "MemorySignature.hpp"
#include "ModuleSections.hpp"
#include "NucleusAdapter.hpp"
#include "ctx.hpp"
#include "UniqueSignature.hpp"
#include "util/LinuxGameSignatures.hpp"

#include <elf.h>
#include <sys/mman.h>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace {

    // Map data only: no game code, constructors, Steam, or game-directory writes.
    class ElfImage {
        std::vector<uint8_t> file;
        uint8_t *mapping = nullptr;
        size_t mapping_size = 0;
        uintptr_t preferred_base = 0;

        template<class T>
        T read(size_t offset) const {
            if (offset > file.size() || sizeof(T) > file.size() - offset) throw std::runtime_error("truncated ELF");
            T result;
            std::memcpy(&result, file.data() + offset, sizeof(T));
            return result;
        }

    public:
        function_relocation::ModuleSections module;
        ListExports_t exports;

        explicit ElfImage(const char *path) {
            std::ifstream stream(path, std::ios::binary);
            file.assign(std::istreambuf_iterator<char>(stream), {});
            const auto header = read<Elf64_Ehdr>(0);
            if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) || header.e_ident[EI_CLASS] != ELFCLASS64 ||
                header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64) throw std::runtime_error("need ELF x64");
            preferred_base = UINTPTR_MAX;
            uint64_t end = 0;
            for (size_t i = 0; i < header.e_phnum; ++i) {
                const auto ph = read<Elf64_Phdr>(header.e_phoff + i * header.e_phentsize);
                if (ph.p_type != PT_LOAD) continue;
                preferred_base = std::min(preferred_base, uintptr_t(ph.p_vaddr & ~uint64_t{0xfff}));
                end = std::max(end, ph.p_vaddr + ph.p_memsz);
            }
            if (preferred_base == UINTPTR_MAX || end <= preferred_base || end - preferred_base > 512 * 1024 * 1024)
                throw std::runtime_error("invalid ELF mapping");
            mapping_size = end - preferred_base;
            mapping = static_cast<uint8_t *>(mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
            if (mapping == MAP_FAILED) throw std::runtime_error("mmap failed");
            for (size_t i = 0; i < header.e_phnum; ++i) {
                const auto ph = read<Elf64_Phdr>(header.e_phoff + i * header.e_phentsize);
                if (ph.p_type != PT_LOAD) continue;
                if (ph.p_offset > file.size() || ph.p_filesz > file.size() - ph.p_offset || ph.p_filesz > ph.p_memsz)
                    throw std::runtime_error("invalid ELF segment");
                std::memcpy(mapping + ph.p_vaddr - preferred_base, file.data() + ph.p_offset, ph.p_filesz);
            }
            const uintptr_t bias = reinterpret_cast<uintptr_t>(mapping) - preferred_base;
            // Reproduce the loader's internal GOT targets. Without this, a PIC
            // training library's calls through its own PLT lose the Lua call graph.
            for (size_t i = 0; i < header.e_shnum; ++i) {
                const auto sh = read<Elf64_Shdr>(header.e_shoff + i * header.e_shentsize);
                if (sh.sh_type != SHT_RELA || sh.sh_entsize != sizeof(Elf64_Rela)) continue;
                const auto symbols = read<Elf64_Shdr>(header.e_shoff + sh.sh_link * header.e_shentsize);
                for (size_t off = 0; off + sizeof(Elf64_Rela) <= sh.sh_size; off += sh.sh_entsize) {
                    const auto reloc = read<Elf64_Rela>(sh.sh_offset + off);
                    const auto type = ELF64_R_TYPE(reloc.r_info);
                    if (type != R_X86_64_RELATIVE && type != R_X86_64_JUMP_SLOT &&
                        type != R_X86_64_GLOB_DAT && type != R_X86_64_64) continue;
                    if (reloc.r_offset < preferred_base || reloc.r_offset - preferred_base + 8 > mapping_size)
                        throw std::runtime_error("invalid ELF relocation");
                    uintptr_t value = 0;
                    if (type == R_X86_64_RELATIVE) value = bias + reloc.r_addend;
                    else {
                        const auto sym = read<Elf64_Sym>(symbols.sh_offset + ELF64_R_SYM(reloc.r_info) * symbols.sh_entsize);
                        if (sym.st_shndx != SHN_UNDEF) value = bias + sym.st_value + reloc.r_addend;
                    }
                    std::memcpy(mapping + reloc.r_offset - preferred_base, &value, sizeof(value));
                }
            }
            mprotect(mapping, mapping_size, PROT_READ);
            module.details = {std::filesystem::path{path}.filename().string(), {reinterpret_cast<uintptr_t>(mapping), mapping_size}, path};
            const auto names = read<Elf64_Shdr>(header.e_shoff + header.e_shstrndx * header.e_shentsize);
            for (size_t i = 0; i < header.e_shnum; ++i) {
                const auto sh = read<Elf64_Shdr>(header.e_shoff + i * header.e_shentsize);
                if (names.sh_offset + sh.sh_name >= file.size()) throw std::runtime_error("invalid ELF section name");
                const std::string name{reinterpret_cast<const char *>(file.data() + names.sh_offset + sh.sh_name)};
                if (sh.sh_flags & SHF_ALLOC) {
                    GumMemoryRange range{bias + sh.sh_addr, sh.sh_size};
                    module.sections[name] = range;
                    if (name == ".text") module.text = range;
                    else if (name == ".rodata")
                        module.rodata = range;
                    else if (name == ".plt")
                        module.plt = range;
                    else if (name == ".got.plt")
                        module.got_plt = range;
                    else if (name == ".bss")
                        module.bss = range;
                }
                if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) continue;
                const auto strings = read<Elf64_Shdr>(header.e_shoff + sh.sh_link * header.e_shentsize);
                for (size_t off = 0; off + sizeof(Elf64_Sym) <= sh.sh_size; off += sh.sh_entsize) {
                    const auto sym = read<Elf64_Sym>(sh.sh_offset + off);
                    if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_shndx == SHN_UNDEF || sym.st_name >= strings.sh_size) continue;
                    const std::string symbol{reinterpret_cast<const char *>(file.data() + strings.sh_offset + sym.st_name)};
                    module.symbol_names[bias + sym.st_value] = symbol;
                    if (sh.sh_type == SHT_DYNSYM && is_lua_signature_export(symbol)) exports.emplace_back(symbol, bias + sym.st_value);
                }
            }
            std::ranges::sort(exports, [](const auto &a, const auto &b) { return a.second > b.second; });
        }

        ~ElfImage() {
            if (mapping && mapping != MAP_FAILED) munmap(mapping, mapping_size);
        }
        ElfImage(const ElfImage &) = delete;

        void analyze() {
            auto table = function_relocation::nucleus_analyze_file(module.details.path);
            if (!table) throw std::runtime_error(table.error());
            if (table->image_base != preferred_base) throw std::runtime_error("incorrect ELF image base");
            if (!function_relocation::apply_nucleus_function_table(module, table->table, table->image_base) ||
                !function_relocation::scan_module_function_features(module)) throw std::runtime_error("function analysis failed");
        }
    };

    uintptr_t verify_pattern(ElfImage &image, const char *name, const char *pattern) {
        function_relocation::MemorySignature sig{pattern, 0};
        sig.log = false;
        if (!sig.scan(image.module.text.base_address, image.module.text.size)) throw std::runtime_error(std::string{name} + " is missing or ambiguous");
        const auto entry = function_relocation::resolve_function_entry(image.module, sig.target_address);
        if (!entry) throw std::runtime_error(std::string{name} + " is not at an instruction boundary in an FDE");
        std::cout << name << " entry RVA=0x" << std::hex << entry - image.module.details.range.base_address << std::dec << '\n';
        return entry;
    }

}// namespace

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        std::cerr << "usage: verify_linux_signatures lua51.so game_binary [output.json|--check-cache]\n";
        return 2;
    }
    gum_init_embedded();
    if (!function_relocation::init_ctx()) return 1;
    spdlog::set_level(spdlog::level::warn);
    const bool check_cache = argc == 4 && std::string_view{argv[3]} == "--check-cache";
    try {
        ElfImage train{argv[1]}, game{argv[2]};
        const auto base = verify_pattern(game, "index2adr", ds::linux_signatures::lua_module);
        verify_pattern(game, "luaopen_getsize", ds::linux_signatures::register_debug_getsize);
        verify_pattern(game, "execution_error", ds::linux_signatures::execution_error);
        verify_pattern(game, "FrameProfiler::Push", ds::linux_signatures::profiler_push);
        verify_pattern(game, "FrameProfiler::Push singleton", ds::linux_signatures::profiler_push_singleton);
        verify_pattern(game, "FrameProfiler::Pop", ds::linux_signatures::profiler_pop);
        const auto scan_range = function_relocation::signature_search_range(game.module, base);
        train.analyze();
        game.analyze();
        if (std::getenv("DS_SIGNATURE_DEBUG")) {
            for (const auto &[name, address]: train.exports) {
                const auto *fn = train.module.find_function(address);
                std::cout << "train " << name << " RVA=" << std::hex << address - train.module.details.range.base_address
                          << std::dec << " size=" << (fn ? fn->size : 0) << '\n';
            }
        }
        Signatures signatures{};
        for (const auto &[name, address]: train.exports) signatures.funcs[name] = {};
        auto error = resolve_lua_signatures_from_modules(signatures, base, train.exports, train.module, game.module);
        if (!error.empty()) throw std::runtime_error(error);
        if (check_cache) {
            const auto expected = signatures.funcs;
            // A legacy cache can be locally correct at its RVA yet ambiguous
            // elsewhere. Inject that case and require update to certify/repair
            // it instead of accepting the narrow local match.
            auto &legacy = signatures.funcs.at("lua_gettop");
            const uintptr_t entry = base + legacy.offset;
            const auto first = *reinterpret_cast<const uint8_t *>(entry);
            constexpr char hex[] = "0123456789abcdef";
            legacy.pattern = std::string{hex[first >> 4], hex[first & 15]};
            legacy.pattern_offset = 0;
            function_relocation::MemorySignature local{legacy.pattern.c_str(), 0};
            local.log = false;
            if (local.scan(entry, 1) != entry ||
                function_relocation::validate_unique_signature({&scan_range, 1}, legacy, entry))
                throw std::runtime_error("invalid ambiguous-cache regression fixture");
            // A new update starts with no target labels. Rebuild both module
            // tables so the fresh pass cannot mask a missing registration.
            train.analyze();
            game.analyze();
            error = resolve_lua_signatures_from_modules(signatures, base, train.exports, train.module, game.module);
            if (!error.empty()) throw std::runtime_error(error);
            for (const auto &[name, previous]: expected) {
                const auto &updated = signatures.funcs.at(name);
                if (updated.offset != previous.offset) {
                    throw std::runtime_error("cached update changed " + name + " offset " +
                                             std::to_string(previous.offset) + " -> " + std::to_string(updated.offset));
                }
            }
            std::cout << "cached update preserved " << expected.size() << " Lua entry offsets\n";
            std::cout << "ambiguous legacy cache repaired and verified from Lua base\n";
        }
        nlohmann::json funcs = nlohmann::json::object();
        for (const auto &[name, sig]: signatures.funcs) {
            const uintptr_t entry = base + sig.offset;
            if (!function_relocation::validate_unique_signature({&scan_range, 1}, sig, entry)) {
                std::cerr << name << " offset=" << sig.offset << " pattern_offset=" << sig.pattern_offset << " pattern=" << sig.pattern << '\n';
                throw std::runtime_error("pattern is missing, ambiguous or targets another entry: " + name);
            }
            if (function_relocation::resolve_function_entry(game.module, entry) != entry) throw std::runtime_error("not an FDE entry: " + name);
            funcs[name] = {{"offset", sig.offset}, {"pattern", sig.pattern}, {"pattern_offset", sig.pattern_offset}};
        }
        std::cout << "resolved and verified " << funcs.size() << " Lua export patterns unique from Lua base\n";
        if (argc == 4 && !check_cache) {
            std::ifstream version(std::filesystem::path{argv[2]}.parent_path().parent_path() / "version.txt");
            uintptr_t value = 0;
            if (!(version >> value)) throw std::runtime_error("cannot read game version");
            std::ofstream output(argv[3]);
            output << nlohmann::json{{"version", value}, {"funcs", funcs}}.dump() << '\n';
            if (!output) throw std::runtime_error("cannot write signatures");
        }
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    function_relocation::deinit_ctx();
    gum_deinit_embedded();
}
