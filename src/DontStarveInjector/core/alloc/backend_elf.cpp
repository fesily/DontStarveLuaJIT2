// Linux backend: rewrite the import slots of every non-system image we are
// allowed to touch. The game and its plugins call malloc/free through their own
// .got/.got.plt, so per-module all-or-nothing rewriting keeps a module's
// producers and consumers in the same heap domain.

#include "AllocShim.hpp"

#if defined(__linux__)

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstring>

#if defined(__LP64__)
#define DS_ELF_R_TYPE(info) ELF64_R_TYPE(info)
#define DS_ELF_R_SYM(info) ELF64_R_SYM(info)
#else
#define DS_ELF_R_TYPE(info) ELF32_R_TYPE(info)
#define DS_ELF_R_SYM(info) ELF32_R_SYM(info)
#endif

namespace ds::alloc::detail {
    namespace {

        constexpr size_t kMaxPatches = 256;
        constexpr size_t kMaxPages = 32;

        struct Patch {
            void **slot;
            void *shim;
        };

        struct PageDesc {
            uintptr_t address;
            int prot;
        };

        struct ScanContext {
            bool patch_all;
            size_t patched;
            size_t failed;
            bool primary_patched;
        };

        size_t page_size() {
            static const size_t value = [] {
                const long queried = sysconf(_SC_PAGESIZE);
                return queried > 0 ? static_cast<size_t>(queried) : static_cast<size_t>(4096);
            }();
            return value;
        }

        uintptr_t align_down(uintptr_t value) {
            return value & ~(static_cast<uintptr_t>(page_size()) - 1);
        }

        bool is_system_module(const char *name) {
            if (name == nullptr || name[0] == '\0') return false;// main program
            static constexpr const char *kPrefixes[] = {
                    "/lib/", "/lib32/", "/lib64/", "/libx32/",
                    "/usr/lib/", "/usr/lib32/", "/usr/lib64/", "/usr/libx32/",
                    "/usr/local/lib/",
            };
            for (const char *prefix: kPrefixes) {
                if (std::strncmp(name, prefix, std::strlen(prefix)) == 0) return true;
            }
            return false;
        }

        // mprotect() does not report the previous protection, so derive it from the
        // mapping itself: PT_LOAD flags give the page's normal rights, and pages that
        // ld.so locked down after relocation (PT_GNU_RELRO) come back read-only.
        int page_protection(const struct dl_phdr_info &info, uintptr_t address) {
            int prot = PROT_READ;
            for (size_t i = 0; i < info.dlpi_phnum; ++i) {
                const auto &phdr = info.dlpi_phdr[i];
                if (phdr.p_type != PT_LOAD) continue;
                const auto start = static_cast<uintptr_t>(info.dlpi_addr) + phdr.p_vaddr;
                if (address < start || address >= start + phdr.p_memsz) continue;
                prot = 0;
                if ((phdr.p_flags & PF_R) != 0) prot |= PROT_READ;
                if ((phdr.p_flags & PF_W) != 0) prot |= PROT_WRITE;
                if ((phdr.p_flags & PF_X) != 0) prot |= PROT_EXEC;
                break;
            }
            for (size_t i = 0; i < info.dlpi_phnum; ++i) {
                const auto &phdr = info.dlpi_phdr[i];
                if (phdr.p_type != PT_GNU_RELRO) continue;
                const auto start = align_down(static_cast<uintptr_t>(info.dlpi_addr) + phdr.p_vaddr);
                const auto end = static_cast<uintptr_t>(info.dlpi_addr) + phdr.p_vaddr + phdr.p_memsz;
                if (address >= start && address < end) prot &= ~PROT_WRITE;
            }
            return prot;
        }

        const SlotDesc *match_slot(const char *name) {
            for (const auto &slot: kPosixSlots) {
                if (std::strcmp(slot.name, name) == 0) return &slot;
            }
            return nullptr;
        }

        bool resolve_originals(ProviderOrig &prov) {
#ifdef RTLD_NOLOAD
            void *handle = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
#else
            void *handle = nullptr;
#endif
            const auto lookup = [handle](const char *name) -> void * {
                void *symbol = handle != nullptr ? dlsym(handle, name) : nullptr;
                if (symbol == nullptr) symbol = dlsym(RTLD_DEFAULT, name);
                return symbol;
            };

            prov.malloc_fn = reinterpret_cast<void *(*)(size_t)>(lookup("malloc"));
            prov.calloc_fn = reinterpret_cast<void *(*)(size_t, size_t)>(lookup("calloc"));
            prov.realloc_fn = reinterpret_cast<void *(*)(void *, size_t)>(lookup("realloc"));
            prov.free_fn = reinterpret_cast<void (*)(void *)>(lookup("free"));
            prov.reallocarray_fn = reinterpret_cast<void *(*)(void *, size_t, size_t)>(lookup("reallocarray"));
            prov.posix_memalign_fn = reinterpret_cast<int (*)(void **, size_t, size_t)>(lookup("posix_memalign"));
            prov.aligned_alloc_fn = reinterpret_cast<void *(*)(size_t, size_t)>(lookup("aligned_alloc"));
            prov.memalign_fn = reinterpret_cast<void *(*)(size_t, size_t)>(lookup("memalign"));
            prov.valloc_fn = reinterpret_cast<void *(*)(size_t)>(lookup("valloc"));
            prov.strdup_fn = reinterpret_cast<char *(*)(const char *)>(lookup("strdup"));
            prov.module = "libc";
            return prov.malloc_fn != nullptr && prov.calloc_fn != nullptr &&
                   prov.realloc_fn != nullptr && prov.free_fn != nullptr;
        }

        int scan_module(struct dl_phdr_info *info, size_t, void *data) {
            auto &ctx = *static_cast<ScanContext *>(data);
            const bool primary = info->dlpi_name == nullptr || info->dlpi_name[0] == '\0';
            if (!primary) {
                if (!ctx.patch_all) return 0;
                if (is_system_module(info->dlpi_name)) return 0;
            }

            const ElfW(Phdr) *dynamic = nullptr;
            for (size_t i = 0; i < info->dlpi_phnum; ++i) {
                if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                    dynamic = &info->dlpi_phdr[i];
                    break;
                }
            }
            if (dynamic == nullptr || dynamic->p_memsz < sizeof(ElfW(Dyn))) return 0;

            const auto *dyn = reinterpret_cast<const ElfW(Dyn) *>(info->dlpi_addr + dynamic->p_vaddr);

            ElfW(Addr) symtab = 0;
            ElfW(Addr) strtab = 0;
            ElfW(Addr) jmprel = 0;
            ElfW(Addr) rela = 0;
            ElfW(Addr) rel = 0;
            size_t pltrelsz = 0;
            size_t relasz = 0;
            size_t relsz = 0;
            ElfW(Sxword) pltrel = DT_RELA;
            for (const auto *entry = dyn; entry->d_tag != DT_NULL; ++entry) {
                switch (entry->d_tag) {
                    case DT_SYMTAB: symtab = entry->d_un.d_ptr; break;
                    case DT_STRTAB: strtab = entry->d_un.d_ptr; break;
                    case DT_JMPREL: jmprel = entry->d_un.d_ptr; break;
                    case DT_PLTRELSZ: pltrelsz = entry->d_un.d_val; break;
                    case DT_PLTREL: pltrel = entry->d_un.d_val; break;
                    case DT_RELA: rela = entry->d_un.d_ptr; break;
                    case DT_RELASZ: relasz = entry->d_un.d_val; break;
                    case DT_REL: rel = entry->d_un.d_ptr; break;
                    case DT_RELSZ: relsz = entry->d_un.d_val; break;
                    default: break;
                }
            }
            if (symtab == 0 || strtab == 0) return 0;

            // glibc relocates the DT_* pointers of a writable dynamic segment in place;
            // a loader that leaves the segment read-only hands out load-relative values.
            const bool pointers_absolute = (dynamic->p_flags & PF_W) != 0;
            const auto adjust = [&](ElfW(Addr) value) -> uintptr_t {
                return pointers_absolute ? static_cast<uintptr_t>(value)
                                         : static_cast<uintptr_t>(info->dlpi_addr + value);
            };

            const auto *symbols = reinterpret_cast<const ElfW(Sym) *>(adjust(symtab));
            const auto *strings = reinterpret_cast<const char *>(adjust(strtab));

            Patch patches[kMaxPatches];
            size_t count = 0;
            bool overflow = false;

            const auto handle_reloc = [&](const auto &reloc) {
                const auto symbol_index = DS_ELF_R_SYM(reloc.r_info);
                const SlotDesc *desc = match_slot(strings + symbols[symbol_index].st_name);
                if (desc == nullptr) return;
                void *replacement = shim_entry(0, desc->kind);
                if (replacement == nullptr) return;
                auto *slot = reinterpret_cast<void **>(static_cast<uintptr_t>(info->dlpi_addr) + reloc.r_offset);
                if (*slot == replacement) return;// rescan: slot already carries our entry
                if (count == kMaxPatches) {
                    overflow = true;
                    return;
                }
                patches[count++] = {slot, replacement};
            };

            const auto walk = [&](const auto *entries, size_t bytes, unsigned expected_type) {
                if (entries == nullptr || bytes == 0) return;
                const size_t total = bytes / sizeof(*entries);
                for (size_t i = 0; i < total; ++i) {
                    if (DS_ELF_R_TYPE(entries[i].r_info) != expected_type) continue;
                    handle_reloc(entries[i]);
                }
            };

#if defined(__x86_64__)
            constexpr unsigned kJumpSlot = R_X86_64_JUMP_SLOT;
            constexpr unsigned kGlobDat = R_X86_64_GLOB_DAT;
#elif defined(__aarch64__)
            constexpr unsigned kJumpSlot = R_AARCH64_JUMP_SLOT;
            constexpr unsigned kGlobDat = R_AARCH64_GLOB_DAT;
#else
            constexpr unsigned kJumpSlot = 0;
            constexpr unsigned kGlobDat = 0;
#endif

            if (jmprel != 0 && pltrelsz != 0) {
                if (pltrel == DT_RELA) {
                    walk(reinterpret_cast<const ElfW(Rela) *>(adjust(jmprel)), pltrelsz, kJumpSlot);
                } else {
                    walk(reinterpret_cast<const ElfW(Rel) *>(adjust(jmprel)), pltrelsz, kJumpSlot);
                }
            }
            if (rela != 0) walk(reinterpret_cast<const ElfW(Rela) *>(adjust(rela)), relasz, kGlobDat);
            if (rel != 0) walk(reinterpret_cast<const ElfW(Rel) *>(adjust(rel)), relsz, kGlobDat);

            if (count == 0) return 0;

            // All-or-nothing per module: resolve every page first, then make the whole
            // set writable before touching any slot.
            PageDesc pages[kMaxPages];
            size_t page_count = 0;
            for (size_t i = 0; i < count; ++i) {
                const auto first = align_down(reinterpret_cast<uintptr_t>(patches[i].slot));
                const auto last = align_down(reinterpret_cast<uintptr_t>(patches[i].slot) + sizeof(void *) - 1);
                for (auto address = first; address <= last; address += page_size()) {
                    bool known = false;
                    for (size_t p = 0; p < page_count; ++p) {
                        if (pages[p].address == address) {
                            known = true;
                            break;
                        }
                    }
                    if (known) continue;
                    if (page_count == kMaxPages) {
                        overflow = true;
                        break;
                    }
                    pages[page_count++] = {address, page_protection(*info, address)};
                }
            }
            if (overflow) {
                note_failure();
                ++ctx.failed;
                return 0;
            }

            bool writable = true;
            for (size_t p = 0; p < page_count; ++p) {
                if (mprotect(reinterpret_cast<void *>(pages[p].address), page_size(), PROT_READ | PROT_WRITE) != 0) {
                    writable = false;
                }
            }
            if (writable) {
                for (size_t i = 0; i < count; ++i) {
                    __atomic_store_n(patches[i].slot, patches[i].shim, __ATOMIC_RELEASE);
                }
            }
            for (size_t p = 0; p < page_count; ++p) {
                (void) mprotect(reinterpret_cast<void *>(pages[p].address), page_size(), pages[p].prot);
            }
            if (!writable) {
                note_failure();
                ++ctx.failed;
                return 0;
            }

            ctx.patched += count;
            note_patched(count);
            if (primary) {
                ctx.primary_patched = true;
                note_primary_target();
            }
            return 0;
        }

    }// namespace

    bool install_platform_hooks(const Options &opts) {
        set_backend(Backend::ElfGot);
        auto &prov = provider_slot(0);
        if (prov.free_fn == nullptr && !resolve_originals(prov)) {
            note_failure();
            return false;
        }

        ScanContext ctx{opts.patch_all_modules, 0, 0, false};
        dl_iterate_phdr(scan_module, &ctx);
        if (ctx.patched == 0) {
            note_failure();
            return false;
        }
        prov.active = true;
        return true;
    }

    void rescan_modules() noexcept {
        auto &prov = provider_slot(0);
        if (!prov.active) return;
        ScanContext ctx{true, 0, 0, false};
        dl_iterate_phdr(scan_module, &ctx);
    }

}// namespace ds::alloc::detail

#undef DS_ELF_R_TYPE
#undef DS_ELF_R_SYM

#endif// __linux__
