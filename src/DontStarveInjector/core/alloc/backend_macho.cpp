// macOS backend: rewrite the symbol-pointer slots (__got / __la_symbol_ptr) of
// every non-system image. Slot identity comes from the indirect symbol table,
// which both LC_DYLD_INFO and LC_DYLD_CHAINED_FIXUPS images still carry; slots
// that cannot be named that way are matched by comparing the already-bound
// pointer against the original libSystem entry. Memory is never reinterpreted as
// a chained-fixup bit field: by the time the image is loaded those words are
// ordinary pointers (or dyld_stub_binder, which the name match still resolves).

#include "AllocShim.hpp"

#if defined(__APPLE__)

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <sys/mman.h>

#include <cstring>

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
            vm_prot_t prot;
        };

        struct SegmentInfo {
            uint64_t vmaddr = 0;
            uint64_t fileoff = 0;
            uint64_t filesize = 0;
            bool present = false;
        };

        bool is_system_image(const char *install_name) {
            if (install_name == nullptr) return false;// main executable has no LC_ID_DYLIB
            return std::strncmp(install_name, "/usr/lib/", 9) == 0 ||
                   std::strncmp(install_name, "/System/", 8) == 0;
        }

        // Bound import names carry the C underscore ("_malloc"); the slot table uses
        // the plain C name.
        const SlotDesc *match_slot(const char *symbol) {
            if (symbol == nullptr || symbol[0] != '_') return nullptr;
            const char *plain = symbol + 1;
            for (const auto &slot: kPosixSlots) {
                if (std::strcmp(slot.name, plain) == 0) return &slot;
            }
            return nullptr;
        }

        bool resolve_originals(ProviderOrig &prov) {
#ifdef RTLD_NOLOAD
            void *handle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW | RTLD_NOLOAD);
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
            prov.posix_memalign_fn = reinterpret_cast<int (*)(void **, size_t, size_t)>(lookup("posix_memalign"));
            prov.aligned_alloc_fn = reinterpret_cast<void *(*)(size_t, size_t)>(lookup("aligned_alloc"));
            prov.memalign_fn = reinterpret_cast<void *(*)(size_t, size_t)>(lookup("memalign"));
            prov.valloc_fn = reinterpret_cast<void *(*)(size_t)>(lookup("valloc"));
            prov.strdup_fn = reinterpret_cast<char *(*)(const char *)>(lookup("strdup"));
            prov.module = "libSystem";
            return prov.malloc_fn != nullptr && prov.calloc_fn != nullptr &&
                   prov.realloc_fn != nullptr && prov.free_fn != nullptr;
        }

        // mprotect() cannot report the old rights and cannot express a copy-on-write
        // upgrade, so ask the kernel first and restore exactly what it reported.
        bool make_writable(void *address, size_t size, vm_prot_t &prot, vm_prot_t &max_prot) {
            vm_address_t region = reinterpret_cast<vm_address_t>(address);
            vm_size_t region_size = 0;
            vm_region_basic_info_data_64_t info{};
            mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t object_name = MACH_PORT_NULL;
            if (vm_region_64(mach_task_self(), &region, &region_size, VM_REGION_BASIC_INFO_64,
                             reinterpret_cast<vm_region_info_t>(&info), &info_count, &object_name) != KERN_SUCCESS) {
                return false;
            }
            prot = info.protection;
            max_prot = info.max_protection;

            if (mprotect(address, size, prot | VM_PROT_WRITE) == 0) return true;
            if ((max_prot & VM_PROT_WRITE) != 0 &&
                mach_vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(address), size, FALSE,
                                prot | VM_PROT_WRITE) == KERN_SUCCESS) {
                return true;
            }
            return mach_vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(address), size, FALSE,
                                   prot | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS;
        }

        void restore_protection(void *address, size_t size, vm_prot_t prot) {
            (void) mach_vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(address), size, FALSE, prot);
        }

        struct ImageScan {
            Patch *patches;
            size_t count;
            size_t capacity;
            bool overflow;
        };

        void consider_slot(ImageScan &scan, void **slot, const SlotDesc *desc) {
            if (desc == nullptr) return;
            void *replacement = shim_entry(0, desc->kind);
            if (replacement == nullptr) return;
            if (*slot == replacement) return;// rescan: already ours
            if (scan.count == scan.capacity) {
                scan.overflow = true;
                return;
            }
            scan.patches[scan.count++] = {slot, replacement};
        }

        // Slots whose indirect symbol is unusable are still recognisable: the image is
        // already loaded, so the word is the libSystem entry it was bound to.
        const SlotDesc *match_by_original(const void *value, const ProviderOrig &orig) {
            if (value == nullptr) return nullptr;
            for (const auto &slot: kPosixSlots) {
                if (slot.kind == SlotKind::Free && value == reinterpret_cast<const void *>(orig.free_fn)) return &slot;
                if (slot.kind == SlotKind::Realloc && value == reinterpret_cast<const void *>(orig.realloc_fn)) return &slot;
                if (slot.kind == SlotKind::Calloc && value == reinterpret_cast<const void *>(orig.calloc_fn)) return &slot;
            }
            return nullptr;
        }

        void scan_image(const struct mach_header *header, intptr_t slide) {
            auto &prov = provider_slot(0);
            if (!prov.active || header == nullptr) return;
            if (header->magic != MH_MAGIC_64) return;

            const auto *mh = reinterpret_cast<const struct mach_header_64 *>(header);
            const char *image_bytes = reinterpret_cast<const char *>(header);

            SegmentInfo linkedit{};
            const char *install_name = nullptr;
            const struct symtab_command *symtab = nullptr;
            const struct dysymtab_command *dysymtab = nullptr;

            const char *command = image_bytes + sizeof(struct mach_header_64);
            for (uint32_t i = 0; i < mh->ncmds; ++i) {
                const auto *load = reinterpret_cast<const struct load_command *>(command);
                if (load->cmdsize == 0) return;
                switch (load->cmd) {
                    case LC_SEGMENT_64: {
                        const auto *segment = reinterpret_cast<const struct segment_command_64 *>(load);
                        if (std::strcmp(segment->segname, "__LINKEDIT") == 0) {
                            linkedit = {segment->vmaddr, segment->fileoff, segment->filesize, true};
                        }
                        break;
                    }
                    case LC_SYMTAB:
                        symtab = reinterpret_cast<const struct symtab_command *>(load);
                        break;
                    case LC_DYSYMTAB:
                        dysymtab = reinterpret_cast<const struct dysymtab_command *>(load);
                        break;
                    case LC_ID_DYLIB: {
                        const auto *dylib = reinterpret_cast<const struct dylib_command *>(load);
                        install_name = image_bytes + dylib->dylib.name.offset;
                        break;
                    }
                    default:
                        break;
                }
                command += load->cmdsize;
            }

            if (is_system_image(install_name)) return;
            if (!linkedit.present || symtab == nullptr || dysymtab == nullptr) return;
            if (symtab->nsyms == 0 || dysymtab->nindirectsyms == 0) return;

            const char *linkedit_base = reinterpret_cast<const char *>(slide + linkedit.vmaddr);
            const auto file_to_memory = [&](uint32_t file_offset) {
                return linkedit_base + (file_offset - linkedit.fileoff);
            };

            const auto *symbols = reinterpret_cast<const struct nlist_64 *>(file_to_memory(symtab->symoff));
            const auto *strings = file_to_memory(symtab->stroff);
            const auto *indirect = reinterpret_cast<const uint32_t *>(file_to_memory(dysymtab->indirectsymoff));

            Patch patches[kMaxPatches];
            ImageScan scan{patches, 0, kMaxPatches, false};

            command = image_bytes + sizeof(struct mach_header_64);
            for (uint32_t i = 0; i < mh->ncmds; ++i) {
                const auto *load = reinterpret_cast<const struct load_command *>(command);
                if (load->cmd == LC_SEGMENT_64) {
                    const auto *segment = reinterpret_cast<const struct segment_command_64 *>(load);
                    const auto *section = reinterpret_cast<const struct section_64 *>(
                            reinterpret_cast<const char *>(segment) + sizeof(struct segment_command_64));
                    for (uint32_t s = 0; s < segment->nsects; ++s, ++section) {
                        const uint32_t type = section->flags & SECTION_TYPE;
                        if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) continue;
                        const size_t stride = sizeof(void *);
                        const size_t slot_count = section->size / stride;
                        const uint32_t indirect_index = section->reserved1;
                        auto *base = reinterpret_cast<void **>(slide + section->addr);
                        for (size_t slot_index = 0; slot_index < slot_count; ++slot_index) {
                            auto *slot = &base[slot_index];
                            const SlotDesc *desc = nullptr;
                            if (indirect_index + slot_index < dysymtab->nindirectsyms) {
                                const uint32_t symbol_index = indirect[indirect_index + slot_index];
                                if ((symbol_index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) == 0 &&
                                    symbol_index < symtab->nsyms) {
                                    desc = match_slot(strings + symbols[symbol_index].n_un.n_strx);
                                }
                            }
                            if (desc == nullptr) desc = match_by_original(*slot, prov);
                            consider_slot(scan, slot, desc);
                        }
                    }
                }
                command += load->cmdsize;
            }

            if (scan.count == 0 || scan.overflow) {
                if (scan.overflow) note_failure();
                return;
            }

            PageDesc pages[kMaxPages];
            size_t page_count = 0;
            const size_t page = static_cast<size_t>(getpagesize());
            bool ok = true;
            for (size_t i = 0; i < scan.count && ok; ++i) {
                const uintptr_t address = reinterpret_cast<uintptr_t>(scan.patches[i].slot);
                const uintptr_t first = address & ~(page - 1);
                if (page_count == kMaxPages) {
                    ok = false;
                    break;
                }
                bool known = false;
                for (size_t p = 0; p < page_count; ++p) {
                    if (pages[p].address == first) {
                        known = true;
                        break;
                    }
                }
                if (known) continue;
                vm_prot_t prot = VM_PROT_READ;
                vm_prot_t max_prot = VM_PROT_READ;
                if (!make_writable(reinterpret_cast<void *>(first), page, prot, max_prot)) {
                    ok = false;
                    break;
                }
                pages[page_count++] = {first, prot};
            }

            if (ok) {
                for (size_t i = 0; i < scan.count; ++i) {
                    __atomic_store_n(scan.patches[i].slot, scan.patches[i].shim, __ATOMIC_RELEASE);
                }
            }
            for (size_t p = 0; p < page_count; ++p) {
                restore_protection(reinterpret_cast<void *>(pages[p].address), page, pages[p].prot);
            }
            if (!ok) {
                note_failure();
                return;
            }
            note_patched(scan.count);
            // The main executable is the only image without LC_ID_DYLIB; asking dyld
            // for its header here would take the loader lock the callback already holds.
            if (install_name == nullptr) note_primary_target();
        }

    }// namespace

    bool install_platform_hooks(const Options &opts) {
        set_backend(Backend::MachO);
        auto &prov = provider_slot(0);
        if (prov.free_fn == nullptr && !resolve_originals(prov)) {
            note_failure();
            return false;
        }
        (void) opts;

        // Registration replays the callback for every already-loaded image while dyld
        // holds its lock, so no manual _dyld_image_count() pass is needed (that would
        // scan every image twice).
        prov.active = true;// callbacks run during registration
        _dyld_register_func_for_add_image(&scan_image);
        prov.active = patched_slot_count() != 0;
        if (!prov.active) note_failure();
        return prov.active;
    }

    // dyld reports additions through the callback above; removals need no cleanup
    // because the patches die with the image's pages.
    void rescan_modules() noexcept {
    }

}// namespace ds::alloc::detail

#endif// __APPLE__
