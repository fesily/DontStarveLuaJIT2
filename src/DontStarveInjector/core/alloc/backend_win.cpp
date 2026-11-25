// Windows backend: replace the CRT allocation entry points themselves.
//
// A pure IAT rewrite cannot cover this process: msvcp90.dll (WinSxS) allocates
// every std::string/std::vector through MSVCR90!??2 / ??3 / _malloc_crt, and
// inside msvcr90.dll those are relative call/jmp into free/malloc - no import
// slot is involved. Hooking free/malloc inside the CRT image is the only place
// that covers the game, msvcp90 and every plugin loaded later, and it is the
// same trick mimalloc-redirect plays for ucrtbase.

#include "AllocShim.hpp"

#ifdef _WIN32

#include "util/FastHook.hpp"

#include <frida-gum.h>
#include <windows.h>

namespace ds::alloc::detail {
    namespace {

        constexpr size_t kMaxModuleSlots = 32;

        struct InstalledTargets {
            void *targets[kMaxModuleSlots]{};
            size_t count = 0;

            void add(void *target) noexcept {
                if (count < kMaxModuleSlots) targets[count++] = target;
            }
        };

        enum class InstallOutcome : unsigned char { Installed, Absent, Failed };

        // FastHook resolves native jump thunks (ucrtbase realloc -> _realloc_base) at
        // install time, so a target may already be covered by the time the alias
        // spelling is offered. Anything else is a real failure: FastHook reports
        // ALREADY_REPLACED only for its own record, and a foreign gum hook answers
        // WRONG_TYPE instead.
        InstallOutcome install_named(GumInterceptor *interceptor, HMODULE module, const char *name, void *shim,
                                     void **orig, InstalledTargets &installed) noexcept {
            auto *target = reinterpret_cast<void *>(GetProcAddress(module, name));
            if (target == nullptr) return InstallOutcome::Absent;// this CRT build has no such entry
            // FastHook clears *original before it decides, including on the
            // ALREADY_REPLACED path: an alias that resolved to the entry we already
            // hooked must not wipe the trampoline that entry produced.
            void *const saved = orig != nullptr ? *orig : nullptr;
            const auto result = ds::FastHook::Install(interceptor, target, shim, orig);
            if (result == GUM_REPLACE_OK) {
                installed.add(target);
                return InstallOutcome::Installed;
            }
            if (orig != nullptr) *orig = saved;
            return result == GUM_REPLACE_ALREADY_REPLACED ? InstallOutcome::Installed : InstallOutcome::Failed;
        }

        bool install_slot(GumInterceptor *interceptor, HMODULE module, const SlotDesc &slot, size_t provider,
                          InstalledTargets &installed) noexcept {
            auto &prov = provider_slot(provider);
            void *shim = shim_entry(provider, slot.kind);
            void **orig = orig_slot(prov, slot.kind);
            if (shim == nullptr || orig == nullptr) return false;

            // Name first, alias second: the alias is the lower-level implementation,
            // so the provider's stored trampoline ends up pointing at the bottom of
            // the chain. Reversing this would let the alias trampoline re-enter the
            // name entry that is already redirected to the shim.
            const auto primary = install_named(interceptor, module, slot.name, shim, orig, installed);
            if (primary != InstallOutcome::Installed) return false;
            if (slot.alias == nullptr) return true;
            // A CRT exposing only one of the two spellings is fine; a spelling that
            // exists but refuses the hook would leave an unhooked link in the chain.
            return install_named(interceptor, module, slot.alias, shim, orig, installed) != InstallOutcome::Failed;
        }

        void rollback(GumInterceptor *interceptor, const InstalledTargets &installed) noexcept {
            // Revert must run outside the transaction: inside one it only defers the
            // restore, so a single retry covers the deferred case.
            for (size_t i = 0; i < installed.count; ++i) {
                if (!ds::FastHook::Revert(interceptor, installed.targets[i])) {
                    (void) ds::FastHook::Revert(interceptor, installed.targets[i]);
                }
            }
        }

        // Checks the group that was just committed: producers are only installed in
        // phase B, so requiring them during phase A would fail every module.
        bool required_trampolines_ready(size_t provider, bool producers) noexcept {
            auto &prov = provider_slot(provider);
            for (const auto &slot: kWindowsCrtSlots) {
                if (!slot.required) continue;
                if (produces_memory(slot.kind) != producers) continue;
                const auto orig = orig_slot(prov, slot.kind);
                if (orig == nullptr || *orig == nullptr) return false;
            }
            return true;
        }

        bool hook_module(GumInterceptor *interceptor, HMODULE module, size_t provider, const char *label) noexcept {
            if (module == nullptr) return false;

            auto &prov = provider_slot(provider);
            prov.module = label;
            prov.active = false;

            InstalledTargets consumers;
            InstalledTargets producers;
            bool consumers_ok = true;

            // Phase A: consumers and queries. gum/FastHook allocate while they work,
            // so this transaction must be committed while every producer is still the
            // original CRT entry - otherwise a block from the new heap could reach an
            // unhooked free.
            gum_interceptor_begin_transaction(interceptor);
            for (const auto &slot: kWindowsCrtSlots) {
                if (produces_memory(slot.kind)) continue;
                if (!install_slot(interceptor, module, slot, provider, consumers)) {
                    note_failure();
                    if (slot.required) consumers_ok = false;
                }
            }
            gum_interceptor_end_transaction(interceptor);

            if (!consumers_ok || !required_trampolines_ready(provider, false)) {
                note_failure();
                rollback(interceptor, consumers);
                return false;
            }

            // Phase B: producers. Every consumer resolved, so a producer installed now
            // can only hand out blocks that the shim already recognises as its own.
            bool producers_ok = true;
            gum_interceptor_begin_transaction(interceptor);
            for (const auto &slot: kWindowsCrtSlots) {
                if (!produces_memory(slot.kind)) continue;
                if (!install_slot(interceptor, module, slot, provider, producers)) {
                    note_failure();
                    if (slot.required) producers_ok = false;
                }
            }
            gum_interceptor_end_transaction(interceptor);

            if (!producers_ok || !required_trampolines_ready(provider, true)) {
                note_failure();
                rollback(interceptor, producers);
                rollback(interceptor, consumers);
                return false;
            }

            prov.active = true;
            note_patched(consumers.count + producers.count);
            return true;
        }

    }// namespace

    bool install_win_crt_hooks(const Options &opts) {
        set_backend(Backend::WinCrtHook);

        // The game may unload the Winmm proxy (and therefore Injector.dll) while the
        // CRT entries still point into our shim; pin the image for process lifetime.
        HMODULE self = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                                reinterpret_cast<LPCWSTR>(&install_win_crt_hooks), &self)) {
            note_failure();
        }

        GumInterceptor *interceptor = gum_interceptor_obtain();
        if (interceptor == nullptr) {
            note_failure();
            return false;
        }

        // A debug CRT image keeps its own block bookkeeping in its malloc/free path:
        // replacing only the allocator entry points leaves the debug free validating a
        // block that no longer carries its header (debug_heap.cpp
        // `_CrtIsValidHeapPointer`, `is_block_type_valid`, plus an MI_PADDING overflow
        // report where the debug cookie lands past the shim block). Measured on a /MDd
        // binary, so debug CRTs are out of scope - the shipped game links the release
        // CRT. A debug image is also the only way a process gets one, so its presence
        // means "this build is a debug build".
        if (GetModuleHandleW(L"msvcr90d.dll") != nullptr || GetModuleHandleW(L"ucrtbased.dll") != nullptr) {
            note_skipped_debug_crt();
            return false;
        }

        // Never LoadLibraryW a CRT: hooking a CRT the process does not link would
        // redirect allocations the game never makes. System32\msvcrt.dll is
        // deliberately absent too - it belongs to the OS, not to this process.
        struct Selection {
            HMODULE module;
            const char *label;
            bool primary;
        };
        Selection selections[kMaxProviders]{};
        size_t selected = 0;

        if (HMODULE msvcr = GetModuleHandleW(L"msvcr90.dll"); msvcr != nullptr) {
            selections[selected++] = {msvcr, "msvcr90", true};
        }
        if (opts.patch_all_modules) {
            if (HMODULE ucrt = GetModuleHandleW(L"ucrtbase.dll"); ucrt != nullptr) {
                selections[selected++] = {ucrt, "ucrtbase", false};
            }
        }

        bool any = false;
        for (size_t i = 0; i < selected; ++i) {
            const auto &selection = selections[i];
            if (!hook_module(interceptor, selection.module, i, selection.label)) continue;
            any = true;
            if (selection.primary) note_primary_target();
        }
        return any;
    }

}// namespace ds::alloc::detail

#endif// _WIN32
