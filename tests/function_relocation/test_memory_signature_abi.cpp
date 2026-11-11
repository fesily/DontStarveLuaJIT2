#include "legacy_memory_signature.hpp"

#include <doctest/doctest.h>

#include <frida-gum.h>
#include <new>
#include <algorithm>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace {

    static const char marker[] = "DS_MEMORY_SIGNATURE_LEGACY_ABI_MARKER";
#if defined(__linux__) && UINTPTR_MAX == UINT64_MAX
    static_assert(sizeof(function_relocation::MemorySignature) == 56);
#endif

    // Owns the process-wide gum engine for the single case below (gum only: no
    // FunctionRelocation ctx).
    struct GumEnv {
        GumEnv() { gum_init_embedded(); }

        ~GumEnv() { gum_deinit_embedded(); }

        GumEnv(const GumEnv &) = delete;

        GumEnv &operator=(const GumEnv &) = delete;
    };

    // Two-page fixture mapping; released on scope exit even when an assertion
    // unwinds the case.
    struct MappingGuard {
        unsigned char *base = nullptr;
        size_t size = 0;

        ~MappingGuard() { release(); }

        // 0 on success; neutralizes the guard so the destructor is a no-op.
        int release() {
            if (base == nullptr) {
                return 0;
            }
            unsigned char *mapped = base;
            base = nullptr;
#ifdef _WIN32
            return VirtualFree(mapped, 0, MEM_RELEASE) ? 0 : -1;
#else
            return munmap(mapped, size);
#endif
        }
    };

    // Runs the placement-new destructor once; the storage lives in the mapping.
    struct PlacedSignature {
        function_relocation::MemorySignature *object = nullptr;

        ~PlacedSignature() {
            if (object != nullptr) {
                object->~MemorySignature();
            }
        }

        void destroy() {
            if (object != nullptr) {
                object->~MemorySignature();
                object = nullptr;
            }
        }
    };

}// namespace

TEST_CASE("test_memory_signature_abi/all") {
    GumEnv gum_env;
    size_t page;
#ifdef _WIN32
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    page = system.dwPageSize;
    auto *mapped = static_cast<unsigned char *>(
            VirtualAlloc(nullptr, 2 * page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    REQUIRE(mapped);
#else
    page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *mapped = static_cast<unsigned char *>(
            mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE_NE(mapped, MAP_FAILED);
#endif
    MappingGuard mapping{mapped, 2 * page};
#ifdef _WIN32
    DWORD old_protection;
    REQUIRE(VirtualProtect(mapping.base + page, page, PAGE_NOACCESS, &old_protection));
#else
    REQUIRE_EQ(mprotect(mapping.base + page, page, PROT_NONE), 0);
#endif
    // Any access to a new trailing data member faults at the guard page.
    PlacedSignature placed;
    placed.object = new (mapping.base + page - sizeof(function_relocation::MemorySignature))
            function_relocation::MemorySignature{
                    "44 53 5F 4D 45 4D 4F 52 59 5F 53 49 47 4E 41 54 55 52 45 5F 4C 45 47 41 43 59 5F 41 42 49 5F 4D 41 52 4B 45 52", 0, false};
    auto *signature = placed.object;
    signature->log = false;
    signature->prot_flag = GUM_PAGE_READ;
    const auto expected = reinterpret_cast<uintptr_t>(marker);
    const auto actual = signature->scan(nullptr);
    REQUIRE_NE(actual, 0);
    // ELF may map a read-only file page at more than one module address.
    REQUIRE(std::find(signature->targets.begin(), signature->targets.end(), expected) != signature->targets.end());
    REQUIRE(signature->scan(expected, sizeof(marker) - 1) == expected);
    REQUIRE(signature->targets.size() == 1);
    placed.destroy();
    REQUIRE_EQ(mapping.release(), 0);
}
