#include "legacy_memory_signature.hpp"
#include <frida-gum.h>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <algorithm>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#define REQUIRE(condition)                                            \
    do {                                                              \
        if (!(condition)) {                                           \
            std::fprintf(stderr, "REQUIRE failed: %s\n", #condition); \
            std::abort();                                             \
        }                                                             \
    } while (false)

static const char marker[] = "DS_MEMORY_SIGNATURE_LEGACY_ABI_MARKER";
#if defined(__linux__) && UINTPTR_MAX == UINT64_MAX
static_assert(sizeof(function_relocation::MemorySignature) == 56);
#endif

int main() {
    gum_init_embedded();
    size_t page;
    unsigned char *mapping;
#ifdef _WIN32
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    page = system.dwPageSize;
    mapping = static_cast<unsigned char *>(VirtualAlloc(nullptr, 2 * page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    REQUIRE(mapping);
    DWORD old_protection;
    REQUIRE(VirtualProtect(mapping + page, page, PAGE_NOACCESS, &old_protection));
#else
    page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    mapping = static_cast<unsigned char *>(mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(mapping != MAP_FAILED);
    REQUIRE(mprotect(mapping + page, page, PROT_NONE) == 0);
#endif
    // Any access to a new trailing data member faults at the guard page.
    auto *signature = new (mapping + page - sizeof(function_relocation::MemorySignature))
            function_relocation::MemorySignature{
                    "44 53 5F 4D 45 4D 4F 52 59 5F 53 49 47 4E 41 54 55 52 45 5F 4C 45 47 41 43 59 5F 41 42 49 5F 4D 41 52 4B 45 52", 0, false};
    signature->log = false;
    signature->prot_flag = GUM_PAGE_READ;
    const auto expected = reinterpret_cast<uintptr_t>(marker);
    const auto actual = signature->scan(nullptr);
    REQUIRE(actual != 0);
    // ELF may map a read-only file page at more than one module address.
    REQUIRE(std::find(signature->targets.begin(), signature->targets.end(), expected) != signature->targets.end());
    REQUIRE(signature->scan(expected, sizeof(marker) - 1) == expected);
    REQUIRE(signature->targets.size() == 1);
    signature->~MemorySignature();
#ifdef _WIN32
    REQUIRE(VirtualFree(mapping, 0, MEM_RELEASE));
#else
    REQUIRE(munmap(mapping, 2 * page) == 0);
#endif
    gum_deinit_embedded();
    std::puts("legacy MemorySignature consumer passed against current shared library");
}
