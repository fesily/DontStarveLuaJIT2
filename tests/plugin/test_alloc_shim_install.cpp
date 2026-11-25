// End-to-end check of the real backend: install the shim in this process and
// verify that the CRT entry points now hand out mimalloc blocks. Any mistake in
// the two-phase Windows ordering or in the POSIX slot rewrite shows up here as a
// crash or a foreign pointer, which is why this lives in its own executable.

#include "core/alloc/AllocShim.hpp"

#include <doctest/doctest.h>
#ifdef _WIN32
#include <frida-gum.h>
#endif
#include <mimalloc.h>

#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <crtdbg.h>
#include <malloc.h>
#endif

TEST_CASE("alloc_shim_install/live process dispatches through mimalloc") {
    if (!ds::alloc::read_env_switch()) {
        MESSAGE("DS_ALLOC_SHIM disables the shim; nothing to verify");
        return;
    }
#ifdef _WIN32
    // A debug-CRT report (invalid parameter, heap check) opens a modal dialog by
    // default, which reads as a hang and hides the message. Send every report to
    // stderr and the debugger stream instead.
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif
    if (ds::alloc::installed()) {
        MESSAGE("shim already installed by another test case");
        return;
    }

#ifdef _WIN32
    gum_init_embedded();// production calls this before install_early
#endif

    ds::alloc::Options options{};
    options.enabled = true;
    options.stats = true;
    options.patch_all_modules = true;
    const bool installed = ds::alloc::install_early(options);
    if (!installed && ds::alloc::skipped_debug_crt()) {
        // /MDd: the debug CRTs keep their own block headers in the free path, so the
        // release-CRT-only shim deliberately declines. Nothing to verify here.
        MESSAGE("debug CRT image loaded: shim is release-CRT only");
        return;
    }
    REQUIRE(installed);
    REQUIRE(ds::alloc::installed());
    CHECK(std::string{ds::alloc::backend_name()} != "none");
    CHECK_GT(ds::alloc::patched_slot_count(), 0u);

    const auto before = ds::alloc::stats();

    void *block = std::malloc(64);
    REQUIRE_NE(block, nullptr);
    { INFO("CRT malloc now returns an owned block"); CHECK(mi_is_in_heap_region(block)); }
    CHECK_GE(mi_usable_size(block), 64u);
    std::memset(block, 0x5a, 64);

    void *grown = std::realloc(block, 4096);
    REQUIRE_NE(grown, nullptr);
    { INFO("CRT realloc keeps the block in the shim heap"); CHECK(mi_is_in_heap_region(grown)); }
    std::free(grown);

    void *zeros = std::calloc(8, 32);
    REQUIRE_NE(zeros, nullptr);
    CHECK(mi_is_in_heap_region(zeros));
    std::free(zeros);

#ifdef _WIN32
    char *duplicate = ::_strdup("alloc shim");// CRT-internal malloc -> shim
#else
    char *duplicate = ::strdup("alloc shim");
#endif
    REQUIRE_NE(duplicate, nullptr);
    CHECK(mi_is_in_heap_region(duplicate));
    CHECK_EQ(std::strcmp(duplicate, "alloc shim"), 0);
    std::free(duplicate);

    std::string text(200, 'x');// msvcp140 / libstdc++ allocation path
    CHECK_EQ(text.size(), 200u);

    const auto after = ds::alloc::stats();
    { INFO("statistics see the traffic"); CHECK_GT(after.malloc_calls, before.malloc_calls); }
    CHECK_GT(after.free_own, before.free_own);

#ifdef _WIN32
    void *sized = std::malloc(128);
    REQUIRE_NE(sized, nullptr);
    CHECK_GE(_msize(sized), 128u);

    void *resized = _recalloc(sized, 4, 64);
    REQUIRE_NE(resized, nullptr);
    CHECK(mi_is_in_heap_region(resized));
    CHECK_EQ(_msize(resized) >= 256, true);
    std::free(resized);

    void *aligned = _aligned_malloc(96, 64);
    REQUIRE_NE(aligned, nullptr);
    CHECK(mi_is_in_heap_region(aligned));
    CHECK_EQ(reinterpret_cast<uintptr_t>(aligned) % 64, 0u);
    _aligned_free(aligned);
#endif
}
