#pragma once
// Test assertion that keeps its checking power in every build configuration.
//
// This repo has no /UNDEBUG wiring, and MSVC's Release/RelWithDebInfo add
// /DNDEBUG, which compiles <cassert>'s assert() to nothing. A release-mode ctest
// run therefore could not fail on a broken invariant: test_plugin_path's
// `assert(has(mod / "deps"))` stayed green for months while the invariant was
// false on Windows (see g_dll_roots in core/PluginPath.cpp).
//
// DS_REQUIRE is always evaluated. On failure it prints file:line + expression to
// stderr and exits with status 3 — no dependency on the CRT's assert/abort path
// (no debugger dialog, and the same exit status on MSVC and POSIX), which is
// exactly what ctest needs to mark the test failed.
//
// Usage: #include "support/test_assert.hpp"  (tests/ is on the include path)
//        DS_REQUIRE(expr);
#include <cstdio>
#include <cstdlib>

#define DS_REQUIRE(expr)                                                      \
    do {                                                                      \
        if (!(expr)) {                                                        \
            std::fprintf(stderr, "%s:%d: DS_REQUIRE failed: %s\n", __FILE__,  \
                         __LINE__, #expr);                                    \
            std::fflush(stderr);                                              \
            std::exit(3);                                                     \
        }                                                                     \
    } while (0)
