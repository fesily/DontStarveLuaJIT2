#pragma once
// Export surface for fast_assert.
//
// Every entry point (reporting path + handler slot) must exist exactly once per
// process. Exactly one module owns the implementation and defines
// FAST_ASSERT_BUILD while compiling `fast_assert_owner` — in this product that
// module is the Injector. Every other module links only the header-only
// `fast_assert` view and imports the symbols from the owner.
//
// Windows: the owner exports with dllexport. Other TUs stay unadorned and
// resolve through the owner's import library; this matches
// function_relocation/export.hpp and keeps executables that link the state
// archive statically working (MSVC does not require dllimport for functions).
// ELF/Mach-O: always default visibility, so neither the owner's hidden-visibility
// preset can hide the definition nor a consumer's can shadow-bind a local copy.
#if defined(_WIN32)
#  if defined(FAST_ASSERT_BUILD)
#    define FAST_ASSERT_API __declspec(dllexport)
#  else
#    define FAST_ASSERT_API
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define FAST_ASSERT_API __attribute__((visibility("default")))
#else
#  define FAST_ASSERT_API
#endif
