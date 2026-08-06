#pragma once
// Export surface for function_relocation.
//
// Windows SHARED (FUNCTION_RELOCATION_BUILD): dllexport from the DLL.
// All other TUs leave the macro empty:
//   - Intermediate STATIC libs (ds_signature) must not use dllimport, or tools
//     that link function_relocation_static fail with __imp_* unresolved.
//   - Final consumers resolve via the import lib (plugins/Injector) or the
//     static archive (tools); MSVC does not require dllimport for that.
// FUNCTION_RELOCATION_STATIC is still defined on the tools static target so
// intentional static consumers stay free of any shared-DLL assumption.
#if defined(_WIN32)
#  if defined(FUNCTION_RELOCATION_BUILD)
#    define FUNCTION_RELOCATION_API __declspec(dllexport)
#  else
#    define FUNCTION_RELOCATION_API
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  if defined(FUNCTION_RELOCATION_BUILD) || !defined(FUNCTION_RELOCATION_STATIC)
#    define FUNCTION_RELOCATION_API __attribute__((visibility("default")))
#  else
#    define FUNCTION_RELOCATION_API
#  endif
#else
#  define FUNCTION_RELOCATION_API
#endif
