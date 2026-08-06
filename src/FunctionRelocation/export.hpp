#pragma once
#if defined(_WIN32)
#  if defined(FUNCTION_RELOCATION_BUILD)
#    define FUNCTION_RELOCATION_API __declspec(dllexport)
#  else
#    define FUNCTION_RELOCATION_API __declspec(dllimport)
#  endif
#else
#  define FUNCTION_RELOCATION_API __attribute__((visibility("default")))
#endif
