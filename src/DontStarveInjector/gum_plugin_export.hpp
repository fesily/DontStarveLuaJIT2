#pragma once

// Dynamic plugins call gum_* / cs_* as imports from Injector.
//
// Windows: Injector statically links frida-gum-devkit and re-exports via FridaGum.def.
// Linux / macOS: equivalent ELF version-script / Mach-O export list is NOT implemented.
// Linking libfrida-gum.a into each plugin would create a second Gum instance (crashy).
//
// Fail fast until that re-export lands. Do not weaken this to a warning.

#if defined(__linux__) || defined(__APPLE__)
#  error "Frida Gum re-export for dynamic plugins is unimplemented on Linux/macOS " \
         "(Windows uses FridaGum.def). Wait for ELF/Mach-O export list before building " \
         "gum-using plugins; do not static-link a second frida-gum into plugins."
#endif
