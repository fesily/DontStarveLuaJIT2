/*
 * Thin shared shell for frida-gum.
 * Linked against the static frida-gum archive (+ deps) with tools/frida/FridaGum.def.
 * Compile with -DGUM_EXPORTS and WITHOUT GUM_STATIC so GUM_API is dllexport on Windows.
 * No real logic - the .def pulls gum_* / cs_* from the static archive.
 */
#include <frida-gum.h>

/* Keep a live reference so LTO/GC cannot drop the DLL entry surface on some toolchains. */
GUM_API void
ds_frida_gum_shell_anchor(void)
{
  /* gum_init is always present in the export list; calling is unnecessary. */
  (void)sizeof(GumAddress);
}
