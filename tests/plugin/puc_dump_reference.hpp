#pragma once
// Test-only PUC Lua 5.1 reference side for the string.dump proof.
//
// Split into its own translation unit (puc_dump_reference.cpp) so no build unit
// ever mixes the PUC 5.1 headers with the dynamically loaded LuaJIT ones: this
// header exposes only plain C types, and the implementation owns the src/lua51original
// state. It is the *reference* oracle, not the production path:
//   * ds_ref_dump  compiles a trusted fixture, executes it once and dumps the
//                  requested returned function with PUC's own lua_dump;
//   * ds_ref_execute loads and runs trusted PUC bytecode (the product's target
//                  environment) to prove the dumped bytes are real Lua 5.1 code.
// The production service only ever compiles; executing fixtures here is fine
// because the fixture text is written by this test, not supplied by a mod.

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 1 on success. On failure returns 0 and writes a NUL-terminated reason.
int ds_ref_dump(const char *source, size_t source_len, const char *chunkname,
                int result_index, void **out_data, size_t *out_size,
                char *err, size_t err_cap);

void ds_ref_free(void *data);

// Loads PUC bytecode, calls the resulting function with `arg` and reports the
// single number result.
int ds_ref_execute(const void *data, size_t size, double arg, double *out,
                   char *err, size_t err_cap);

#ifdef __cplusplus
}
#endif
