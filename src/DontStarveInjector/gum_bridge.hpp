#pragma once
#include "config.hpp"
#include <cstddef>
#include <cstdint>

// Plugins must not static-link a second Frida Gum / function_relocation copy.
// All Gum + signature work for plugins goes through Injector (single Gum instance).

struct _GumInterceptor;
struct _GumInvocationContext;
struct _GumProbeListener;
typedef struct _GumInterceptor GumInterceptor;
typedef struct _GumInvocationContext GumInvocationContext;
typedef struct _GumProbeListener GumProbeListener;

typedef void (*DsGumProbeCallback)(GumInvocationContext *context, void *user_data);

DONTSTARVEINJECTOR_GAME_API GumProbeListener *DS_GUM_make_probe_listener(DsGumProbeCallback on_hit,
                                                                         void *user_data);

// Returns 0 on success (GUM_ATTACH_OK), non-zero on failure.
DONTSTARVEINJECTOR_GAME_API int DS_GUM_interceptor_attach(GumInterceptor *interceptor,
                                                          void *target_address,
                                                          GumProbeListener *listener);

DONTSTARVEINJECTOR_GAME_API void DS_GUM_invocation_replace_nth_argument(GumInvocationContext *context,
                                                                        unsigned n,
                                                                        void *value);

DONTSTARVEINJECTOR_GAME_API int DS_GUM_memory_is_readable(const void *addr, size_t len);

// prot is GumPageProtection*
DONTSTARVEINJECTOR_GAME_API int DS_GUM_memory_query_protection(const void *addr, void *prot_out);

// Scan pattern in main module; returns target address or 0.
DONTSTARVEINJECTOR_GAME_API uintptr_t DS_SIG_scan(const char *pattern, int offset);

// Decode first insn at addr; return RIP-relative memory target of operand[op_index], or 0.
DONTSTARVEINJECTOR_GAME_API uintptr_t DS_DISASM_read_operand_rip_mem(const void *addr, size_t max_len,
                                                                     int op_index);

// x64: RDI / RSI from GumInvocationContext cpu_context (0 if unavailable).
DONTSTARVEINJECTOR_GAME_API void *DS_GUM_invocation_get_rdi(GumInvocationContext *context);
DONTSTARVEINJECTOR_GAME_API void *DS_GUM_invocation_get_rsi(GumInvocationContext *context);
