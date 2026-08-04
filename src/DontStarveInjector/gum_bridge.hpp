#pragma once
#include "config.hpp"
#include <cstddef>
#include <cstdint>

// Plugins must not include <frida-gum.h> or link frida-gum / function_relocation.
// All Gum + signature work goes through Injector (single Gum instance).

struct _GumInterceptor;
struct _GumInvocationContext;
typedef struct _GumInterceptor GumInterceptor;
typedef struct _GumInvocationContext GumInvocationContext;
// Opaque listener handle from DS_GUM_make_probe_listener.
typedef void GumProbeListener;

typedef void (*DsGumProbeCallback)(GumInvocationContext *context, void *user_data);

DONTSTARVEINJECTOR_GAME_API GumProbeListener *DS_GUM_make_probe_listener(DsGumProbeCallback on_hit,
                                                                         void *user_data);

// Returns 0 on success.
DONTSTARVEINJECTOR_GAME_API int DS_GUM_interceptor_attach(GumInterceptor *interceptor,
                                                          void *target_address,
                                                          GumProbeListener *listener);

// Returns 0 on success (GUM_REPLACE_OK).
DONTSTARVEINJECTOR_GAME_API int DS_GUM_interceptor_replace(GumInterceptor *interceptor,
                                                           void *target_address,
                                                           void *replacement,
                                                           void **original_out);

DONTSTARVEINJECTOR_GAME_API void DS_GUM_interceptor_revert(GumInterceptor *interceptor,
                                                           void *target_address);

DONTSTARVEINJECTOR_GAME_API void DS_GUM_invocation_replace_nth_argument(GumInvocationContext *context,
                                                                        unsigned n,
                                                                        void *value);

DONTSTARVEINJECTOR_GAME_API int DS_GUM_memory_is_readable(const void *addr, size_t len);

// prot_out receives GumPageProtection as uint32_t (GUM_PAGE_RX == 5).
DONTSTARVEINJECTOR_GAME_API int DS_GUM_memory_query_protection(const void *addr, void *prot_out);

// UTF-8 path of process main module; returns bytes written excluding NUL, or 0.
DONTSTARVEINJECTOR_GAME_API int DS_GUM_main_module_path(char *buf, int buf_len);

// Scan pattern in main module (or path if non-null); returns target address or 0.
DONTSTARVEINJECTOR_GAME_API uintptr_t DS_SIG_scan(const char *pattern, int offset);
DONTSTARVEINJECTOR_GAME_API uintptr_t DS_SIG_scan_module(const char *module_path,
                                                         const char *pattern, int offset);

// Decode first insn at addr; return RIP-relative memory target of operand[op_index], or 0.
DONTSTARVEINJECTOR_GAME_API uintptr_t DS_DISASM_read_operand_rip_mem(const void *addr, size_t max_len,
                                                                     int op_index);

// x64: RDI / RSI from GumInvocationContext cpu_context (0 if unavailable).
DONTSTARVEINJECTOR_GAME_API void *DS_GUM_invocation_get_rdi(GumInvocationContext *context);
DONTSTARVEINJECTOR_GAME_API void *DS_GUM_invocation_get_rsi(GumInvocationContext *context);
