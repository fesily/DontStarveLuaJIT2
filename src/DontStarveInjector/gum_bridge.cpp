#include "gum_bridge.hpp"
#include "MemorySignature.hpp"
#include "disasm.h"
#include "config.hpp"

#include <frida-gum.h>

DONTSTARVEINJECTOR_GAME_API GumProbeListener *DS_GUM_make_probe_listener(DsGumProbeCallback on_hit,
                                                                         void *user_data) {
    struct Node {
        DsGumProbeCallback cb;
        void *ud;
    };
    auto *node = new Node{on_hit, user_data};
    // gum_make_probe_listener returns GumInvocationListener*; keep opaque as GumProbeListener*.
    return reinterpret_cast<GumProbeListener *>(gum_make_probe_listener(
        +[](GumInvocationContext *context, gpointer user_data) {
            auto *n = static_cast<Node *>(user_data);
            if (n && n->cb) {
                n->cb(context, n->ud);
            }
        },
        node, nullptr));
}

DONTSTARVEINJECTOR_GAME_API int DS_GUM_interceptor_attach(GumInterceptor *interceptor,
                                                          void *target_address,
                                                          GumProbeListener *listener) {
    if (!interceptor || !target_address || !listener) {
        return -1;
    }
    return static_cast<int>(gum_interceptor_attach(
        interceptor, target_address, reinterpret_cast<GumInvocationListener *>(listener), nullptr,
        GUM_ATTACH_FLAGS_NONE));
}

DONTSTARVEINJECTOR_GAME_API void DS_GUM_invocation_replace_nth_argument(GumInvocationContext *context,
                                                                        unsigned n,
                                                                        void *value) {
    if (!context) {
        return;
    }
    gum_invocation_context_replace_nth_argument(context, n, value);
}

DONTSTARVEINJECTOR_GAME_API int DS_GUM_memory_is_readable(const void *addr, size_t len) {
    return gum_memory_is_readable(const_cast<void *>(addr), len) ? 1 : 0;
}

DONTSTARVEINJECTOR_GAME_API int DS_GUM_memory_query_protection(const void *addr, void *prot_out) {
    if (!prot_out) {
        return 0;
    }
    GumPageProtection prot{};
    if (!gum_memory_query_protection(const_cast<void *>(addr), &prot)) {
        return 0;
    }
    *static_cast<uint32_t *>(prot_out) = static_cast<uint32_t>(prot);
    return 1;
}

DONTSTARVEINJECTOR_GAME_API uintptr_t DS_SIG_scan(const char *pattern, int offset) {
    if (!pattern) {
        return 0;
    }
    function_relocation::MemorySignature sig{pattern, offset};
    // scan(nullptr) scans main module (existing GameNetwork usage).
    return sig.scan(static_cast<const char *>(nullptr));
}

DONTSTARVEINJECTOR_GAME_API uintptr_t DS_DISASM_read_operand_rip_mem(const void *addr, size_t max_len,
                                                                     int op_index) {
    if (!addr) {
        return 0;
    }
    auto insn = function_relocation::disasm::get_insn(const_cast<void *>(addr), max_len);
    if (!insn || !insn->detail) {
        return 0;
    }
    if (op_index < 0 || op_index >= insn->detail->x86.op_count) {
        return 0;
    }
    return function_relocation::read_operand_rip_mem(*insn, insn->detail->x86.operands[op_index]);
}

DONTSTARVEINJECTOR_GAME_API void *DS_GUM_invocation_get_rdi(GumInvocationContext *context) {
    if (!context || !context->cpu_context) {
        return nullptr;
    }
#ifdef _WIN32
    return reinterpret_cast<void *>(context->cpu_context->rdi);
#else
    return nullptr;
#endif
}

DONTSTARVEINJECTOR_GAME_API void *DS_GUM_invocation_get_rsi(GumInvocationContext *context) {
    if (!context || !context->cpu_context) {
        return nullptr;
    }
#ifdef _WIN32
    return reinterpret_cast<void *>(context->cpu_context->rsi);
#else
    return nullptr;
#endif
}
