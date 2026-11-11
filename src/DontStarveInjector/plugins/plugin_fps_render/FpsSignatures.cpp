#include "FpsSignatures.hpp"

#include "disasm.h"

#include <cstdio>

#if defined(DS_SIG_HAVE_FPS_RENDER)
namespace ds::fps_render {
namespace {

using namespace ds::sig;

// The four float immediates the notebook-mode setter loads: 1/30, 1/60, 30, 60.
// The consumer rewrites their rip-relative targets, so the window has to hold
// exactly this sequence in this order (XMM0/XMM1 from memory).
constexpr int32_t kFrameTimeConstants[4] = {
        1023969417, // 1/30
        1015580809, // 1/60
        1106247680, // 30.0
        1114636288, // 60.0
};

bool verify_notebook_mode(const EntryDef &, const ContextView &, uintptr_t target, uintptr_t, char *detail,
                          size_t detail_cap) {
    function_relocation::disasm ds{reinterpret_cast<uint8_t *>(target), 256};
    int seen = 0;
    for (auto &&insn : ds) {
        if (insn.id != X86_INS_MOVSS) {
            continue;
        }
        const auto &x86 = insn.detail->x86;
        if (x86.op_count != 2 || x86.operands[0].type != X86_OP_REG || x86.operands[1].type != X86_OP_MEM) {
            continue;
        }
        if (x86.operands[0].reg != X86_REG_XMM0 && x86.operands[0].reg != X86_REG_XMM1) {
            std::snprintf(detail, detail_cap, "unexpected MOVSS destination register at {:#x}",
                          static_cast<uintptr_t>(insn.address));
            return false;
        }
        const auto *constant =
                reinterpret_cast<const int32_t *>(function_relocation::read_operand_rip_mem(insn, x86.operands[1]));
        if (constant == nullptr) {
            std::snprintf(detail, detail_cap, "MOVSS operand is not rip-relative");
            return false;
        }
        if (*constant != kFrameTimeConstants[seen]) {
            std::snprintf(detail, detail_cap, "MOVSS constant #%d is {:#x}, expected {:#x}", seen,
                          static_cast<uint32_t>(*constant),
                          static_cast<uint32_t>(kFrameTimeConstants[seen]));
            return false;
        }
        ++seen;
        if (seen == 4) {
            return true;
        }
    }
    std::snprintf(detail, detail_cap, "only %d of 4 frame-time constants found in the window", seen);
    return false;
}

constexpr uint32_t kWin = kPlatformWindowsX64;

EntryDef g_entries[] = {
        {
                .owner = "fps.render",
                .name = "fps.render.notebook_mode",
                .description = "Notebook-mode frame-time setter (four MOVSS constants)",
                .patterns = {"F3 0F 11 89 D8 01 00 00"},
                .pattern_offset = -0x3E,
                .platform_mask = kWin,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = &verify_notebook_mode,
        },
        // Server-only: the client never reads this config byte, and hooking it on a
        // client matches an unrelated body. The gate is client/server, not "feature
        // off", so the entry is listed and reported as NotApplicable on a client.
        {
                .owner = "fps.render",
                .name = "fps.render.notebook_config",
                .description = "Notebook-mode config gate (dedicated-server only)",
                .patterns = {"80 B9 D4 01 00 00 00"},
                .pattern_offset = -0x6,
                .platform_mask = kWin,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 1,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
};

const ProviderDesc g_desc{
        .owner = "fps.render",
        .provider_version = "1",
        .entries = g_entries,
        .entry_count = sizeof(g_entries) / sizeof(g_entries[0]),
        .repair = nullptr,
        .prepare = nullptr,
};

} // namespace

const ds::sig::ProviderDesc &signature_provider() {
    return g_desc;
}

} // namespace ds::fps_render
#endif // DS_SIG_HAVE_FPS_RENDER
