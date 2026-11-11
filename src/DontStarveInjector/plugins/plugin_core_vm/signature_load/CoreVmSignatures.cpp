#include "CoreVmSignatures.hpp"


#include "disasm.h"
#include "ModuleSections.hpp"

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <charconv>
#include <span>
#include <cstdio>
#include <cstring>
#include <string_view>

namespace ds::core_vm::detail {

ExecutionErrorStorage decode_execution_error_storage(uintptr_t helper) {
    ExecutionErrorStorage storage;
    if (helper == 0) {
        return storage;
    }
    const auto mem_target = [](const cs_insn &insn, const auto &op) -> uintptr_t {
        if (op.type != X86_OP_MEM || !function_relocation::reg_is_ip(op.mem.base)) {
            return 0;
        }
        return (uintptr_t) ((int64_t) (insn.address + insn.size) + (int64_t) op.mem.disp);
    };
    // Register -> rip-relative `lea` target seen so far (plus plain register moves, which
    // only forward an already known target). Small: the helper body is a handful of moves.
    struct LeaSource {
        unsigned reg = 0;
        uintptr_t target = 0;
    };
    constexpr size_t max_lea_sources = 8;
    LeaSource lea_sources[max_lea_sources];
    size_t lea_count = 0;
    const auto lea_forget = [&](unsigned reg) {
        for (size_t i = 0; i < lea_count; ++i) {
            if (lea_sources[i].reg == reg) {
                lea_sources[i] = lea_sources[--lea_count];
                return;
            }
        }
    };
    const auto lea_lookup = [&](unsigned reg) -> uintptr_t {
        for (size_t i = 0; i < lea_count; ++i) {
            if (lea_sources[i].reg == reg) {
                return lea_sources[i].target;
            }
        }
        return 0;
    };
    const auto lea_remember = [&](unsigned reg, uintptr_t target) {
        lea_forget(reg);
        if (target == 0) {
            return;
        }
        if (lea_count < max_lea_sources) {
            lea_sources[lea_count++] = LeaSource{reg, target};
        }
    };
    constexpr size_t window = 0xC0;
    function_relocation::disasm ds{std::span{(uint8_t *) helper, window}};
    bool size_seen = false;
    bool store_seen = false;
    for (auto &insn: ds) {
        if (insn.id == 0) {
            continue;
        }
        const auto &x86 = insn.detail->x86;
        for (int i = 0; i < x86.op_count; ++i) {
            const auto &op = x86.operands[i];
            if (op.type == X86_OP_IMM && op.imm == 0x1000) {
                size_seen = true;
            }
        }
        // Track where a register's value came from, so the flag store can be resolved.
        if (insn.id == X86_INS_LEA && x86.op_count == 2 && x86.operands[0].type == X86_OP_REG &&
            x86.operands[1].type == X86_OP_MEM) {
            lea_remember(x86.operands[0].reg, mem_target(insn, x86.operands[1]));
        } else if (insn.id == X86_INS_MOV && x86.op_count == 2 &&
                   x86.operands[0].type == X86_OP_REG) {
            lea_remember(x86.operands[0].reg,
                         x86.operands[1].type == X86_OP_REG ? lea_lookup(x86.operands[1].reg) : 0);
        }
        if (storage.flag == 0 && insn.id == X86_INS_CMP && x86.op_count == 2 &&
            x86.operands[0].type == X86_OP_MEM && x86.operands[1].type == X86_OP_IMM &&
            x86.operands[1].imm == 0) {
            storage.flag = mem_target(insn, x86.operands[0]);
        }
        if (storage.flag != 0 && insn.id == X86_INS_MOV && x86.op_count == 2 &&
            x86.operands[0].type == X86_OP_MEM &&
            x86.operands[1].type == X86_OP_REG &&
            mem_target(insn, x86.operands[0]) == storage.flag) {
            const uintptr_t block = lea_lookup(x86.operands[1].reg);
            if (block != 0) {
                storage.buffer = block;
                store_seen = true;
            }
        }
    }
    if (!size_seen || !store_seen || storage.flag == storage.buffer) {
        return ExecutionErrorStorage{};
    }
    return storage;
}

} // namespace ds::core_vm::detail

namespace ds::core_vm {
namespace {

using namespace std::literals;

// --- read-only verifiers ---------------------------------------------------

// The dev-build flag patch needs a body that loads a *release* build-type string
// through a rip-relative pointer kept in .rodata; other `mov rax,[rip]; ret`
// functions exist, so the candidates are filtered by that string, exactly like
// the previous inline implementation did.
#if defined(DS_SIG_TARGET_WINDOWS_X64)
bool verify_build_type(const ds::sig::EntryDef &, const ds::sig::ContextView &ctx, uintptr_t target,
                       uintptr_t raw_hit, char *detail, size_t detail_cap) {
    (void) target;
    function_relocation::ModuleSections module{};
    if (!ds::sig::module_sections_for(ctx, module)) {
        std::snprintf(detail, detail_cap, "module sections unavailable");
        return false;
    }
    if (!gum_memory_is_readable(reinterpret_cast<gpointer>(raw_hit), 8)) {
        std::snprintf(detail, detail_cap, "candidate is not readable");
        return false;
    }
    auto insn = function_relocation::disasm::get_insn(reinterpret_cast<void *>(raw_hit), 8);
    if (!insn || insn->detail->x86.op_count != 2) {
        std::snprintf(detail, detail_cap, "candidate is not a two-operand load");
        return false;
    }
    const auto &x86 = insn->detail->x86;
    if (x86.operands[0].type != X86_OP_REG || x86.operands[1].type != X86_OP_MEM) {
        std::snprintf(detail, detail_cap, "candidate is not a register load from memory");
        return false;
    }
    const auto string_pointer_slot = function_relocation::read_operand_rip_mem(*insn, x86.operands[1]);
    if (!string_pointer_slot || !gum_memory_is_readable(reinterpret_cast<gpointer>(string_pointer_slot),
                                                       sizeof(uintptr_t))) {
        std::snprintf(detail, detail_cap, "candidate does not load through a readable pointer slot");
        return false;
    }
    const auto string_address = *reinterpret_cast<const uintptr_t *>(string_pointer_slot);
    if (!module.in_rodata(string_address) || !gum_memory_is_readable(reinterpret_cast<gpointer>(string_address), 8)) {
        std::snprintf(detail, detail_cap, "candidate does not load through a .rodata pointer");
        return false;
    }
    const auto build_type = reinterpret_cast<const char *>(string_address);
    if (std::string_view{build_type} != "release") {
        std::snprintf(detail, detail_cap, "candidate build-type string is not \"release\"");
        return false;
    }
    return true;
}

#endif // DS_SIG_TARGET_WINDOWS_X64

#if defined(DS_SIG_TARGET_WINDOWS_X64) || defined(DS_SIG_TARGET_LINUX_X64)
bool verify_execution_error(const ds::sig::EntryDef &, const ds::sig::ContextView &, uintptr_t target,
                            uintptr_t, char *detail, size_t detail_cap) {
    const auto storage = ds::core_vm::detail::decode_execution_error_storage(target);
    if (!storage) {
        std::snprintf(detail, detail_cap, "execution-error storage decode failed");
        return false;
    }
    return true;
}

#endif // win||linux

#if defined(DS_SIG_TARGET_MACOS_X64) || defined(DS_SIG_TARGET_MACOS_ARM64)
bool verify_macos_version(const ds::sig::EntryDef &, const ds::sig::ContextView &ctx, uintptr_t target,
                          uintptr_t, char *detail, size_t detail_cap) {
    function_relocation::ModuleSections module{};
    if (!ds::sig::module_sections_for(ctx, module)) {
        std::snprintf(detail, detail_cap, "module sections unavailable");
        return false;
    }
    if (!module.in_rodata(target) || !gum_memory_is_readable(reinterpret_cast<gpointer>(target), 7)) {
        std::snprintf(detail, detail_cap, "candidate is not a readable .rodata lea target");
        return false;
    }
    const auto *text = reinterpret_cast<const char *>(target);
    if (std::strlen(text) != 6) {
        std::snprintf(detail, detail_cap, "candidate version string is not 6 characters");
        return false;
    }
    uintptr_t value = 0;
    const auto parsed = std::from_chars(text, text + 6, value);
    if (parsed.ec != std::errc{}) {
        std::snprintf(detail, detail_cap, "candidate version string is not numeric");
        return false;
    }
    return true;
}

#endif // macos

// --- definitions -----------------------------------------------------------

#if defined(DS_SIG_TARGET_WINDOWS_X64)
ds::sig::EntryDef g_entries[] = {
        // The Lua module anchor. Windows pins a body offset.
        {
                .owner = "core.vm",
                .name = "core.vm.lua_module",
                .description = "Lua module anchor (win64 build 26474873 literal)",
                .patterns = {"41 B8 EE D8 FF FF 41 3B D0 74 64 81 FA EF D8 FF FF 74 3B"},
                .pattern_offset = -0x37,
                .platform_mask = ds::sig::kPlatformWindowsX64,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(ds::sig::HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ds::sig::ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        // register_debug_getsize: the registration contract the VM replacement has
        // to keep.
        {
                .owner = "core.vm",
                .name = "core.vm.register_debug_getsize",
                .description = "Engine debug.getsize registration helper (win64)",
                .patterns = {"4C 8B 5B 18 48 8B CB 49 8B"},
                .pattern_offset = -0x27,
                .platform_mask = ds::sig::kPlatformWindowsX64,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(ds::sig::HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ds::sig::ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        // The engine's own lua_setexecutionerror-equivalent. Its two .data slots
        // (flag + 0x1000-byte message block) are what the swapped-in VM has to write
        // through; the decode below is the contract, so a wrong window fails closed.
        {
                .owner = "core.vm",
                .name = "core.vm.execution_error",
                .description = "Engine execution-error storage helper (win64, build 26474873 body)",
                .patterns = {"48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 75 76 48 85 C9 48 8D 15 ?? ?? ?? ?? "
                             "48 89 5C 24 30 48 8D 1D ?? ?? ?? ?? 48 0F 45 D1 48 3B D3 74 4B "
                             "48 83 C9 FF 48 89 7C 24 20 33 C0 48 8B FA F2 AE 48 F7 D1 48 FF C9 48 8B F9 "
                             "48 81 F9 00 10 00 00 72 15 BF FF 0F 00 00 0F B6 04 17 24 C0 3C 80 75 06 "
                             "48 83 EF 01 75 F0 4C 8B C7 48 8B CB E8 ?? ?? ?? ?? C6 04 1F 00 "
                             "48 8B 7C 24 20 48 89 1D ?? ?? ?? ?? 48 8B 5C 24 30 48 83 C4 28 C3"},
                .pattern_offset = 0,
                .platform_mask = ds::sig::kPlatformWindowsX64,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(ds::sig::HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ds::sig::ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = &verify_execution_error,
        },
        // Dev build-type flag: several `mov rax,[rip]; ret` bodies exist per build,
        // so the candidates are filtered by the "release" string they load.
        {
                .owner = "core.vm",
                .name = "core.vm.build_type",
                .description = "Engine GetBuildType accessor (win64, filtered by its release string)",
                .patterns = {"48 8B 05 ?? ?? ?? ?? C3"},
                .pattern_offset = 0,
                .platform_mask = ds::sig::kPlatformWindowsX64,
                .prot_flag = GUM_PAGE_EXECUTE,
                .hits_policy = static_cast<int32_t>(ds::sig::HitsPolicy::FilteredLowest),
                .resolve_kind = static_cast<int32_t>(ds::sig::ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_build_type,
        },
};
#elif defined(DS_SIG_TARGET_LINUX_X64)
ds::sig::EntryDef g_entries[] = {
        // Linux pins the body and takes the entry from the exact FDE range
        // (GCC 9 splits bodies).
        {
                .owner = "core.vm",
                .name = "core.vm.lua_module",
                .description = "Lua module anchor (linux-x64, entry from the exact FDE range)",
                .patterns = {"81 FE F1 D8 FF FF 7D ?? 81 FE EF D8 FF FF 74 ?? 81 FE F0 D8 FF FF"},
                .pattern_offset = 0,
                .platform_mask = ds::sig::kPlatformLinuxX64,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(ds::sig::HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ds::sig::ResolveKind::FdeEntry),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        {
                .owner = "core.vm",
                .name = "core.vm.register_debug_getsize",
                .description = "Engine debug.getsize registration helper (linux-x64, FDE entry)",
                .patterns = {"48 8B 45 18 48 89 EF 48 8B 40 10 48 8B 70 20"},
                .pattern_offset = 0,
                .platform_mask = ds::sig::kPlatformLinuxX64,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(ds::sig::HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ds::sig::ResolveKind::FdeEntry),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        {
                .owner = "core.vm",
                .name = "core.vm.execution_error",
                .description = "Engine execution-error storage helper (linux-x64, 759671 body)",
                .patterns = {"F3 0F 1E FA 48 83 3D ?? ?? ?? ?? 00 74 02 C3 90 "
                             "41 54 55 48 89 FD 53 48 85 FF 74 ?? "
                             "4C 8D 25 ?? ?? ?? ?? 4C 39 E7 74 ?? "
                             "E8 ?? ?? ?? ?? 48 89 C3 48 3D FF 0F 00 00 76 ?? "
                             "BB FF 0F 00 00 EB ?? 90 48 83 EB 01 74 ?? "
                             "0F B6 44 1D 00 83 E0 C0 3C 80 74 ?? "
                             "B9 00 10 00 00 48 89 DA 48 89 EE 48 8D 3D ?? ?? ?? ?? "
                             "E8 ?? ?? ?? ?? 41 C6 04 1C 00 5B 5D"},
                .pattern_offset = 0,
                .platform_mask = ds::sig::kPlatformLinuxX64,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(ds::sig::HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ds::sig::ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = &verify_execution_error,
        },
};
#elif defined(DS_SIG_TARGET_MACOS_X64) || defined(DS_SIG_TARGET_MACOS_ARM64)
ds::sig::EntryDef g_entries[] = {
        // macOS also pins body offsets; the getsize helper is matched by its
        // symbol shape, and there is no version.txt — the embedded 6-character
        // version string is the only version source.
        {
                .owner = "core.vm",
                .name = "core.vm.lua_module",
                .description = "Lua module anchor (macos, luaA_pushobject body)",
                .patterns = {"89 48 08 48 83 47 10 10 C3"},
                .pattern_offset = -0xD,
                .platform_mask = ds::sig::kPlatformMacosX64,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(ds::sig::HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ds::sig::ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        {
                .owner = "core.vm",
                .name = "core.vm.register_debug_getsize",
                .description = "Engine debug.getsize registration helper (macos)",
                .patterns = {"53 48 8B 47 18 8B 48 08 FF C9 83 F9 08"},
                .pattern_offset = 0,
                .platform_mask = ds::sig::kPlatformMacosX64,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(ds::sig::HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ds::sig::ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        {
                .owner = "core.vm",
                .name = "core.vm.macos_version",
                .description = "macOS embedded version-string accessor (6-character .rodata lea)",
                .patterns = {"48 8D 05 ?? ?? ?? ?? C3"},
                .pattern_offset = 0,
                .platform_mask =
#if defined(DS_SIG_TARGET_MACOS_ARM64)
                        ds::sig::kPlatformMacosArm64,
#else
                        ds::sig::kPlatformMacosX64,
#endif
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(ds::sig::HitsPolicy::FilteredLowest),
                .resolve_kind = static_cast<int32_t>(ds::sig::ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_macos_version,
        },
};
#endif

const ds::sig::ProviderDesc g_desc{
        .owner = "core.vm",
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

namespace {
std::atomic<uintptr_t> g_lua_module_base{0};
} // namespace

uintptr_t lua_module_base() {
    return g_lua_module_base.load(std::memory_order_acquire);
}

void set_lua_module_base(uintptr_t base) {
    g_lua_module_base.store(base, std::memory_order_release);
}

intptr_t read_game_version_from_memory() {
#if defined(__APPLE__)
    ds::sig::ContextView ctx{};
    ctx.platform = ds::sig::host_platform();
    ctx.is_client = 1;
    ds::sig::ProviderV1 table{};
    if (!ds::sig::make_provider(&g_desc, &table)) {
        return -1;
    }
    ds::sig::ResolveReport report{};
    if (!table.resolve(table.self, "core.vm.macos_version", &ctx, &report)) {
        spdlog::warn("[core.vm] macOS version probe failed: {}", report.detail);
        return -1;
    }
    const auto *text = reinterpret_cast<const char *>(report.target_va);
    uintptr_t version = 0;
    const auto parsed = std::from_chars(text, text + 6, version);
    if (parsed.ec != std::errc{}) {
        return -1;
    }
    return static_cast<intptr_t>(version);
#else
    return -1;
#endif
}

} // namespace ds::core_vm
