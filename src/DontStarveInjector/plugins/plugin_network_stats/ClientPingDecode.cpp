// ClientPingDecode.cpp — x86-64 shape decoder for cNetworkClientObject2::UpdateNetStats.
//
// The function is located by byte signature (ClientPingHook.cpp). This file
// re-derives every structure offset from the decoded instruction window instead
// of hardcoding addresses/offsets, per the project's signature-first rule.
//
// Hard rules (any failure => fail closed; caller disables the feature):
//   1. clamp constant family (0x1869E / 0x1869F) appears at least twice (shape);
//   2. the 10-byte GUID pair (MOV r64,[this+a] / MOVZX r32,word [this+a+8]) is
//      copied into a stack buffer, with `this` derived from the first argument;
//      the pair must be unique in the window;
//   3. the listing pointer is the LEA/MOV of [this+disp] feeding a direct call's
//      1st argument, consistent across all candidates;
//   4. the stats ring: pointer field used with scaled indexing, accumulator
//      pointer field updated via ADD, inline byte index with a matching load and
//      store, slot count from IMUL ...,N stored into the accumulator's first
//      field, cross-checked against a 1/N float constant referenced in-window.
// Rule 4 supplies the RTT itself: the ring's newest slot is the value the engine
// measured for this tick.

#include "ClientPingDecode.hpp"

#if defined(_M_X64) || defined(__x86_64__)

#include "ctx.hpp"
#include "disasm.h"

// frida-gum.h embeds the Capstone API (cs_disasm_iter / x86_reg / x86_insn ids).
#include <frida-gum.h>

#include <cmath>
#include <cstring>
#include <expected>
#include <vector>

namespace ds::net_stats {
namespace {

constexpr size_t kMaxWindow = 0x800;
constexpr size_t kMinWindow = 0x40;
constexpr uint64_t kClampHi = 0x1869Fu;        // 99999
constexpr uint64_t kClampHiMinusOne = 0x1869Eu; // 99998

constexpr int kArg0FamilyMsX64 = 2; // RCX
constexpr int kArg0FamilySysV = 5;  // RDI
constexpr int kRspFamily = 7;
constexpr int kRipFamily = -2;

struct Gpr {
    int family;
    int width;
};

Gpr gpr_of(uint16_t reg) {
    switch (reg) {
        case X86_REG_RAX: return {0, 8};
        case X86_REG_EAX: return {0, 4};
        case X86_REG_AX: return {0, 2};
        case X86_REG_AL:
        case X86_REG_AH: return {0, 1};
        case X86_REG_RBX: return {1, 8};
        case X86_REG_EBX: return {1, 4};
        case X86_REG_BX: return {1, 2};
        case X86_REG_BL:
        case X86_REG_BH: return {1, 1};
        case X86_REG_RCX: return {2, 8};
        case X86_REG_ECX: return {2, 4};
        case X86_REG_CX: return {2, 2};
        case X86_REG_CL:
        case X86_REG_CH: return {2, 1};
        case X86_REG_RDX: return {3, 8};
        case X86_REG_EDX: return {3, 4};
        case X86_REG_DX: return {3, 2};
        case X86_REG_DL:
        case X86_REG_DH: return {3, 1};
        case X86_REG_RSI: return {4, 8};
        case X86_REG_ESI: return {4, 4};
        case X86_REG_SI: return {4, 2};
        case X86_REG_SIL: return {4, 1};
        case X86_REG_RDI: return {5, 8};
        case X86_REG_EDI: return {5, 4};
        case X86_REG_DI: return {5, 2};
        case X86_REG_DIL: return {5, 1};
        case X86_REG_RBP: return {6, 8};
        case X86_REG_EBP: return {6, 4};
        case X86_REG_BP: return {6, 2};
        case X86_REG_BPL: return {6, 1};
        case X86_REG_RSP: return {7, 8};
        case X86_REG_ESP: return {7, 4};
        case X86_REG_SP: return {7, 2};
        case X86_REG_SPL: return {7, 1};
        case X86_REG_R8: return {8, 8};
        case X86_REG_R8D: return {8, 4};
        case X86_REG_R8W: return {8, 2};
        case X86_REG_R8B: return {8, 1};
        case X86_REG_R9: return {9, 8};
        case X86_REG_R9D: return {9, 4};
        case X86_REG_R9W: return {9, 2};
        case X86_REG_R9B: return {9, 1};
        case X86_REG_R10: return {10, 8};
        case X86_REG_R10D: return {10, 4};
        case X86_REG_R10W: return {10, 2};
        case X86_REG_R10B: return {10, 1};
        case X86_REG_R11: return {11, 8};
        case X86_REG_R11D: return {11, 4};
        case X86_REG_R11W: return {11, 2};
        case X86_REG_R11B: return {11, 1};
        case X86_REG_R12: return {12, 8};
        case X86_REG_R12D: return {12, 4};
        case X86_REG_R12W: return {12, 2};
        case X86_REG_R12B: return {12, 1};
        case X86_REG_R13: return {13, 8};
        case X86_REG_R13D: return {13, 4};
        case X86_REG_R13W: return {13, 2};
        case X86_REG_R13B: return {13, 1};
        case X86_REG_R14: return {14, 8};
        case X86_REG_R14D: return {14, 4};
        case X86_REG_R14W: return {14, 2};
        case X86_REG_R14B: return {14, 1};
        case X86_REG_R15: return {15, 8};
        case X86_REG_R15D: return {15, 4};
        case X86_REG_R15W: return {15, 2};
        case X86_REG_R15B: return {15, 1};
        case X86_REG_RIP: return {kRipFamily, 8};
        default: return {-1, 0};
    }
}

int family_of(uint16_t reg) { return gpr_of(reg).family; }
bool is_gpr(uint16_t reg, int width) {
    const auto g = gpr_of(reg);
    return g.family >= 0 && g.width == width;
}
bool is_reg(uint16_t reg) { return gpr_of(reg).family >= 0; }

struct OpInfo {
    uint8_t type = 0;
    uint16_t reg = 0;
    uint16_t memBase = 0;
    uint16_t memIndex = 0;
    uint32_t memScale = 0;
    int64_t memDisp = 0;
    uint8_t size = 0;
    int64_t imm = 0;
};

struct InsnInfo {
    uintptr_t addr = 0;
    uint8_t size = 0;
    uint16_t id = 0;
    uint8_t opCount = 0;
    OpInfo ops[4];
    uint16_t written[12];
    uint8_t writtenCount = 0;
};

// True when operand 0 is a genuine destination for this instruction. Tested
// against the real windows: read-only first operands (CMP/TEST/PUSH) must not
// count as register definitions, otherwise a `test rsi,rsi` between two chain
// loads shadows the real `mov rsi,[rax+disp]` definition.
bool op0_is_destination(uint16_t id, uint8_t op_count) {
    switch (id) {
        case X86_INS_MOV:
        case X86_INS_MOVZX:
        case X86_INS_MOVSX:
        case X86_INS_MOVSXD:
        case X86_INS_MOVBE:
        case X86_INS_LEA:
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_ADC:
        case X86_INS_SBB:
        case X86_INS_AND:
        case X86_INS_OR:
        case X86_INS_XOR:
        case X86_INS_INC:
        case X86_INS_DEC:
        case X86_INS_NEG:
        case X86_INS_NOT:
        case X86_INS_SHL:
        case X86_INS_SHR:
        case X86_INS_SAR:
        case X86_INS_ROL:
        case X86_INS_ROR:
        case X86_INS_RCL:
        case X86_INS_RCR:
        case X86_INS_POP:
        case X86_INS_BSWAP:
        case X86_INS_XCHG:
        case X86_INS_XADD:
        case X86_INS_BSF:
        case X86_INS_BSR:
        case X86_INS_LZCNT:
        case X86_INS_TZCNT:
        case X86_INS_BTS:
        case X86_INS_BTR:
        case X86_INS_BTC:
        case X86_INS_CMPXCHG:
        case X86_INS_ADCX:
        case X86_INS_ADOX:
        case X86_INS_CMOVA:
        case X86_INS_CMOVAE:
        case X86_INS_CMOVB:
        case X86_INS_CMOVBE:
        case X86_INS_CMOVE:
        case X86_INS_CMOVG:
        case X86_INS_CMOVGE:
        case X86_INS_CMOVL:
        case X86_INS_CMOVLE:
        case X86_INS_CMOVNE:
        case X86_INS_CMOVNO:
        case X86_INS_CMOVNP:
        case X86_INS_CMOVNS:
        case X86_INS_CMOVO:
        case X86_INS_CMOVP:
        case X86_INS_CMOVS:
            return true;
        case X86_INS_IMUL:
            return op_count >= 2; // 1-operand form uses EDX:EAX, op0 is the source
        default:
            return false; // CMP / TEST / PUSH / JMP / CALL / BT / ...: op0 is a source
    }
}

// Implicit GPR writes not visible in the operand list.
void collect_implicit_writes(const InsnInfo &rec, uint16_t *out, uint8_t &n) {
    auto add = [&](int family) {
        if (family < 0 || n >= 12) {
            return;
        }
        for (uint8_t i = 0; i < n; ++i) {
            if (family_of(out[i]) == family) {
                return;
            }
        }
        // Store a canonical 64-bit name for the family.
        static constexpr uint16_t kCanonical[16] = {
            X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI,
            X86_REG_RBP, X86_REG_RSP, X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
            X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
        };
        out[n++] = kCanonical[family];
    };

    switch (rec.id) {
        case X86_INS_MUL:
        case X86_INS_DIV:
        case X86_INS_IDIV:
            add(0); // RAX
            add(3); // RDX
            break;
        case X86_INS_IMUL:
            if (rec.opCount == 1) {
                add(0);
                add(3);
            }
            break;
        case X86_INS_CDQ:
        case X86_INS_CQO:
        case X86_INS_CWD:
            add(3);
            break;
        case X86_INS_CPUID:
            add(0);
            add(1);
            add(2);
            add(3);
            break;
        case X86_INS_RDTSC:
        case X86_INS_RDTSCP:
            add(0);
            add(3);
            break;
        case X86_INS_PUSH:
        case X86_INS_POP:
            add(7); // RSP
            break;
        default:
            break;
    }
}

bool op_is_mem_with_gpr_base(const OpInfo &op) { return op.type == X86_OP_MEM && is_reg(op.memBase) && !is_reg(op.memIndex); }

bool is_conditional_jump(uint16_t id) {
    switch (id) {
        case X86_INS_JAE:
        case X86_INS_JA:
        case X86_INS_JBE:
        case X86_INS_JB:
        case X86_INS_JCXZ:
        case X86_INS_JECXZ:
        case X86_INS_JE:
        case X86_INS_JGE:
        case X86_INS_JG:
        case X86_INS_JLE:
        case X86_INS_JL:
        case X86_INS_JNE:
        case X86_INS_JNO:
        case X86_INS_JNP:
        case X86_INS_JNS:
        case X86_INS_JO:
        case X86_INS_JP:
        case X86_INS_JRCXZ:
        case X86_INS_JS:
            return true;
        default:
            return false;
    }
}

// Linear sweep from the entry with branch-target following. The byte window may
// run past the function end (0x800 > function size), and the neighbouring
// function's code must not feed the rules: it contributes false candidates
// (e.g. its own [this+disp] arguments to direct calls). Bytes that no path from
// the entry reaches are dropped; an indirect jump or return ends a path.
std::vector<InsnInfo> reachable_only(const std::vector<InsnInfo> &insns) {
    const size_t n = insns.size();
    std::vector<uint8_t> visited(n, 0);
    std::vector<uint8_t> keep(n, 0);
    std::vector<size_t> work;
    work.push_back(0);

    auto index_of = [&](uintptr_t addr) -> size_t {
        for (size_t i = 0; i < n; ++i) {
            if (insns[i].addr == addr) {
                return i;
            }
        }
        return n;
    };

    while (!work.empty()) {
        const size_t start = work.back();
        work.pop_back();
        for (size_t i = start; i < n; ++i) {
            if (visited[i] != 0) {
                break; // continuation already walked
            }
            visited[i] = 1;
            keep[i] = 1;
            const InsnInfo &in = insns[i];
            if (is_conditional_jump(in.id)) {
                if (in.opCount >= 1 && in.ops[0].type == X86_OP_IMM) {
                    const size_t target = index_of(static_cast<uintptr_t>(in.ops[0].imm));
                    if (target < n && visited[target] == 0) {
                        work.push_back(target);
                    }
                }
                continue;
            }
            if (in.id == X86_INS_JMP) {
                if (in.opCount >= 1 && in.ops[0].type == X86_OP_IMM) {
                    const size_t target = index_of(static_cast<uintptr_t>(in.ops[0].imm));
                    if (target < n && visited[target] == 0) {
                        work.push_back(target);
                    }
                }
                break;
            }
            if (in.id == X86_INS_RET || in.id == X86_INS_IRET) {
                break;
            }
        }
    }

    std::vector<InsnInfo> out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        if (keep[i] != 0) {
            out.push_back(insns[i]);
        }
    }
    return out;
}

std::expected<std::vector<InsnInfo>, std::string> collect_window(uintptr_t entry) {
    size_t window = kMaxWindow;
    while (window > kMinWindow && !gum_memory_is_readable(reinterpret_cast<gconstpointer>(entry), window)) {
        window >>= 1;
    }
    if (!gum_memory_is_readable(reinterpret_cast<gconstpointer>(entry), window)) {
        return std::unexpected(std::string{"window unreadable"});
    }

    const auto hcs = function_relocation::get_ctx().hcs;
    if (!hcs) {
        return std::unexpected(std::string{"capstone unavailable"});
    }

    const uint8_t *code = reinterpret_cast<const uint8_t *>(entry);
    size_t remaining = window;
    uint64_t address = entry;
    cs_insn *insn = cs_malloc(hcs);
    if (!insn) {
        return std::unexpected(std::string{"capstone alloc failed"});
    }

    std::vector<InsnInfo> out;
    out.reserve(512);
    while (remaining > 0 && cs_disasm_iter(hcs, &code, &remaining, &address, insn)) {
        InsnInfo rec{};
        rec.addr = insn->address;
        rec.size = static_cast<uint8_t>(insn->size);
        rec.id = static_cast<uint16_t>(insn->id);
        const auto &x86 = insn->detail->x86;
        rec.opCount = x86.op_count > 4 ? 4 : static_cast<uint8_t>(x86.op_count);
        for (int i = 0; i < rec.opCount; ++i) {
            const cs_x86_op &op = x86.operands[i];
            OpInfo &o = rec.ops[i];
            o.type = static_cast<uint8_t>(op.type);
            o.size = op.size;
            if (op.type == X86_OP_REG) {
                o.reg = static_cast<uint16_t>(op.reg);
            } else if (op.type == X86_OP_MEM) {
                o.memBase = static_cast<uint16_t>(op.mem.base);
                o.memIndex = static_cast<uint16_t>(op.mem.index);
                o.memScale = op.mem.scale;
                o.memDisp = op.mem.disp;
            } else if (op.type == X86_OP_IMM) {
                o.imm = op.imm;
            }
        }
        // Register writes: operand 0 when it is a genuine destination, plus the
        // implicit GPR writes of the few instructions that have any. Capstone's
        // cs_regs_access is NOT used: it flags read-only operands of CMP/TEST as
        // written on this version, which shadowed real definitions in the chain
        // walk (test rsi,rsi between the two chain loads).
        uint8_t n = 0;
        if (rec.opCount >= 1 && rec.ops[0].type == X86_OP_REG && is_reg(rec.ops[0].reg) &&
            op0_is_destination(rec.id, rec.opCount)) {
            rec.written[n++] = rec.ops[0].reg;
        }
        collect_implicit_writes(rec, rec.written, n);
        rec.writtenCount = n;
        out.push_back(rec);
    }
    cs_free(insn, 1);

    if (out.empty()) {
        return std::unexpected(std::string{"no instructions decoded"});
    }
    return out;
}

} // namespace

std::expected<NetStatsLayout, std::string> decode_net_stats(uintptr_t entry, PingCallConv conv) {
    if (conv == PingCallConv::Host) {
#if defined(_WIN32)
        conv = PingCallConv::MsX64;
#else
        conv = PingCallConv::SysV;
#endif
    }
    const int arg0Family = (conv == PingCallConv::MsX64) ? kArg0FamilyMsX64 : kArg0FamilySysV;
    if (entry == 0) {
        return std::unexpected(std::string{"null anchor"});
    }

    auto collected = collect_window(entry);
    if (!collected) {
        return std::unexpected(std::move(collected.error()));
    }
    const std::vector<InsnInfo> insns = reachable_only(*collected);
    if (insns.empty()) {
        return std::unexpected(std::string{"no reachable instructions"});
    }

    auto fail = [](const char *msg) -> std::expected<NetStatsLayout, std::string> {
        return std::unexpected(std::string{msg});
    };

    auto insn_writes = [&](size_t idx, int family) {
        for (uint8_t i = 0; i < insns[idx].writtenCount; ++i) {
            if (family_of(insns[idx].written[i]) == family) {
                return true;
            }
        }
        return false;
    };
    auto nearest_writer = [&](int family, size_t before) -> int {
        if (family < 0 || before > insns.size()) {
            return -1;
        }
        for (size_t i = before; i-- > 0;) {
            if (insn_writes(i, family)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    };

    // --- Rule 1: clamp constant family -------------------------------------
    int clampCount = 0;
    for (const auto &in : insns) {
        if (in.id == X86_INS_MOV && in.opCount >= 2 && in.ops[0].type == X86_OP_REG && in.ops[1].type == X86_OP_IMM) {
            if (is_gpr(in.ops[0].reg, 4) && static_cast<uint64_t>(in.ops[1].imm) == kClampHi) {
                ++clampCount;
            }
        } else if (in.id == X86_INS_CMP && in.opCount >= 2 && in.ops[0].type == X86_OP_REG &&
                   in.ops[1].type == X86_OP_IMM) {
            const uint64_t v = static_cast<uint64_t>(in.ops[1].imm);
            if (is_gpr(in.ops[0].reg, 4) && (v == kClampHi || v == kClampHiMinusOne)) {
                ++clampCount;
            }
        }
    }
    if (clampCount < 2) {
        return fail("clamp constants < 2");
    }

    // --- Rule 2: the 10-byte RakNetGUID, copied out of the first argument --
    // Shape: MOV [rsp+d], r64    where r64 <- MOV r64,[X+off]
    //        MOV [rsp+d+8], r16  where r16 <- MOVZX r32,word [X+off+8]
    // and X is the first-argument register (or a copy of it). Uniqueness is
    // required; a second validating pair fails closed.
    int thisFamily = -1;
    int pairs = 0;
    for (size_t i = 0; i < insns.size(); ++i) {
        const auto &qst = insns[i];
        if (qst.id != X86_INS_MOV || qst.opCount < 2 || qst.ops[0].type != X86_OP_MEM ||
            qst.ops[0].size != 8 || qst.ops[1].type != X86_OP_REG || qst.ops[1].size != 8 ||
            family_of(qst.ops[0].memBase) != kRspFamily || is_reg(qst.ops[0].memIndex)) {
            continue;
        }
        const int64_t qDst = qst.ops[0].memDisp;

        int wIdx = -1;
        for (size_t j = 0; j < insns.size(); ++j) {
            const auto &st = insns[j];
            if (st.id != X86_INS_MOV || st.opCount < 2 || st.ops[0].type != X86_OP_MEM ||
                st.ops[0].size != 2 || st.ops[1].type != X86_OP_REG || st.ops[1].size != 2 ||
                family_of(st.ops[0].memBase) != kRspFamily || is_reg(st.ops[0].memIndex)) {
                continue;
            }
            if (st.ops[0].memDisp == qDst + 8) {
                wIdx = static_cast<int>(j);
                break;
            }
        }
        if (wIdx < 0) {
            continue;
        }

        const int qDef = nearest_writer(family_of(qst.ops[1].reg), i);
        const int wDef = nearest_writer(family_of(insns[wIdx].ops[1].reg), static_cast<size_t>(wIdx));
        if (qDef < 0 || wDef < 0) {
            continue;
        }
        const auto &qd = insns[qDef];
        const auto &wd = insns[wDef];
        if (qd.id != X86_INS_MOV || qd.opCount < 2 || qd.ops[0].type != X86_OP_REG ||
            family_of(qd.ops[0].reg) != family_of(qst.ops[1].reg) || qd.ops[1].type != X86_OP_MEM ||
            !is_reg(qd.ops[1].memBase) || is_reg(qd.ops[1].memIndex) || qd.ops[1].size != 8) {
            continue;
        }
        if ((wd.id != X86_INS_MOVZX && wd.id != X86_INS_MOVSX) || wd.opCount < 2 ||
            wd.ops[0].type != X86_OP_REG ||
            family_of(wd.ops[0].reg) != family_of(insns[wIdx].ops[1].reg) ||
            wd.ops[1].type != X86_OP_MEM || !is_reg(wd.ops[1].memBase) || is_reg(wd.ops[1].memIndex) ||
            wd.ops[1].size != 2) {
            continue;
        }
        const int fam = family_of(qd.ops[1].memBase);
        if (fam != family_of(wd.ops[1].memBase) || wd.ops[1].memDisp != qd.ops[1].memDisp + 8) {
            continue;
        }

        // The base register must be the first argument, either directly or via
        // a single register-to-register copy.
        bool from_arg0 = false;
        {
            const size_t upto = static_cast<size_t>(qDef < wDef ? qDef : wDef);
            const int thisDef = nearest_writer(fam, upto);
            if (thisDef < 0) {
                from_arg0 = (fam == arg0Family);
            } else {
                const auto &td = insns[thisDef];
                from_arg0 = td.id == X86_INS_MOV && td.opCount >= 2 && td.ops[0].type == X86_OP_REG &&
                            family_of(td.ops[0].reg) == fam && td.ops[1].type == X86_OP_REG &&
                            family_of(td.ops[1].reg) == arg0Family;
            }
        }
        if (!from_arg0) {
            continue;
        }

        ++pairs;
        thisFamily = fam;
    }
    if (pairs == 0) {
        return fail("guid pair not found");
    }
    if (pairs > 1) {
        return fail("guid pair ambiguous");
    }

    // --- Rule 3: listing pointer (1st argument of a direct call) -----------
    uint32_t listingOff = 0;
    {
        std::vector<int64_t> candidates;
        for (size_t i = 0; i < insns.size(); ++i) {
            if (insns[i].id != X86_INS_CALL || insns[i].opCount < 1 || insns[i].ops[0].type != X86_OP_IMM) {
                continue;
            }
            const int def = nearest_writer(arg0Family, i);
            if (def < 0) {
                continue;
            }
            const auto &in = insns[def];
            if (in.opCount < 2 || in.ops[0].type != X86_OP_REG || family_of(in.ops[0].reg) != arg0Family) {
                continue;
            }
            if ((in.id == X86_INS_LEA || in.id == X86_INS_MOV) && in.ops[1].type == X86_OP_MEM &&
                family_of(in.ops[1].memBase) == thisFamily && !is_reg(in.ops[1].memIndex)) {
                candidates.push_back(in.ops[1].memDisp);
            }
        }
        if (candidates.empty()) {
            return fail("listing offset not found");
        }
        for (const int64_t d : candidates) {
            if (d != candidates.front()) {
                return fail("listing candidates inconsistent");
            }
        }
        if (candidates.front() < 0 || candidates.front() > 0x800) {
            return fail("listing offset out of range");
        }
        listingOff = static_cast<uint32_t>(candidates.front());
    }

    NetStatsLayout layout{};
    layout.listingOff = listingOff;

    // --- Rule 4: the stats ring (source of the per-tick RTT) ----------------
    uint32_t ringPtrOff = 0;
    uint32_t accumPtrOff = 0;
    uint32_t indexOff = 0;
    uint32_t ringStride = 0;
    bool haveRing = false;
    bool haveAccum = false;
    bool haveIndex = false;

    // (a) ring pointer: loaded from [this+disp], later used as base with a scaled index.
    for (size_t i = 0; i < insns.size() && !haveRing; ++i) {
        const auto &in = insns[i];
        if (in.id != X86_INS_MOV || in.opCount < 2 || in.ops[0].type != X86_OP_REG || in.ops[0].size != 8 ||
            !op_is_mem_with_gpr_base(in.ops[1]) || family_of(in.ops[1].memBase) != thisFamily) {
            continue;
        }
        const int fam = family_of(in.ops[0].reg);
        for (size_t j = i + 1; j < insns.size() && !haveRing; ++j) {
            const auto &use = insns[j];
            for (int k = 0; k < use.opCount; ++k) {
                const auto &op = use.ops[k];
                if (op.type == X86_OP_MEM && family_of(op.memBase) == fam && is_reg(op.memIndex) &&
                    op.memScale > 1 && op.size <= 4) {
                    ringPtrOff = static_cast<uint32_t>(in.ops[1].memDisp);
                    ringStride = op.memScale;
                    haveRing = true;
                    break;
                }
            }
        }
    }

    // (b) accumulator pointer: loaded from [this+disp], later updated via ADD.
    int accumLoadIdx = -1;
    int accumFamily = -1;
    for (size_t i = 0; i < insns.size() && !haveAccum; ++i) {
        const auto &in = insns[i];
        if (in.id != X86_INS_MOV || in.opCount < 2 || in.ops[0].type != X86_OP_REG || in.ops[0].size != 8 ||
            !op_is_mem_with_gpr_base(in.ops[1]) || family_of(in.ops[1].memBase) != thisFamily) {
            continue;
        }
        const int fam = family_of(in.ops[0].reg);
        for (size_t j = i + 1; j < insns.size() && !haveAccum; ++j) {
            const auto &use = insns[j];
            if ((use.id == X86_INS_ADD || use.id == X86_INS_SUB) && use.opCount >= 1 &&
                use.ops[0].type == X86_OP_MEM && family_of(use.ops[0].memBase) == fam &&
                !is_reg(use.ops[0].memIndex) && use.ops[0].memDisp >= 0 && use.ops[0].memDisp <= 7) {
                accumPtrOff = static_cast<uint32_t>(in.ops[1].memDisp);
                accumLoadIdx = static_cast<int>(i);
                accumFamily = fam;
                haveAccum = true;
            }
        }
    }

    // (c) inline byte index: matching byte load + byte store at [this+disp].
    for (size_t i = 0; i < insns.size() && !haveIndex; ++i) {
        const auto &in = insns[i];
        if ((in.id != X86_INS_MOVZX && in.id != X86_INS_MOVSX) || in.opCount < 2 ||
            in.ops[0].type != X86_OP_REG || !op_is_mem_with_gpr_base(in.ops[1]) ||
            family_of(in.ops[1].memBase) != thisFamily || in.ops[1].size != 1) {
            continue;
        }
        const int64_t d = in.ops[1].memDisp;
        for (size_t j = 0; j < insns.size() && !haveIndex; ++j) {
            const auto &st = insns[j];
            if (st.id == X86_INS_MOV && st.opCount >= 2 && st.ops[0].type == X86_OP_MEM &&
                family_of(st.ops[0].memBase) == thisFamily && !is_reg(st.ops[0].memIndex) &&
                st.ops[0].memDisp == d && st.ops[0].size == 1 && st.ops[1].type == X86_OP_REG &&
                st.ops[1].size == 1) {
                indexOff = static_cast<uint32_t>(d);
                haveIndex = true;
            }
        }
    }

    // (d) slot count: IMUL r32,r32,N written into the accumulator's first field.
    uint32_t ringWindow = 0;
    if (haveAccum && accumLoadIdx >= 0) {
        for (size_t j = 0; j < insns.size() && ringWindow == 0; ++j) {
            const auto &st = insns[j];
            if (st.id != X86_INS_MOV || st.opCount < 2 || st.ops[0].type != X86_OP_MEM ||
                st.ops[1].type != X86_OP_REG || !st.ops[1].size || st.ops[1].size != 4) {
                continue;
            }
            if (!is_reg(st.ops[0].memBase) || is_reg(st.ops[0].memIndex) || st.ops[0].memDisp != 0) {
                continue;
            }
            const int baseFamily = family_of(st.ops[0].memBase);
            bool baseFromAccum = false;
            for (size_t k = 0; k < insns.size(); ++k) {
                const auto &ld = insns[k];
                if (ld.id == X86_INS_MOV && ld.opCount >= 2 && ld.ops[0].type == X86_OP_REG &&
                    family_of(ld.ops[0].reg) == baseFamily && ld.ops[1].type == X86_OP_MEM &&
                    is_reg(ld.ops[1].memBase) && family_of(ld.ops[1].memBase) == thisFamily &&
                    !is_reg(ld.ops[1].memIndex) &&
                    static_cast<uint32_t>(ld.ops[1].memDisp) == accumPtrOff) {
                    baseFromAccum = true;
                    break;
                }
            }
            if (!baseFromAccum) {
                continue;
            }
            const int def = nearest_writer(family_of(st.ops[1].reg), j);
            if (def < 0) {
                continue;
            }
            const auto &im = insns[def];
            if (im.id != X86_INS_IMUL || im.opCount < 2) {
                continue;
            }
            int64_t imm = -1;
            if (im.opCount >= 3 && im.ops[2].type == X86_OP_IMM) {
                imm = im.ops[2].imm;
            } else if (im.ops[1].type == X86_OP_IMM) {
                imm = im.ops[1].imm;
            }
            if (imm >= 2 && imm <= 4096) {
                ringWindow = static_cast<uint32_t>(imm);
            }
        }
    }

    // (e) cross-check: a float constant equal to 1/N is referenced in-window.
    bool floatOk = false;
    if (ringWindow != 0) {
        const float want = 1.0f / static_cast<float>(ringWindow);
        for (const auto &in : insns) {
            if (in.id != X86_INS_MULSS && in.id != X86_INS_MOVSS && in.id != X86_INS_DIVSS) {
                continue;
            }
            for (int k = 0; k < in.opCount; ++k) {
                const auto &op = in.ops[k];
                if (op.type != X86_OP_MEM || op.size != 4 || is_reg(op.memIndex)) {
                    continue;
                }
                uintptr_t abs = 0;
                if (op.memBase == X86_REG_RIP) {
                    abs = in.addr + in.size + static_cast<uintptr_t>(static_cast<int64_t>(op.memDisp));
                } else if (!is_reg(op.memBase)) {
                    abs = static_cast<uintptr_t>(static_cast<int64_t>(op.memDisp));
                } else {
                    continue;
                }
                if (!gum_memory_is_readable(reinterpret_cast<gconstpointer>(abs), sizeof(float))) {
                    continue;
                }
                float value = 0.0f;
                std::memcpy(&value, reinterpret_cast<const void *>(abs), sizeof(value));
                if (std::fabs(value - want) < 1e-6f) {
                    floatOk = true;
                    break;
                }
            }
            if (floatOk) {
                break;
            }
        }
    }

    if (!haveRing || !haveAccum || !haveIndex || ringWindow == 0 || !floatOk) {
        return fail("ring layout not found");
    }
    if (ringStride < 2 || ringStride > 64 || ringPtrOff == accumPtrOff || ringPtrOff == indexOff ||
        accumPtrOff == indexOff) {
        return fail("ring layout inconsistent");
    }
    layout.ringPtrOff = ringPtrOff;
    layout.indexOff = indexOff;
    layout.ringWindow = ringWindow;
    layout.ringStride = ringStride;

    return layout;
}

} // namespace ds::net_stats

#else // !x86-64 build: decoder is empty, the caller stays disabled.

namespace ds::net_stats {

std::expected<NetStatsLayout, std::string> decode_net_stats(uintptr_t, PingCallConv) {
    return std::unexpected(std::string{"unsupported architecture"});
}

} // namespace ds::net_stats

#endif
