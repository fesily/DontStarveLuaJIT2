#include <algorithm>
#include <cassert>
#include <functional>
#include <numbers>
#include <optional>
#include <ranges>
#include <regex>
#include <string_view>

#include <frida-gum.h>
#if defined(__linux__)
#include <keystone/keystone.h>
#endif
#include <range/v3/all.hpp>
#include <spdlog/spdlog.h>

#include "Signature.hpp"

#include "MemorySignature.hpp"
#include "ModuleSections.hpp"
#include "FunctionTable.hpp"
#include "ctx.hpp"
#include "disasm.h"
#include "config.hpp"
#include "MatchPolicy.hpp"
#include "MicroWindow.hpp"

#include <cstring>
#include <numeric>
#include <set>
#include <unordered_set>

// Soft-match accept policy primitives (plan: function-relocation-match-v2
// todo 1). Constants and accept_candidates live in match_policy; bring them
// into file scope so the soft path can call them and so the locked values
// are pinned at compile time. Scores are never serialized to SignatureInfo.
namespace {
    using namespace function_relocation::match_policy;
    using function_relocation::match_policy::MatchCandidate;
    using function_relocation::match_policy::AcceptResult;
    using function_relocation::match_policy::accept_candidates;
    // Compile-time pin of the locked accept constants. If the plan values
    // drift, this static_assert fires and forces an explicit plan update.
    static_assert(SCORE_T == 3.0f, "SCORE_T locked by plan");
    static_assert(SCORE_M == 1.5f, "SCORE_M locked by plan");
    static_assert(W_CONST == 10.0f, "W_CONST locked by plan");
    static_assert(W_IMM == 4.0f, "W_IMM locked by plan");
    static_assert(W_SIZE == 2.0f, "W_SIZE locked by plan");
    static_assert(W_VOTE_CAP == 8.0f, "W_VOTE_CAP locked by plan");
    static_assert(W_VOTE_PER_WINDOW == 1.0f, "W_VOTE_PER_WINDOW locked by plan");
    static_assert(W_CALL_STILL == 1.0f, "W_CALL_STILL locked by plan");
    static_assert(W_CALL_INLINED == 0.8f, "W_CALL_INLINED locked by plan");
    static_assert(W_CALL_MISSING == -0.5f, "W_CALL_MISSING locked by plan");
} // namespace

static gboolean
gum_memory_is_execute(gconstpointer address,
                      gsize len) {
    GumPageProtection prot;
    if (!gum_memory_query_protection(address, &prot)) return FALSE;
    return (prot & GUM_PAGE_EXECUTE) != 0;
}

using namespace std::literals;

namespace function_relocation {

    using in_function_t = std::function<bool(void *)>;

    static std::string to_hex(const uint8_t *first, const uint8_t *last) {
        const auto length = last - first;
        std::string res;
        for (int i = 0; i < length; ++i) { res.append(fmt::format("{:0>2x} ", first[i])); }
        return res;
    }

    static std::string make_unknown_string(size_t length) {
        std::string res;
        res.reserve(length * 2);
        for (int i = 0; i < length; ++i) { res.append("?? "); }
        return res;
    }

    std::string Signature::to_string(bool lineMode) const {
        size_t length = 0;
        for (auto &code: this->asm_codes) { length += code.size(); }
        std::string ret;
        ret.reserve(length + (lineMode ? asm_codes.size() : 1));
        for (auto &code: this->asm_codes) {
            ret.append(code);
            if (lineMode) ret.append("\n");
        }
        return ret;
    }

    bool Signature::operator==(const Signature &other) const {
        if (this->asm_codes.size() != other.asm_codes.size()) return false;
        for (size_t i = 0; i < this->asm_codes.size(); i++) {
            if (this->asm_codes[i] != other.asm_codes[i]) return false;
        }
        return true;
    }

    // Forward declaration: calcBlockScore is defined after Creator but used by
    // the micro-window generator to weight windows by their containing block.
    static float calcBlockScore(CodeBlock *l);

    static auto regx1 = std::regex(R"(\[r(.)x \+ rax\*(\d+) (\+\-) 0x([0-9a-z]+)\])");
    static auto regx2 = std::regex("0x[0-9a-z]+");

    struct Creator {


        bool is_valid_remote_offset(int64_t offset, uintptr_t address) {
            if (target) { return target->in_rodata(address); }
            return offset >= std::numeric_limits<short>::min() && offset <= std::numeric_limits<short>::max();
        }

        void
        filter_signature(cs_insn *insn, uint64_t &maybe_end, decltype(Signature::asm_codes) &asm_codes) {
            const auto &csX86 = insn->detail->x86;
            std::string op_str = insn->op_str;
#ifdef __linux__
            // linux上fpic生成的so跟直接生成应用程序的二进制上，对于加载确定的位置内存方式有一些差别
            // 把类似与 mov reg, 0x????? 转成 lea reg, [rip + 0x????]
            if (insn->id == X86_INS_MOV && csX86.op_count == 2) {
                if (csX86.operands[0].type == x86_op_type::X86_OP_REG &&
                    csX86.operands[1].type == x86_op_type::X86_OP_IMM) {
                    auto imm = csX86.operands[1].imm;
                    if (is_valid_remote_offset(imm, insn->address + insn->size + imm)) {
                        asm_codes.push_back("lea");
                        asm_codes.push_back(std::regex_replace(op_str, regx2,
                                                               imm > 0 ? "[rip + 0x?]" : "[rip - 0x?]"));
                        return;
                    }
                }
            }
#endif
            std::string signature = op_str;
            int64_t imm = 0;
            bool rva = false;
            if (csX86.disp != 0 && csX86.op_count == 2) {
                const auto &operand = csX86.operands[1];
                if (operand.type == X86_OP_MEM) {
                    if (operand.mem.base == X86_REG_RIP) {
                        signature = std::regex_replace(op_str, regx2,
                                                       csX86.disp > 0 ? "[rip + 0x?]" : "[rip - 0x?]");
                        rva = insn->id == X86_INS_JMP || insn->id == X86_INS_CALL;
                    } else if (operand.mem.index != X86_REG_INVALID) {
                        signature = std::regex_replace(op_str, regx1, "[r$1x + rax*$2 $3 0x?]");
                    }
                }
            } else if (csX86.op_count == 1) {
                const auto &operand = csX86.operands[0];
                if (operand.type == X86_OP_IMM) {
                    imm = operand.imm;
                    if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS) {
                        signature = "0x?";
                    } else {
                        maybe_end = std::max(maybe_end, static_cast<uint64_t>(imm));
                        const int64_t offset = imm - (insn->address + insn->size);
                        signature = std::to_string(offset);
                    }
                }
            }
            do {
                if (insn->id == X86_INS_JMP || insn->id == X86_INS_CALL) {
                    if (imm != 0) {
                        auto data = (void *) imm;

                        if (rva && !gum_memory_is_execute(data, sizeof(void *))) {
                            data = *static_cast<void **>(data);
                            if (!gum_memory_is_execute(data, sizeof(void *))) break;
                        }
                        signature.clear();
                        const auto sub_signatures = create_signature(data, nullptr, insn->id == X86_INS_CALL ? 4 : 1);
                        if (sub_signatures.size() > 0) {
                            asm_codes.insert(asm_codes.end(), sub_signatures.asm_codes.cbegin(),
                                             sub_signatures.asm_codes.cend());
                            return;
                        }
                    }
                }
            } while (false);
            asm_codes.push_back(insn->mnemonic);
            asm_codes.push_back(std::move(signature));
        }

        Signature create_signature(void *func, const in_function_t &in_func, size_t limit = static_cast<size_t>(-1)) {
            Signature ret;

            const uint8_t *binary = static_cast<uint8_t *>(func);
            const auto hcs = get_ctx().hcs;
            const auto insn = cs_malloc(hcs);
            uint64_t address = (uint64_t) func;
            size_t insn_len = 1024;
            size_t count = 0;
            uint64_t maybe_end = 0;
            while (cs_disasm_iter(hcs, &binary, &insn_len, &address, insn)) {
                if (count >= limit) break;

                count++;

                filter_signature(insn, maybe_end, ret.asm_codes);
                if (insn->id == X86_INS_JMP || insn->id == X86_INS_INT3 || insn->id == X86_INS_RET ||
                    insn->id == X86_INS_CALL) {
                    if (maybe_end >= (insn->address + insn->size)) continue;
                    if (!in_func || !in_func((void *) (insn->address + insn->size))) { break; }
                }
            }
            cs_free(insn, 1);
            return ret;
        }

#if defined(__linux__)
        std::vector<uint8_t> AsmX86(const char *CODE) {
            ks_engine *ks;
            ks_err err;
            size_t count;
            unsigned char *encode;
            size_t size;

            err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
            if (err != KS_ERR_OK) {
                spdlog::get(logger_name)->error("ERROR: failed on ks_open(), quit");
                return {};
            }

            if (ks_asm(ks, CODE, 0, &encode, &size, &count) != KS_ERR_OK) {
                spdlog::get(logger_name)->error("ERROR: ks_asm() failed & count = {}, error = {}",
                                                count, (int) ks_errno(ks));
            }
            std::vector<uint8_t> res{encode, encode + size};
            // NOTE: free encode after usage to avoid leaking memory
            ks_free(encode);

            // close Keystone instance when done
            ks_close(ks);

            return res;
        }

#endif
        std::pair<Signature, uintptr_t>
        create_signature(ModuleSections *section, uint8_t *address, size_t size, size_t max_len, int offset) {
            Signature signature{};
            disasm ds{address, size};
            bool skip_next_one = false;
            uintptr_t real_address = (uintptr_t) address;
            for (const auto &insn: ds) {
                if (offset-- > 0) {
                    real_address = insn.address + insn.size;
                    continue;
                }
                if (max_len-- == 0) break;
                if (skip_next_one) {
                    skip_next_one = false;
                    continue;
                }
                const auto &details = insn.detail->x86;
                const auto &operand0 = details.operands[0];
                const auto &operand1 = details.operands[1];
                switch (insn.id) {
                    case X86_INS_JMP:
                    case X86_INS_CALL:
                        if (operand1.type == X86_OP_MEM || operand0.type == X86_OP_IMM) {
                            auto pref = fmt::format("{:0>2x} ", insn.bytes[0]);
                            signature.asm_codes.push_back(pref + make_unknown_string(insn.size - 1));
                            continue;
                        }
                        break;
                    case X86_INS_LEA:
                    case X86_INS_MOV:
#if defined(__linux__)
                        // `mov exx 0x?????`
                        if (insn.id == X86_INS_MOV && operand1.type == X86_OP_IMM && operand0.type == X86_OP_REG) {
                            if (section->in_module(operand1.imm)) {
                                assert(insn.size == 5);
                                signature.asm_codes.push_back(
                                        to_hex(insn.bytes, insn.bytes + 1) + make_unknown_string(insn.size - 1));
                                continue;
                            }
                        }
#endif
                        if (operand1.type == X86_OP_MEM && details.disp != 0 && operand1.mem.base == X86_REG_RIP) {
                            // Keep opcode/ModRM; only mask the RIP displacement so the
                            // pattern still self-matches on train (LEA→MOV rewrite used
                            // to produce `b8/b9 ??…` that never hits train's `48 8d …`).
                            // Game absolute `mov reg, imm` is handled by unique_const xrefs.
                            auto bytes = insn.bytes;
                            auto size = insn.size;
                            if (size >= 4) {
                                signature.asm_codes.push_back(
                                        to_hex(bytes, bytes + 3) + make_unknown_string(size - 3));
                                continue;
                            }
                            break;
                        }
                        break;
                }
                signature.asm_codes.push_back(to_hex(insn.bytes, insn.bytes + insn.size));
            }
            return {signature, real_address};
        }

        // Training scan: pattern_offset is relative to original entry (usually <= 0).
        // Target scan: pattern_offset=0 raw matches, then resolve via target FunctionTable.
        void *scan_by_signature(const std::string &signature, int signature_offset, bool skip_check = false) {
            if (!original || original->size == 0) {
                if (auto logger = spdlog::get(logger_name)) {
                    logger->error("scan_by_signature: original body size is 0 (need Nucleus sizes) for {}",
                                  original ? original->name : "<null>");
                }
                return nullptr;
            }

            // Validate pattern uniqueness on training module against original entry.
            // Scan .text only: full module range on ELF includes PROT_NONE gaps that
            // SIGSEGV under gum_memory_scan (seen on signature_updater create luaL_openlibs).
            MemorySignature scan1{signature.c_str(), signature_offset, false};
            scan1.log = !nolog;
            const auto &train_text = original->module->text;
            if (train_text.base_address == 0 || train_text.size == 0) {
                if (auto logger = spdlog::get(logger_name)) {
                    logger->error("scan_by_signature: training module has empty .text");
                }
                return nullptr;
            }
            scan1.scan(train_text.base_address, train_text.size);
            if (!skip_check && scan1.targets.size() != 1) return nullptr;

            const auto training_hit = scan1.target_address;
            const bool train_ok = !scan1.targets.empty();
            if (!skip_check) {
                if (training_hit != original->address) {
                    return nullptr;
                }
                // match_addr = training_hit - signature_offset must sit in Nucleus body.
                const intptr_t train_match =
                        static_cast<intptr_t>(training_hit) - static_cast<intptr_t>(signature_offset);
                if (train_match < static_cast<intptr_t>(original->address) ||
                    train_match >= static_cast<intptr_t>(original->address + original->size)) {
                    if (auto logger = spdlog::get(logger_name)) {
                        logger->warn("scan_by_signature: training match {:#x} outside body [{:#x},{:#x})",
                                     train_match, original->address, original->address + original->size);
                    }
                    return nullptr;
                }
            } else if (train_ok && training_hit != 0 && training_hit != original->address) {
                if (auto logger = spdlog::get(logger_name)) {
                    logger->debug("scan_by_signature: skip_check training hit {:#x} != entry {:#x}",
                                  training_hit, original->address);
                }
            }

            if (target->function_table.empty()) {
                if (auto logger = spdlog::get(logger_name)) {
                    logger->error("scan_by_signature: target FunctionTable empty; run apply_nucleus_function_table");
                }
                return nullptr;
            }

            // Target: raw pattern matches (offset 0), resolve entry via containing().
            MemorySignature scan{signature.c_str(), /*pattern_offset=*/0, false};
            scan.log = !nolog;
            assert(limit_address > target->text.base_address);
            scan.scan(limit_address, target->text.size - (limit_address - target->text.base_address));

            std::vector<uintptr_t> raw_matches = scan.targets;
            if (raw_matches.empty()) {
                // Also collect from full-text scan fallback? stick to limit window.
                return nullptr;
            }

            // Keep matches that fall in a known target function at/after limit.
            std::vector<std::pair<uintptr_t, uint64_t>> resolved; // match, entry
            for (auto match: raw_matches) {
                if (match < limit_address) continue;
                const uint64_t entry = target->function_table.containing(match);
                if (entry == 0) continue;
                if (entry < limit_address) continue;
                resolved.emplace_back(match, entry);
            }

            if (resolved.empty()) {
                // Record raw matches for LCS fallback path (as process VAs of match sites).
                auto ptrs = raw_matches | std::views::transform([](auto v) {
                    return reinterpret_cast<void *>(v);
                });
                function_address.insert(function_address.end(), ptrs.begin(), ptrs.end());
                return nullptr;
            }

            // Require a unique entry among resolved matches.
            uint64_t unique_entry = resolved.front().second;
            uintptr_t unique_match = resolved.front().first;
            bool unique = true;
            for (size_t i = 1; i < resolved.size(); ++i) {
                if (resolved[i].second != unique_entry) {
                    unique = false;
                    break;
                }
                // Prefer the earliest match for the same entry.
                if (resolved[i].first < unique_match) {
                    unique_match = resolved[i].first;
                }
            }

            if (!unique) {
                // Ambiguous entries — keep candidates for LCS fallback.
                for (const auto &[match, entry]: resolved) {
                    (void)match;
                    function_address.push_back(reinterpret_cast<void *>(entry));
                }
                return nullptr;
            }

            // Target-local pattern_offset only: entry - match.
            const int target_po =
                    static_cast<int>(static_cast<intptr_t>(unique_entry) - static_cast<intptr_t>(unique_match));
            last_training_offset = signature_offset;
            if (signature_info) {
                signature_info->pattern = signature;
                signature_info->pattern_offset = target_po;
            }
            return reinterpret_cast<void *>(unique_entry);
        }

        static auto trim(std::string s) {
            while (s.front() == '?' || s.front() == ' ') {
                s.erase(s.begin());
            }
            while (s.back() == '?' || s.back() == ' ') {
                s.pop_back();
            }
            return s;
        }

        void *scan_by_block(ModuleSections *section, CodeBlock *block) {
            if (!original || original->size == 0) {
                if (auto logger = spdlog::get(logger_name)) {
                    logger->error("scan_by_block: original->size==0 for {}; refusing to invent body",
                                  original ? original->name : "<null>");
                }
                return nullptr;
            }

            const uint64_t body_begin = original->address;
            const uint64_t body_end = original->address + original->size; // exclusive

            // Reject blocks that do not overlap the Nucleus body at all.
            if (block->address >= body_end || block->address + block->size <= body_begin) {
                return nullptr;
            }

            // Clamp the block window to [body_begin, body_end).
            const uint64_t clamped_addr = std::max<uint64_t>(block->address, body_begin);
            const uint64_t clamped_end = std::min<uint64_t>(block->address + block->size, body_end);
            if (clamped_end <= clamped_addr) {
                return nullptr;
            }
            const size_t clamped_size = static_cast<size_t>(clamped_end - clamped_addr);

            // Insn count for the clamped window: scale when we clipped the start.
            size_t start_skip_insns = 0;
            if (clamped_addr > block->address && block->size > 0 && block->insn_count > 0) {
                const double ratio =
                        static_cast<double>(clamped_addr - block->address) / static_cast<double>(block->size);
                start_skip_insns = static_cast<size_t>(ratio * static_cast<double>(block->insn_count));
                if (start_skip_insns >= block->insn_count) {
                    start_skip_insns = block->insn_count - 1;
                }
            }
            const int max_insns = static_cast<int>(block->insn_count - start_skip_insns);
            if (max_insns <= 1) {
                return nullptr;
            }

            std::string signature;
            int signature_offset;
            for (int limit = max_insns; limit > 1; --limit) {
                for (int offset = max_insns - limit; offset >= 0; --offset) {
                    // create_signature starts at clamped_addr — offset is relative to that base.
                    const auto [s, real_address] = create_signature(
                            section, reinterpret_cast<uint8_t *>(clamped_addr), clamped_size,
                            static_cast<size_t>(limit), offset);

                    // real_address is the first byte of the kept pattern window.
                    if (real_address < body_begin || real_address >= body_end) {
                        continue;
                    }

                    signature = trim(s.to_string(false));
                    if (signature.empty()) {
                        continue;
                    }

                    // Training signature_offset: entry - real_address (usually negative).
                    signature_offset = static_cast<int>(
                            static_cast<intptr_t>(original->address) -
                            static_cast<intptr_t>(real_address));

                    // Training offset must not step outside body when applied to entry.
                    // match = entry - signature_offset = real_address (already checked).
                    // Also ensure the resolved training address (entry) is inside body.
                    if (!original->in_function(original->address)) {
                        continue;
                    }

                    if (auto ptr = scan_by_signature(signature, signature_offset); ptr) {
                        return ptr;
                    }
                }
            }
            return nullptr;
        }

        // Decode the Nucleus-clamped body into a MicroInsn stream for the core
        // micro-window generator. Reuses create_signature's per-insn wildcard
        // rules (RIP-relative, call imm, external, module-imm mov) WITHOUT the
        // recursive callee-prologue embed path. CALL and unconditional JMP are
        // marked splits=true so the generator drops them as segment boundaries.
        std::vector<micro_window::MicroInsn>
        generate_micro_window_insns(const Function &fn) {
            std::vector<micro_window::MicroInsn> out;
            const uint64_t body_begin = fn.address;
            // Clamp to leaf so overshot Nucleus spans do not explode windows.
            const size_t leaf = function_leaf_size(fn, 256);
            const size_t body_len = leaf > 0 ? leaf : std::min(fn.size, size_t{256});
            const uint64_t body_end = fn.address + body_len;
            if (body_end <= body_begin) return out;

            struct BlockRange {
                uint64_t start;
                uint64_t end;
                float score;
            };
            std::vector<BlockRange> ranges;
            for (auto ba : fn.blocks) {
                auto *blk = fn.module->address_blocks[ba];
                if (!blk) continue;
                ranges.push_back({blk->address, blk->address + blk->size,
                                  calcBlockScore(blk)});
            }
            std::sort(ranges.begin(), ranges.end(),
                      [](const auto &a, const auto &b) { return a.start < b.start; });

            struct InsnInfo {
                uint64_t address;
                size_t size;
                x86_insn id;
            };
            std::vector<InsnInfo> infos;
            disasm ds{reinterpret_cast<uint8_t *>(body_begin),
                      static_cast<size_t>(body_end - body_begin)};
            for (const auto &insn : ds) {
                infos.push_back({insn.address, insn.size,
                                 static_cast<x86_insn>(insn.id)});
            }
            if (infos.empty()) return out;

            auto [sig, real_addr] = create_signature(
                    fn.module, reinterpret_cast<uint8_t *>(body_begin),
                    static_cast<size_t>(body_end - body_begin), infos.size(), 0);
            (void) real_addr;

            out.reserve(infos.size());
            for (size_t k = 0; k < infos.size(); ++k) {
                micro_window::MicroInsn m;
                m.address = infos[k].address;
                m.size = infos[k].size;
                m.splits = (infos[k].id == X86_INS_CALL ||
                            infos[k].id == X86_INS_JMP);
                if (k < sig.asm_codes.size()) {
                    m.hex = sig.asm_codes[k];
                    if (!m.hex.empty() && m.hex.back() != ' ') m.hex += ' ';
                }
                auto it = std::upper_bound(
                        ranges.begin(), ranges.end(), infos[k].address,
                        [](uint64_t a, const BlockRange &r) { return a < r.start; });
                if (it != ranges.begin()) {
                    --it;
                    if (infos[k].address >= it->start && infos[k].address < it->end)
                        m.weight = it->score;
                }
                out.push_back(std::move(m));
            }
            return out;
        }

        // Extract FunctionFeatures (consts, stable imms, size) from a Function
        // by aggregating over its CodeBlocks. Used for both train (original)
        // and target (candidate entry) feature vectors.
        match_policy::FunctionFeatures extract_features(const Function &fn) {
            // P0: materialize leaf-clamped features on first use.
            ensure_function_features(const_cast<Function &>(fn));
            match_policy::FunctionFeatures feat;
            feat.size = fn.size;
            for (auto ba : fn.blocks) {
                auto *blk = fn.module->address_blocks[ba];
                if (!blk) continue;
                for (const auto &s : blk->consts)
                    feat.consts.push_back(s);
                for (auto v : blk->const_numbers) {
                    if (match_policy::is_stable_imm(v))
                        feat.imms.push_back(v);
                }
                for (auto v : blk->const_offset_numbers) {
                    if (match_policy::is_stable_imm(v))
                        feat.imms.push_back(v);
                }
            }
            return feat;
        }

        // Check whether a Function is in the module's export known_functions list.
        bool is_known_function(const Function &fn) const {
            if (fn.name.empty()) return false;
            auto it = fn.module->known_functions.find(fn.name);
            return it != fn.module->known_functions.end() && it->second == &fn;
        }

        // Collect eligible direct helper callees of the original (train) function
        // and return their features (plan todo 4 flatten1).
        // Eligibility: callee in same module text, Function size > 0,
        // size <= 256 OR not in export known_functions, depth exactly 1.
        std::vector<match_policy::FunctionFeatures> extract_helper_edges() {
            std::vector<match_policy::FunctionFeatures> helpers;
            std::set<uint64_t> seen;
            for (auto ba : original->blocks) {
                auto *blk = original->module->address_blocks[ba];
                if (!blk) continue;
                for (uint64_t callee : blk->call_functions) {
                    if (!seen.insert(callee).second) continue;
                    if (!original->module->in_text(callee)) continue;
                    auto *fn = original->module->find_function(callee);
                    if (!fn || fn->size == 0) continue;
                    if (fn->size > 256 && is_known_function(*fn)) continue;
                    helpers.push_back(extract_features(*fn));
                }
            }
            return helpers;
        }

        // Collect callee features for one target candidate entry's direct call
        // edges (for StillCall fingerprinting in the call-edit label).
        std::vector<match_policy::FunctionFeatures>
        extract_target_call_callees(const Function &entry) {
            std::vector<match_policy::FunctionFeatures> callees;
            std::set<uint64_t> seen;
            for (auto ba : entry.blocks) {
                auto *blk = entry.module->address_blocks[ba];
                if (!blk) continue;
                for (uint64_t callee : blk->call_functions) {
                    if (!seen.insert(callee).second) continue;
                    auto *fn = target->find_function(callee);
                    if (!fn) continue;
                    callees.push_back(extract_features(*fn));
                }
            }
            return callees;
        }

        // Soft path (plan todo 2/3/4): generate all micro-windows for the
        // original body, validate each on the training module, scan the
        // target, collect (raw_match, entry) votes across all windows, and
        // resolve via accept_candidates with feature-based scores.
        // Returns the winning entry VA or nullptr.
        // Match via train-body LEA string unique in both modules + single RIP xref.
        void *scan_by_unique_const() {
            if (!original || original->size == 0 || !original->module) return nullptr;
            if (target->function_table.empty()) return nullptr;
            if (target->text.base_address == 0 || target->text.size == 0) return nullptr;

            auto find_c_string = [](uintptr_t base, size_t size,
                                    const std::string &s) -> std::vector<uintptr_t> {
                std::vector<uintptr_t> hits;
                if (base == 0 || size <= s.size()) return hits;
                const auto *p = reinterpret_cast<const char *>(base);
                const auto *end = p + (size - s.size());
                for (const char *q = p; q < end; ++q) {
                    if (std::memcmp(q, s.data(), s.size()) == 0 && q[s.size()] == '\0') {
                        hits.push_back(reinterpret_cast<uintptr_t>(q));
                    }
                }
                return hits;
            };

            auto count_c_string = [&](ModuleSections &mod, const std::string &s) -> size_t {
                size_t n = 0;
                if (mod.rodata.base_address && mod.rodata.size) {
                    n += find_c_string(mod.rodata.base_address, mod.rodata.size, s).size();
                }
                if (n == 0 && mod.details.range.base_address && mod.details.range.size) {
                    n = find_c_string(mod.details.range.base_address, mod.details.range.size, s)
                                .size();
                }
                return n;
            };

            std::vector<std::string> body_strs;
            std::unordered_set<std::string> seen;
            {
                disasm ds{std::span{reinterpret_cast<uint8_t *>(original->address),
                                    original->size}};
                for (auto &insn: ds) {
                    const auto &x86 = insn.detail->x86;
                    if (x86.op_count != 2 || x86.operands[0].type != X86_OP_REG) continue;
                    const char *str = nullptr;
                    if (insn.id == X86_INS_LEA) {
                        const auto &op = x86.operands[1];
                        if (op.type == X86_OP_MEM && reg_is_ip(op.mem.base) &&
                            op.mem.index == X86_REG_INVALID) {
                            const auto tgt = insn.address + insn.size + op.mem.disp;
                            if (original->module->in_module(tgt) &&
                                !original->module->in_text(tgt)) {
                                str = reinterpret_cast<const char *>(tgt);
                            }
                        }
                    } else if (insn.id == X86_INS_MOV &&
                               x86.operands[1].type == X86_OP_IMM) {
                        const auto tgt = static_cast<uintptr_t>(x86.operands[1].imm);
                        if (original->module->in_module(tgt) &&
                            !original->module->in_text(tgt)) {
                            str = reinterpret_cast<const char *>(tgt);
                        }
                    }
                    if (!str) continue;
                    size_t len = 0;
                    bool ok = true;
                    while (len < 256 && str[len] != '\0') {
                        const unsigned char c = static_cast<unsigned char>(str[len]);
                        if (c < 0x20 || c > 0x7e) {
                            ok = false;
                            break;
                        }
                        ++len;
                    }
                    if (!ok || len < 3 || str[len] != '\0') continue;
                    std::string s(str, len);
                    if (!seen.insert(s).second) continue;
                    body_strs.push_back(std::move(s));
                }
            }
            if (body_strs.empty()) {
                if (auto logger = spdlog::get(logger_name)) {
                    logger->info("scan_by_unique_const: {} no LEA strings in train body",
                                 original->name);
                }
                return nullptr;
            }

            auto scan_str_xrefs = [&](uint64_t str_va) -> std::unordered_map<uint64_t, uintptr_t> {
                std::unordered_map<uint64_t, uintptr_t> entry_earliest;
                const auto *text = reinterpret_cast<const uint8_t *>(target->text.base_address);
                const size_t tsz = target->text.size;
                const auto note = [&](uint64_t insn_va) {
                    if (insn_va < limit_address) return;
                    const uint64_t e = target->function_table.containing(insn_va);
                    if (e == 0 || e < limit_address) return;
                    auto it = entry_earliest.find(e);
                    if (it == entry_earliest.end() || insn_va < it->second) {
                        entry_earliest[e] = insn_va;
                    }
                };
                for (size_t i = 0; i + 5 <= tsz; ++i) {
                    const uint8_t b0 = text[i];
                    const uint64_t insn_va = target->text.base_address + i;
                    // PIC: REX + LEA/MOV r64,[rip+disp32] (7 bytes)
                    if (i + 7 <= tsz && (b0 >= 0x40 && b0 <= 0x4f) &&
                        (text[i + 1] == 0x8d || text[i + 1] == 0x8b) &&
                        (text[i + 2] & 0xC7) == 0x05) {
                        int32_t disp = 0;
                        std::memcpy(&disp, text + i + 3, sizeof(disp));
                        if (static_cast<uint64_t>(static_cast<int64_t>(insn_va + 7) + disp) ==
                            str_va) {
                            note(insn_va);
                        }
                    }
                    // Non-PIC / large-code: mov r32, imm32 (B8+rd id) — game open_io style
                    // e.g. be 00 c9 87 00  => mov esi, 0x87c900
                    if (b0 >= 0xB8 && b0 <= 0xBF) {
                        uint32_t imm = 0;
                        std::memcpy(&imm, text + i + 1, sizeof(imm));
                        if (static_cast<uint64_t>(imm) == (str_va & 0xffffffffull) &&
                            (str_va >> 32) == 0) {
                            note(insn_va);
                        }
                    }
                }
                return entry_earliest;
            };

            std::ranges::sort(body_strs, [](const auto &a, const auto &b) {
                return a.size() > b.size();
            });

            for (const auto &s: body_strs) {
                if (count_c_string(*original->module, s) != 1) {
                    if (auto logger = spdlog::get(logger_name)) {
                        logger->info("scan_by_unique_const: {} train '{}' not unique",
                                     original->name, s);
                    }
                    continue;
                }
                std::vector<uintptr_t> hits;
                if (target->rodata.base_address != 0 && target->rodata.size != 0) {
                    hits = find_c_string(target->rodata.base_address, target->rodata.size, s);
                }
                if (hits.empty() && target->details.range.base_address != 0) {
                    hits = find_c_string(target->details.range.base_address,
                                         target->details.range.size, s);
                }
                if (hits.size() != 1) {
                    if (auto logger = spdlog::get(logger_name)) {
                        logger->info("scan_by_unique_const: {} target '{}' hits={}",
                                     original->name, s, hits.size());
                    }
                    continue;
                }
                auto entry_earliest = scan_str_xrefs(hits[0]);
                // Prefer entries where the xref is near the prologue (first 24B).
                // Unique string with a single xref is strong evidence — accept even
                // when Nucleus span size ratios look wrong (over-merged spans).
                std::vector<std::pair<uint64_t, uintptr_t>> candidates;
                candidates.reserve(entry_earliest.size());
                for (const auto &[e, m]: entry_earliest) {
                    if (entry_earliest.size() > 1) {
                        if (auto *fn = target->find_function(e); fn && original->size > 0) {
                            const size_t tgt_leaf = effective_leaf_size(*fn);
                            const size_t src_leaf = effective_leaf_size(*original);
                            const size_t a = tgt_leaf ? tgt_leaf : fn->size;
                            const size_t b = src_leaf ? src_leaf : original->size;
                            if (a > 0 && b > 0) {
                                const double ratio = static_cast<double>(a) / static_cast<double>(b);
                                if (ratio < 0.25 || ratio > 6.0) continue;
                            }
                        }
                    }
                    candidates.emplace_back(e, m);
                }
                if (candidates.empty()) {
                    if (auto logger = spdlog::get(logger_name)) {
                        logger->info("scan_by_unique_const: {} '{}' no size-ok xrefs (raw={})",
                                     original->name, s, entry_earliest.size());
                    }
                    continue;
                }
                if (candidates.size() > 1) {
                    std::vector<std::pair<uint64_t, uintptr_t>> near;
                    for (const auto &[e, m]: candidates) {
                        if (m >= e && m - e < 24) near.emplace_back(e, m);
                    }
                    if (near.size() == 1) {
                        candidates = std::move(near);
                    } else {
                        if (auto logger = spdlog::get(logger_name)) {
                            logger->info("scan_by_unique_const: {} '{}' xref_entries={}",
                                         original->name, s, candidates.size());
                        }
                        continue;
                    }
                }
                auto [entry, match] = candidates.front();
                // If Nucleus over-merged (xref far from span start), recover entry
                // from train-side string offset within the original body.
                {
                    uintptr_t train_str = 0;
                    if (original->module->rodata.base_address != 0) {
                        auto th = find_c_string(original->module->rodata.base_address,
                                                original->module->rodata.size, s);
                        if (th.size() == 1) train_str = th[0];
                    }
                    if (train_str == 0) {
                        auto th = find_c_string(original->module->details.range.base_address,
                                                original->module->details.range.size, s);
                        if (th.size() == 1) train_str = th[0];
                    }
                    if (train_str != 0) {
                        // Scan train .text for xref inside original body.
                        const auto &tt = original->module->text;
                        int train_off = -1;
                        if (tt.base_address != 0 && tt.size > 0) {
                            const auto *text = reinterpret_cast<const uint8_t *>(tt.base_address);
                            for (size_t i = 0; i + 7 < tt.size; ++i) {
                                const uint64_t iva = tt.base_address + i;
                                if (iva < original->address ||
                                    iva >= original->address + original->size) {
                                    continue;
                                }
                                const uint8_t b0 = text[i];
                                if ((b0 == 0x48 || b0 == 0x4C) && text[i + 1] == 0x8D) {
                                    const uint8_t modrm = text[i + 2];
                                    if ((modrm & 0xC7) == 0x05) {
                                        int32_t rel = 0;
                                        std::memcpy(&rel, text + i + 3, sizeof(rel));
                                        if (static_cast<uint64_t>(iva + 7 + rel) == train_str) {
                                            train_off = static_cast<int>(iva - original->address);
                                            break;
                                        }
                                    }
                                }
                                if (b0 >= 0xB8 && b0 <= 0xBF) {
                                    uint32_t imm = 0;
                                    std::memcpy(&imm, text + i + 1, sizeof(imm));
                                    if (static_cast<uint64_t>(imm) == (train_str & 0xffffffffull)) {
                                        train_off = static_cast<int>(iva - original->address);
                                        break;
                                    }
                                }
                            }
                        }
                        if (train_off >= 0) {
                            const uint64_t guess =
                                    static_cast<uint64_t>(static_cast<intptr_t>(match) - train_off);
                            const auto span = entry;
                            // Only override when Nucleus clearly over-merged
                            // (xref far past a span that dwarfs the train body).
                            const size_t far =
                                    std::max<size_t>(256, original->size > 0 ? original->size : 256);
                            if (guess != span && match >= span && (match - span) > far) {
                                if (target->in_text(guess)) {
                                    if (auto logger = spdlog::get(logger_name)) {
                                        logger->info(
                                                "scan_by_unique_const: {} '{}' Nucleus span {:#x} "
                                                "too coarse; using train-off {} -> {:#x}",
                                                original->name, s, span, train_off, guess);
                                    }
                                    entry = guess;
                                }
                            }
                        }
                    }
                }
                last_training_offset = 0;
                if (signature_info) {
                    signature_info->pattern.clear();
                    signature_info->pattern_offset = 0;
                }
                soft_path_active = false;
                if (auto logger = spdlog::get(logger_name)) {
                    logger->info("scan_by_unique_const: {} via '{}' -> {:#x} (xref {:#x})",
                                 original->name, s, entry, match);
                }
                return reinterpret_cast<void *>(entry);
            }
            return nullptr;
        }

        static size_t effective_leaf_size(const Function &fn) {
            return function_leaf_size(fn, 128);
        }

        // Short / distinctive bodies: whole-body hex pattern (same wildcards as
        // create_signature). Accept only when train hits stay inside original and
        // target hits collapse to a single Nucleus entry. Covers tiny exports
        // (e.g. lua_pushnil 17B) where micro-windows lack SCORE_T signal.
        void *scan_by_short_body() {
            if (!original || original->size == 0) return nullptr;
            if (target->function_table.empty()) return nullptr;
            if (!original->module) return nullptr;
            const size_t leaf = effective_leaf_size(*original);
            auto log_skip = [&](const char *why) {
                if (auto logger = spdlog::get(logger_name)) {
                    logger->info("scan_by_short_body: {} skip ({}) leaf={} size={}",
                                 original->name, why, leaf, original->size);
                }
            };
            if (leaf == 0 || leaf > 128) {
                log_skip("leaf_out_of_range");
                return nullptr;
            }

            const auto &train_text = original->module->text;
            if (train_text.base_address == 0 || train_text.size == 0) {
                log_skip("no_train_text");
                return nullptr;
            }
            if (limit_address <= target->text.base_address) {
                log_skip("bad_limit");
                return nullptr;
            }

            // Build candidate (pattern, train_po, try_sz) pairs:
            // 0) exact leaf bytes (no create_signature) — tiny leaves like dump
            // 1) create_signature wildcards at leaf + shorter sizes
            // 2) raw fixed-byte prologues (no reloc wildcards) for equal/topointer
            struct PatTry {
                std::string pattern;
                int train_po;
                size_t try_sz;
            };
            std::vector<PatTry> tries;
            {
                const auto *p = reinterpret_cast<const uint8_t *>(original->address);
                std::string exact;
                exact.reserve(leaf * 3);
                for (size_t i = 0; i < leaf; ++i) {
                    if (i) exact.push_back(' ');
                    exact += fmt::format("{:02x}", p[i]);
                }
                if (!exact.empty()) {
                    tries.push_back({std::move(exact), 0, leaf});
                }
            }
            std::vector<size_t> try_sizes{leaf};
            for (size_t s: {size_t{32}, size_t{24}, size_t{16}, size_t{12}}) {
                if (s < leaf && s >= 12) try_sizes.push_back(s);
            }
            for (const size_t try_sz: try_sizes) {
                auto [sig, real_addr] = create_signature(
                        original->module, reinterpret_cast<uint8_t *>(original->address),
                        try_sz, static_cast<size_t>(-1), 0);
                auto pattern = trim(sig.to_string(false));
                if (pattern.empty()) continue;
                const int train_po = static_cast<int>(
                        static_cast<intptr_t>(original->address) -
                        static_cast<intptr_t>(real_addr));
                tries.push_back({std::move(pattern), train_po, try_sz});
            }
            // Raw fixed prologue: stop before first E8/E9 (call/jmp rel32).
            {
                const auto *bytes = reinterpret_cast<const uint8_t *>(original->address);
                size_t fixed_len = 0;
                while (fixed_len < leaf && fixed_len < 16) {
                    if (bytes[fixed_len] == 0xE8 || bytes[fixed_len] == 0xE9) break;
                    ++fixed_len;
                }
                if (fixed_len >= 8) {
                    tries.push_back({to_hex(bytes, bytes + fixed_len), 0, fixed_len});
                }
            }

            for (const auto &tr: tries) {
                const auto &pattern = tr.pattern;
                bool any_fixed = false;
                for (char c: pattern) {
                    if (c != '?' && c != ' ') {
                        any_fixed = true;
                        break;
                    }
                }
                if (!any_fixed) continue;

                MemorySignature train_scan(pattern.c_str(), tr.train_po, false);
                train_scan.log = false;
                train_scan.scan(train_text.base_address, train_text.size);
                if (train_scan.targets.empty()) continue;
                const uint64_t train_entry = original->address;
                bool train_ok = true;
                for (auto t: train_scan.targets) {
                    const uint64_t e = original->module->function_table.empty()
                                               ? (original->in_function(t) ? train_entry : 0)
                                               : original->module->function_table.containing(t);
                    if (e != train_entry) {
                        train_ok = false;
                        break;
                    }
                }
                if (!train_ok) continue;

                MemorySignature tgt_scan(pattern.c_str(), 0, false);
                tgt_scan.log = false;
                tgt_scan.scan(limit_address,
                              target->text.size - (limit_address - target->text.base_address));
                if (tgt_scan.targets.empty()) continue;

                std::unordered_map<uint64_t, uintptr_t> entry_earliest;
                for (auto m: tgt_scan.targets) {
                    if (m < limit_address) continue;
                    const uint64_t e = target->function_table.containing(m);
                    if (e == 0 || e < limit_address) continue;
                    bool claimed = false;
                    for (const auto &[name, fn]: target->known_functions) {
                        (void) name;
                        if (fn && fn->address == e) {
                            claimed = true;
                            break;
                        }
                    }
                    if (claimed) continue;
                    auto it = entry_earliest.find(e);
                    if (it == entry_earliest.end() || m < it->second) {
                        entry_earliest[e] = m;
                    }
                }
                if (entry_earliest.empty()) continue;

                uint64_t entry = 0;
                uintptr_t match = 0;
                if (entry_earliest.size() == 1) {
                    entry = entry_earliest.begin()->first;
                    match = entry_earliest.begin()->second;
                } else {
                    int best_diff = std::numeric_limits<int>::max();
                    int ties = 0;
                    for (const auto &[e, m]: entry_earliest) {
                        auto *fn = target->find_function(e);
                        if (!fn || fn->size == 0) continue;
                        const size_t tgt_leaf = effective_leaf_size(*fn);
                        if (tgt_leaf == 0) continue;
                        const int diff = std::abs(static_cast<int>(tgt_leaf) -
                                                  static_cast<int>(leaf));
                        if (diff < best_diff) {
                            best_diff = diff;
                            ties = 1;
                            entry = e;
                            match = m;
                        } else if (diff == best_diff) {
                            ++ties;
                        }
                    }
                    if (entry == 0 || ties != 1 || best_diff > 32) continue;
                }

                if (auto *fn = target->find_function(entry); fn && fn->size > 0) {
                    const size_t tgt_leaf = effective_leaf_size(*fn);
                    if (tgt_leaf > 0 && leaf > 0) {
                        const double ratio = static_cast<double>(tgt_leaf) /
                                            static_cast<double>(leaf);
                        if (ratio < 0.4 || ratio > 2.5) continue;
                    }
                }

                const int target_po = static_cast<int>(
                        static_cast<intptr_t>(entry) - static_cast<intptr_t>(match));
                last_training_offset = tr.train_po;
                if (signature_info) {
                    signature_info->pattern = pattern;
                    signature_info->pattern_offset = target_po;
                }
                soft_path_active = false;
                if (auto logger = spdlog::get(logger_name)) {
                    logger->info("scan_by_short_body: {} -> {:#x} (leaf={} try_sz={})",
                                 original->name, entry, leaf, tr.try_sz);
                }
                return reinterpret_cast<void *>(entry);
            }

            // Unique fixed mid-body needle for prologue-sharing families
            // (equal/rawequal/lessthan). Strict: single raw hit on train and
            // target; match must lie inside the resolved body.
            {
                const auto *bytes = reinterpret_cast<const uint8_t *>(original->address);
                const size_t n = leaf;
                for (size_t len = 12; len >= 6; --len) {
                    // Prefer mid/late needles over shared prologues.
                    for (size_t off = n - len + 1; off-- > 0; ) {
                        size_t nonzero = 0;
                        for (size_t k = 0; k < len; ++k) {
                            if (bytes[off + k] != 0) ++nonzero;
                        }
                        if (nonzero < (len * 3) / 4) continue;
                        // Shared equal-family prologues start with push r12; skip.
                        if (off < 8) continue;

                        auto pattern = trim(to_hex(bytes + off, bytes + off + len));
                        MemorySignature train_scan(pattern.c_str(), 0, false);
                        train_scan.log = false;
                        train_scan.scan(train_text.base_address, train_text.size);
                        if (train_scan.targets.size() != 1) continue;
                        if (!original->in_function(train_scan.targets[0])) continue;

                        MemorySignature tgt_scan(pattern.c_str(), 0, false);
                        tgt_scan.log = false;
                        tgt_scan.scan(limit_address,
                                      target->text.size -
                                              (limit_address - target->text.base_address));
                        if (tgt_scan.targets.size() != 1) continue;
                        const uintptr_t match = tgt_scan.targets[0];
                        if (match < limit_address) continue;
                        const uint64_t entry = target->function_table.containing(match);
                        if (entry == 0 || entry < limit_address) continue;
                        if (match < entry) continue;
                        bool claimed = false;
                        for (const auto &[name, fn]: target->known_functions) {
                            (void) name;
                            if (fn && fn->address == entry) {
                                claimed = true;
                                break;
                            }
                        }
                        if (claimed) continue;
                        auto *fn = target->find_function(entry);
                        if (!fn || fn->size == 0) continue;
                        if (match >= entry + fn->size) continue;
                        // Train needle at +off must land at roughly +off on target
                        // (rejects equal-family prologue collisions).
                        const auto rel = static_cast<int64_t>(match - entry);
                        if (std::abs(rel - static_cast<int64_t>(off)) > 24) continue;
                        const size_t tgt_leaf = effective_leaf_size(*fn);
                        if (tgt_leaf > 0) {
                            const double ratio = static_cast<double>(tgt_leaf) /
                                                static_cast<double>(leaf);
                            if (ratio < 0.4 || ratio > 2.5) continue;
                        }
                        if (match >= entry + std::max(leaf * 2, size_t{256})) continue;

                        const int target_po = static_cast<int>(
                                static_cast<intptr_t>(entry) - static_cast<intptr_t>(match));
                        last_training_offset = -static_cast<int>(off);
                        if (signature_info) {
                            signature_info->pattern = pattern;
                            signature_info->pattern_offset = target_po;
                        }
                        soft_path_active = false;
                        if (auto logger = spdlog::get(logger_name)) {
                            logger->info("scan_by_short_body: {} -> {:#x} (unique_needle len={} off={})",
                                         original->name, entry, len, off);
                        }
                        return reinterpret_cast<void *>(entry);
                    }
                }
            }

            log_skip("all_sizes_failed");
            return nullptr;
        }

        void *scan_by_micro_windows() {
            if (!original || original->size == 0) return nullptr;
            if (target->function_table.empty()) return nullptr;

            auto insns = generate_micro_window_insns(*original);
            auto windows = micro_window::generate_micro_windows(insns,
                                                                 original->address);
            if (windows.empty()) return nullptr;

            struct VoteExt {
                uintptr_t raw_match;
                uint64_t entry;
                size_t window_idx;
            };
            std::vector<VoteExt> votes_ext;

            for (size_t wi = 0; wi < windows.size(); ++wi) {
                const auto &w = windows[wi];

                MemorySignature train_scan(w.pattern.c_str(),
                                           w.train_signature_offset, false);
                train_scan.log = !nolog;
                const auto &train_text = original->module->text;
                if (train_text.base_address == 0 || train_text.size == 0) continue;
                train_scan.scan(train_text.base_address, train_text.size);
                if (train_scan.targets.empty()) continue;
                bool ok = true;
                for (auto t : train_scan.targets) {
                    if (!original->in_function(t)) {
                        ok = false;
                        break;
                    }
                }
                if (!ok) continue;

                MemorySignature tgt_scan(w.pattern.c_str(), 0, false);
                tgt_scan.log = !nolog;
                assert(limit_address > target->text.base_address);
                tgt_scan.scan(limit_address,
                              target->text.size -
                                      (limit_address - target->text.base_address));
                for (auto m : tgt_scan.targets) {
                    if (m < limit_address) continue;
                    uint64_t e = target->function_table.containing(m);
                    if (e == 0 || e < limit_address) continue;
                    bool claimed = false;
                    for (const auto &[nm, fn]: target->known_functions) {
                        (void) nm;
                        if (fn && fn->address == e) {
                            claimed = true;
                            break;
                        }
                    }
                    if (claimed) continue;
                    votes_ext.push_back({m, e, wi});
                }
            }

            if (votes_ext.empty()) return nullptr;

            std::vector<micro_window::HitVote> votes;
            votes.reserve(votes_ext.size());
            for (const auto &v : votes_ext)
                votes.push_back({v.raw_match, v.entry});

            // Extract train features from the original function body.
            const auto train_own = extract_features(*original);

            // Collect eligible helper edges and build flatten1 train features.
            auto helper_edges = extract_helper_edges();
            const auto train_flat = match_policy::flatten1_features(train_own, helper_edges);

            // Extract per-entry target features and call-edge callees.
            std::unordered_map<uint64_t, match_policy::FunctionFeatures> target_feats;
            std::unordered_map<uint64_t, std::vector<match_policy::FunctionFeatures>> target_callees;
            for (const auto &v : votes_ext) {
                if (target_feats.count(v.entry)) continue;
                auto *fn = target->find_function(v.entry);
                if (!fn) continue;
                target_feats[v.entry] = extract_features(*fn);
                target_callees[v.entry] = extract_target_call_callees(*fn);
            }

            auto candidates = micro_window::build_feature_candidates(
                    votes, train_own, train_flat, helper_edges,
                    target_feats, target_callees);
            auto candidates_for_log = candidates; // copy for fail-closed logging
            auto result = match_policy::accept_candidates(std::move(candidates));
            if (!result) {
                if (auto logger = spdlog::get(logger_name)) {
                    const auto s = micro_window::summarize_candidates(candidates_for_log);
                    if (s.count == 0) {
                        logger->warn("scan_by_micro_windows: fail-closed for {} (no candidates)",
                                     original->name);
                    } else if (!s.has_second) {
                        logger->warn("scan_by_micro_windows: fail-closed for {} "
                                     "sole entry={:#x} score={:.3f} (<SCORE_T or disagree)",
                                     original->name, s.best_entry, s.best_score);
                    } else {
                        logger->warn("scan_by_micro_windows: fail-closed for {} "
                                     "best entry={:#x} score={:.3f} "
                                     "second entry={:#x} score={:.3f} margin={:.3f} entries={}",
                                     original->name, s.best_entry, s.best_score,
                                     s.second_entry, s.second_score, s.margin, s.count);
                    }
                }
                return nullptr;
            }

            std::string chosen_pattern;
            int chosen_train_offset = 0;
            size_t chosen_len = 0;
            bool found = false;
            for (const auto &v : votes_ext) {
                if (v.raw_match != result->chosen_raw_match ||
                    v.entry != result->entry)
                    continue;
                const auto &w = windows[v.window_idx];
                if (!found || w.pattern.size() > chosen_len) {
                    chosen_pattern = w.pattern;
                    chosen_train_offset = w.train_signature_offset;
                    chosen_len = w.pattern.size();
                    found = true;
                }
            }
            if (!found) return nullptr;

            const int target_po = static_cast<int>(
                    static_cast<intptr_t>(result->entry) -
                    static_cast<intptr_t>(result->chosen_raw_match));
            last_training_offset = chosen_train_offset;
            if (signature_info) {
                signature_info->pattern = chosen_pattern;
                signature_info->pattern_offset = target_po;
            }
            // Cache the soft-path context so limit_signature can re-validate
            // shortened patterns against the SAME vote+margin+feature accept
            // policy without re-extracting features or re-scanning micro-windows.
            soft_path_active = true;
            soft_winning_entry = result->entry;
            soft_train_own = train_own;
            soft_train_flat = train_flat;
            soft_helper_edges = helper_edges;
            soft_target_feats = target_feats;
            soft_target_callees = target_callees;
            return reinterpret_cast<void *>(result->entry);
        }

        // Re-validate a single shortened pattern against the cached soft-path
        // context (vote+margin+feature accept policy). Used by limit_signature
        // so that pattern shortening never falls back to unique-byte-only
        // scan_by_signature, which would reintroduce pick-first. Returns true
        // and updates signature_info when the shortened pattern soft-accepts to
        // the SAME entry previously chosen by scan_by_micro_windows.
        bool soft_revalidate_pattern(const std::string &pattern, int train_offset) {
            if (!soft_path_active) return false;
            if (target->function_table.empty()) return false;

            MemorySignature scan(pattern.c_str(), /*pattern_offset=*/0, false);
            scan.log = !nolog;
            assert(limit_address > target->text.base_address);
            scan.scan(limit_address, target->text.size -
                                             (limit_address - target->text.base_address));

            std::vector<micro_window::HitVote> votes;
            for (auto m : scan.targets) {
                if (m < limit_address) continue;
                const uint64_t e = target->function_table.containing(m);
                if (e == 0 || e < limit_address) continue;
                votes.push_back({m, e});
            }
            if (votes.empty()) return false;

            auto candidates = micro_window::build_feature_candidates(
                    votes, soft_train_own, soft_train_flat, soft_helper_edges,
                    soft_target_feats, soft_target_callees);
            auto result = match_policy::accept_candidates(std::move(candidates));
            if (!result) return false;
            if (result->entry != soft_winning_entry) return false;

            const int target_po = static_cast<int>(
                    static_cast<intptr_t>(result->entry) -
                    static_cast<intptr_t>(result->chosen_raw_match));
            last_training_offset = train_offset;
            if (signature_info) {
                signature_info->pattern = pattern;
                signature_info->pattern_offset = target_po;
            }
            return true;
        }

        bool limit_signature() {
            nolog = true;
            struct S{
                ~S() {
                    self->nolog = false;
                }
                Creator* self;
            } scope{this};
            std::string &signature = signature_info->pattern;
            if (signature.size() <= 8 * 2 + 7)
                return true;
            // Shorten using training-module offset (byte units). Target-local po is
            // rewritten by scan_by_signature (legacy) or soft_revalidate_pattern
            // (soft path) on each successful candidate.
            const int train_po = last_training_offset;
            for (size_t length = 8 * 2 + 7; length < signature.size(); length += 3) {
                for (size_t begin = 0; begin < length; begin += 3) {
                    auto new_s = trim(signature.substr(begin, length));
                    // begin is hex-string index ("xx " * n); convert to byte offset.
                    const int byte_begin = static_cast<int>(begin / 3);
                    const int offset = train_po - byte_begin;
                    if (soft_path_active) {
                        if (soft_revalidate_pattern(new_s, offset)) {
                            return true;
                        }
                    } else if (scan_by_signature(new_s, offset)) {
                        return true;
                    }
                }
            }
            return false;
        }

        ModuleSections *target;
        const Function *original;
        uintptr_t limit_address;
        SignatureInfo *signature_info;

        std::vector<void *> function_address;

        bool nolog = false;
        // Last training-module pattern_offset used for validation (entry - match).
        // Distinct from signature_info->pattern_offset which is target-local after resolve.
        int last_training_offset = 0;

        // Soft-path context cached by scan_by_micro_windows on a successful
        // accept, so limit_signature can re-validate shortened patterns via
        // the SAME vote+margin+feature accept policy (soft_revalidate_pattern)
        // instead of falling back to scan_by_signature uniqueness.
        bool soft_path_active = false;
        uint64_t soft_winning_entry = 0;
        match_policy::FunctionFeatures soft_train_own;
        match_policy::FunctionFeatures soft_train_flat;
        std::vector<match_policy::FunctionFeatures> soft_helper_edges;
        std::unordered_map<uint64_t, match_policy::FunctionFeatures> soft_target_feats;
        std::unordered_map<uint64_t, std::vector<match_policy::FunctionFeatures>> soft_target_callees;
    };


    static auto &signature_cache() {
        static std::unordered_map<void *, Signature> signature_cache;
        return signature_cache;
    }

    void release_signature_cache() {
        signature_cache().clear();
    }

    static const Signature *get_signature_cache(Creator &creator, void *fix_target) {
        Signature *target_s;
        if (signature_cache().contains(fix_target)) {
            target_s = &signature_cache()[fix_target];
        } else {
            signature_cache()[fix_target] = creator.create_signature(fix_target, nullptr, static_cast<size_t>(-1));
            target_s = &signature_cache()[fix_target];
        }
        return target_s;
    }

    static int longestCommonSubstring(const std::vector<std::string> &text1, const std::vector<std::string> &text2) {
        int m = text1.size(), n = text2.size();
        std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));
        for (int i = 1; i <= m; i++) {
            auto c1 = text1.at(i - 1);
            for (int j = 1; j <= n; j++) {
                auto c2 = text2.at(j - 1);
                if (c1 == c2) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = std::max(dp[i - 1][j], dp[i][j - 1]);
                }
            }
        }
        return dp[m][n];
    }

#if 1
#define OUTPUT_SIGNATURE(addr, s) fprintf(stderr, "---%p---\n%s\n\n\n", addr, s.c_str())
#else
#define OUTPUT_SIGNATURE(addr, s)
#endif

    static constexpr size_t func_aligned() {
#ifdef _M_X86
        return 8;
#elif defined(__i386__)
        return 8;
#else
        return 16;
#endif
    }

    static float calcBlockScore(CodeBlock *l) {
        return l->external_call_functions.size() * 1.1f + l->call_functions.size() + l->consts.size() +
               l->const_numbers.size() * 0.8f + l->const_offset_numbers.size() * 0.5f + l->insn_count * 0.3;
    }

    void *
    fix_func_address_by_signature(ModuleSections &target, const Function &original, uintptr_t limit_address,
                                  SignatureInfo *signature) {
        // knowns_signature table intentionally empty: soft micro-window +
        // Nucleus FunctionTable only (no hardcoded seed patterns).
        spdlog::get(logger_name)->warn("fix_func_address_by_signature: {}", original.name);
        Creator creator{&target, &original, limit_address, signature};
        // Soft path (FunctionTable present): micro-window generator splits at
        // CALL/JMP and resolves multi-hit raw matches by entry voting. This
        // replaces the scan_by_block sliding that could span CALL and embed
        // callee prologues. When the FunctionTable is empty, fall through to
        // the legacy scan_by_block + LCS path.
        if (!target.function_table.empty()) {
            if (auto ptr = creator.scan_by_unique_const(); ptr) {
                creator.limit_signature();
                return ptr;
            }
            if (auto ptr = creator.scan_by_short_body(); ptr) {
                creator.limit_signature();
                return ptr;
            }
            if (auto ptr = creator.scan_by_micro_windows(); ptr) {
                creator.limit_signature();
                return ptr;
            }
            return nullptr;
        }
        // find the block to signature
        auto blocks = original.blocks;

        std::ranges::sort(blocks, [&](auto l, auto r) {
            return calcBlockScore(original.module->address_blocks[l]) <
                   calcBlockScore(original.module->address_blocks[r]);
        });

        for (auto block_address: blocks | std::views::reverse) {
            auto block = original.module->address_blocks[block_address];
            if (auto ptr = creator.scan_by_block(original.module, block); ptr) {
                creator.limit_signature();
                return ptr;
            }
        }
        for (size_t take = 2; take <= original.blocks.size(); ++take) {
            auto begin = original.blocks.begin();
            auto end = begin + take - 1;
            for (; end != original.blocks.end(); ++end, ++begin) {
                auto beginBlock = original.module->address_blocks[*begin];
                auto endBlock = original.module->address_blocks[*end];
                CodeBlock block = {beginBlock->address,
                                   endBlock->address + endBlock->size - beginBlock->address,
                                   std::accumulate(begin, end + 1, size_t(0), [&](size_t s, auto b) {
                                       return s + original.module->address_blocks[b]->insn_count;
                                   })};
                if (auto ptr = creator.scan_by_block(original.module, &block); ptr) {
                    creator.limit_signature();
                    return ptr;
                }
            }
        }
#ifdef __linux__
        assert(false);
        return nullptr;
#else
        // LCS is a last-resort heuristic that compares entry-aligned asm windows.
        // When a target FunctionTable is present, signatures must come from
        // scan_by_block/scan_by_signature so pattern_offset is target-local.
        // Accepting LCS would return an entry (or raw match site) without rewriting
        // training pattern_offset — forbidden under the Nucleus contract.
        if (!target.function_table.empty()) {
            if (auto logger = spdlog::get(logger_name)) {
                logger->error(
                        "fix_func_address_by_signature: no block signature for {}; "
                        "refusing LCS while FunctionTable is present",
                        original.name);
            }
            return nullptr;
        }

        auto &function_address = creator.function_address;
        if (function_address.empty() && !target.functions.empty()) {
            const auto ptrs = target.functions |
                              std::views::transform([](auto &fn) { return reinterpret_cast<void *>(fn.address); });
            function_address.insert(function_address.end(), ptrs.begin(), ptrs.end());
        }
        function_address = function_address | std::views::filter(
                [limit_address](auto addr) { return limit_address <= (uintptr_t) addr; }) | ranges::to<std::vector>();
        std::ranges::sort(function_address);
        auto [begin, end] = std::ranges::unique(function_address);
        function_address.erase(begin, end);
        const auto original_s = creator.create_signature((void *) original.address,
                                                         [&original](auto address) {
                                                             return original.in_function(
                                                                     reinterpret_cast<uintptr_t>(address));
                                                         });

        int maybe_target_count = 1;
        void *maybe_target_addr = nullptr;
        for (const auto fix_target: function_address) {
            if (*static_cast<char *>(fix_target) != *(char *) original.address) { continue; }
            const auto target_s = get_signature_cache(creator, fix_target);
            if (!target_s) continue;
            const auto max = longestCommonSubstring(original_s.asm_codes, target_s->asm_codes);
            if (max == original_s.size()) {
                // Legacy path only (no FunctionTable): still force pattern_offset=0 so
                // callers cannot treat a training offset as target geometry.
                if (signature) {
                    signature->pattern_offset = 0;
                }
                return fix_target;
            }
            if (max > maybe_target_count) {
                maybe_target_count = max;
                maybe_target_addr = fix_target;
            }
        }
        if (maybe_target_addr) {
            OUTPUT_SIGNATURE((void *) original.address, original_s.to_string());
            fprintf(stderr, "maybe target:\n");
            OUTPUT_SIGNATURE(maybe_target_addr, get_signature_cache(creator, maybe_target_addr)->to_string());
            if (signature) {
                signature->pattern_offset = 0;
            }
            return maybe_target_addr;
        }
        OUTPUT_SIGNATURE((void *) original.address, original_s.to_string());
        return nullptr;
#endif
    }
}// namespace function_relocation
