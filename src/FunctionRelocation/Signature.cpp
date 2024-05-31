#include <algorithm>
#include <cassert>
#include <functional>
#include <numbers>
#include <optional>
#include <ranges>
#include <regex>
#include <string_view>

#include <frida-gum.h>
#include <keystone/keystone.h>
#include <range/v3/all.hpp>
#include <spdlog/spdlog.h>

#include "Signature.hpp"

#include "MemorySignature.hpp"
#include "ModuleSections.hpp"
#include "ctx.hpp"
#include "disasm.h"
#include "config.hpp"

#include <numeric>
#include <set>

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
                            auto bytes = insn.bytes;
                            auto size = insn.size;
#if defined(__linux__)

                            //"need transform so `lea rxx [rip + 0x??]` to `mov rxx 0xxxxxx`
                            assert(insn.id == X86_INS_LEA);
                            std::string reg{std::string_view{insn.op_str}.substr(0, 3)};
                            if (reg[0] == 'r') {
                                reg[0] = 'e';
                            }
                            // reg 64 to 32
                            std::string new_one = std::format("mov {}, 0xffffff", reg);
                            const auto new_bytes = AsmX86(new_one.c_str());
                            assert(!new_bytes.empty());
                            bytes = new_bytes.data();
                            size = new_bytes.size();
                            if (size == 5) {
                                signature.asm_codes.push_back(to_hex(bytes, bytes + 1) + make_unknown_string(size - 1));
                                continue;
                            }
#endif
                            assert(size == 7);
                            // transform [rip+0x??] to [rip+0x??]
                            signature.asm_codes.push_back(to_hex(bytes, bytes + 3) + make_unknown_string(size - 3));
                            continue;
                        }
                        break;
                }
                signature.asm_codes.push_back(to_hex(insn.bytes, insn.bytes + insn.size));
            }
            return {signature, real_address};
        }

        void *scan_by_signature(const std::string &signature, int signature_offset, bool skip_check = false) {
            MemorySignature scan1{signature.c_str(), signature_offset, false};
            scan1.scan(original->module->details.range.base_address, original->module->details.range.size);
            if (!skip_check && scan1.targets.size() != 1) return nullptr;

            if (skip_check || scan1.target_address == original->address) {
                MemorySignature scan{signature.c_str(), signature_offset, false};
                assert(limit_address > target->text.base_address);
                scan.scan(limit_address, target->text.size - (limit_address - target->text.base_address));
                void *target = 0;
                if (scan.targets.size() == 1) target = (void *) scan.target_address;
                else {
                    auto targets =
                            scan.targets | std::views::filter([this](auto addr) { return addr >= limit_address; }) |
                            ranges::to<std::vector>();
                    if (targets.size() == 1) target = (void *) targets[0];
                    auto ptrs =
                            scan.targets | std::views::transform([](auto v) { return reinterpret_cast<void *>(v); });
                    function_address.insert(function_address.end(), ptrs.begin(), ptrs.end());
                }
                if (target && signature_info) {
                    signature_info->pattern = signature;
                    signature_info->pattern_offset = signature_offset;
                    return target;
                }
            }
            return nullptr;
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
            std::string signature;
            int signature_offset;
            for (int limit = block->insn_count; limit > 1; --limit) {
                for (int offset = block->insn_count - limit; offset >= 0; --offset) {
                    const auto [s, real_address] = create_signature(section, (uint8_t *) block->address, block->size,
                                                                    limit, offset);
                    signature = trim(s.to_string(false));
                    assert(real_address >= original->address);
                    signature_offset = static_cast<int>(-(static_cast<intptr_t>(real_address) -
                                                          static_cast<intptr_t>(original->address)));
                    if (auto ptr = scan_by_signature(signature, signature_offset); ptr) return ptr;
                }
            }
            return nullptr;
        }

        bool limit_signature() {
            std::string &signature = signature_info->pattern;
            int &signature_offset = signature_info->pattern_offset;
            if (signature.size() <= 8 * 2 + 7)
                return true;
            for (size_t length = 8 * 2 + 7; length < signature.size(); length += 3) {
                auto begin = 0;
                for (; begin < length; begin += 3) {
                    auto new_s = trim(signature.substr(begin, length));
                    assert(signature_offset <= 0);
                    const auto offset = signature_offset - begin;
                    if (scan_by_signature(new_s, offset)) {
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
        static std::unordered_map<std::string, SignatureInfo> knowns_signature = {
#ifdef __linux__
                {"lua_pushvalue"s, {0, "48 89 0A 8B 40 08 89 42  08 48 83 43 10 10 5B C3"s, -0x10}},
                {"lua_insert"s, {0, "48 89 D1 48 83 EA 10 4C  29 C9 4C 8B 04 31 4C 89"s, -0x20}},
                {"lua_xmove"s, {0, "48 8B 4F 10 48 8B 56 10  48 01 C1 48 83 C0 10 4C"s, -0x30}},
                {"lua_remove"s, {0, "48 83 E9 10  48 89 4B 10 5B C3"s, -0x44}},
                {"lua_pushnil"s, {0, "48 8B 47 10 C7 40 08 00 00 00 00 48 83 47 10 10 C3"s, 0x0}},
                {"lua_replace"s, {0, "48 8B 53 10 81 FD EE D8"s, -0x18}},
                {"lua_pushvfstring"s, {0, "C7 44 24 0C 30 00 00 00 48 89 44 24 18 E8 ?? ?? ?? ?? 48  81 C4 D8 00 00 00 C3"s, -0x75}}
#elifdef __APPLE__
                //season： use different register
                {"lua_rawset"s, {0, "49 89 C6 49 8B 5F 10 48 8B 30 48 8D 53 E0 4C 89 FF E8"s, -0xD}},
                {"luaL_loadbuffer"s, {0, "48 83 EC 18 48 8D 44 24 08 48 89 30 48 89 50 08 48 8D 35 0D 00 00 00"s, 0x0}},
                {"lua_concat"s, {0, "7C 44  41 80 BE C0 00 00 00 00"s, -0xc}},
                {"lua_rawgeti"s, {0, "89 41 08 48 83 43 10 10 48 83 C4 08"s, -0x24}},
                {"lua_getfield"s, {0, "C7 42 08 04 00 00 00 48 8B 4B 10 48 89 DF"s, -0x33}},
                {"lua_pushvfstring"s, {0, "48 3B 48 70 72 08 48 89 DF E8 ?? ?? ?? ?? 48 89 DF 4C 89 FE"s, -0x1f}},
                {"lua_pushstring"s,
                 {0, "49 8B 46 10 C7 40 08 00 00 00 00 48 83 C0 10 49 89 46 10 48 83 C4 08"s, -0x2c}},
#endif
        };

        Creator creator{&target, &original, limit_address, signature};
        if (knowns_signature.contains(original.name)) {
            const auto &pattern = knowns_signature[original.name];
            if (auto ptr = creator.scan_by_signature(pattern.pattern, pattern.pattern_offset, true); ptr) return ptr;
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
            if (max == original_s.size()) return fix_target;
            if (max > maybe_target_count) {
                maybe_target_count = max;
                maybe_target_addr = fix_target;
            }
        }
        if (maybe_target_addr) {
            OUTPUT_SIGNATURE((void *) original.address, original_s.to_string());
            fprintf(stderr, "maybe target:\n");
            OUTPUT_SIGNATURE(maybe_target_addr, get_signature_cache(creator, maybe_target_addr)->to_string());
            return maybe_target_addr;
        }
        OUTPUT_SIGNATURE((void *) original.address, original_s.to_string());
        return nullptr;
#endif
    }
}// namespace function_relocation