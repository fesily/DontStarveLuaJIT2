#include "MemorySignature.hpp"
#include <frida-gum.h>
#include <cassert>
#include <cctype>
#include <string>
#include <tuple>
#include <spdlog/spdlog.h>
#include "config.hpp"
namespace function_relocation
{

// Frida-Gum ≥16 rejects patterns that END with wildcard tokens (??). Trailing
// wildcards do not change the match start, so strip them before parse. Also
// collapse runs of spaces. Returns empty if nothing fixed remains.
static std::string normalize_gum_pattern(const char *raw) {
    if (!raw || !*raw) return {};
    std::string s(raw);
    // Trim trailing spaces / '?' so the last token is a fixed byte when possible.
    while (!s.empty() && (s.back() == ' ' || s.back() == '?')) {
        s.pop_back();
    }
    // Collapse internal double spaces (knowns seeds sometimes have them).
    std::string out;
    out.reserve(s.size());
    bool prev_space = false;
    for (char c : s) {
        if (c == ' ') {
            if (!prev_space && !out.empty()) out.push_back(' ');
            prev_space = true;
        } else {
            out.push_back(c);
            prev_space = false;
        }
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    // Require at least one fixed hex nibble so gum has an anchor.
    bool has_fixed = false;
    for (char c : out) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            has_fixed = true;
            break;
        }
    }
    if (!has_fixed) return {};
    return out;
}

static gboolean sacnBaseAddrCb(GumAddress address, gsize size, gpointer user_data) {
    auto self = static_cast<MemorySignature*>(user_data);
    if (self->only_one) assert(self->target_address == 0);
    self->target_address = address + self->pattern_offset;
    self->targets.push_back(address + self->pattern_offset);
    if (self->log) {
        if (auto logger = spdlog::get(logger_name)) {
            logger->info("\t {}", (void *) self->target_address);
        }
    }
    return true;
}

static gboolean findBaseAddrCb(const GumRangeDetails* details, gpointer user_data) {
    auto p = static_cast<std::pair<MemorySignature*, GumMatchPattern*>*>(user_data);
    gum_memory_scan(details->range, p->second, sacnBaseAddrCb, (void*)p->first);
    return true;
}

uintptr_t MemorySignature::scan(const char* module_name) {
    target_address = 0;
    const std::string normalized = normalize_gum_pattern(pattern);
    if (normalized.empty()) {
        if (auto logger = spdlog::get(logger_name)) {
            logger->error("MemorySignature::scan: empty/invalid pattern after normalize: '{}'",
                          pattern ? pattern : "<null>");
        }
        return 0;
    }
    auto match_pattern = gum_match_pattern_new_from_string(normalized.c_str());
    if (!match_pattern) {
        if (auto logger = spdlog::get(logger_name)) {
            logger->error("MemorySignature::scan: gum parse failed for '{}'", normalized);
        }
        return 0;
    }
    auto ctx = std::pair{ this, match_pattern };
    auto m = module_name ? gum_process_find_module_by_name(module_name) : gum_process_get_main_module();
    if (log) {
        if (auto logger = spdlog::get(logger_name)) {
            logger->info("{} Signature {}", gum_module_get_path(m), normalized);
        }
    }
    gum_module_enumerate_ranges(m, this-> prot_flag, findBaseAddrCb, (gpointer)&ctx);
    gum_match_pattern_unref(match_pattern);
    return target_address;
}
uintptr_t MemorySignature::scan(uintptr_t address, size_t size) {
    target_address = 0;
    const std::string normalized = normalize_gum_pattern(pattern);
    if (normalized.empty()) {
        if (auto logger = spdlog::get(logger_name)) {
            logger->error("MemorySignature::scan: empty/invalid pattern after normalize: '{}'",
                          pattern ? pattern : "<null>");
        }
        return 0;
    }
    auto match_pattern = gum_match_pattern_new_from_string(normalized.c_str());
    if (!match_pattern) {
        if (auto logger = spdlog::get(logger_name)) {
            logger->error("MemorySignature::scan: gum parse failed for '{}'", normalized);
        }
        return 0;
    }
    if (log) {
        if (auto logger = spdlog::get(logger_name)) {
            logger->info("Scan [{}, {}] Signature {}", (void *) address, size, normalized);
        }
    }
    GumMemoryRange range{address, size};
    gum_memory_scan(&range, match_pattern, sacnBaseAddrCb, (void*)this);
    gum_match_pattern_unref(match_pattern);
    return target_address;
}
}// namespace function_relocation
