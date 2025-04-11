#include "MemorySignature.hpp"
#include <frida-gum.h>
#include <cassert>
#include <tuple>
#include <spdlog/spdlog.h>
#include "config.hpp"
namespace function_relocation
{

static gboolean sacnBaseAddrCb(GumAddress address, gsize size, gpointer user_data) {
    auto self = static_cast<MemorySignature*>(user_data);
    if (self->only_one) assert(self->target_address == 0);
    self->target_address = address + self->pattern_offset;
    self->targets.push_back(address + self->pattern_offset);
    if (self->log)
        spdlog::get(logger_name)->info("\t {}", (void *) self->target_address);
    return true;
}

static gboolean findBaseAddrCb(const GumRangeDetails* details, gpointer user_data) {
    auto p = static_cast<std::pair<MemorySignature*, GumMatchPattern*>*>(user_data);
    gum_memory_scan(details->range, p->second, sacnBaseAddrCb, (void*)p->first);
    return true;
}

uintptr_t MemorySignature::scan(const char* module_name) {
    target_address = 0;
    auto match_pattern = gum_match_pattern_new_from_string(pattern);
    assert(match_pattern);
    if (log)
        spdlog::get(logger_name)->info("{} Signature {}", module_name, pattern);
    auto ctx = std::pair{ this, match_pattern };
    auto m = gum_process_find_module_by_name(module_name);
    gum_module_enumerate_ranges(m, this-> prot_flag, findBaseAddrCb, (gpointer)&ctx);
    gum_match_pattern_unref(match_pattern);
    return target_address;
}
uintptr_t MemorySignature::scan(uintptr_t address, size_t size) {
    target_address = 0;
    auto match_pattern = gum_match_pattern_new_from_string(pattern);
    assert(match_pattern);
    if (log)
        spdlog::get(logger_name)->info("Scan [{}, {}] Signature {}", (void *) address, size, pattern);
    auto ctx = std::pair{ this, match_pattern };
    GumMemoryRange range{address, size};
    gum_memory_scan(&range, match_pattern, sacnBaseAddrCb, (void*)this);
    gum_match_pattern_unref(match_pattern);
    return target_address;
}
}// namespace function_relocation
