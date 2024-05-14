#include "MemorySignature.hpp"
#include <frida-gum.h>
#include <cassert>
#include <tuple>
namespace function_relocation
{

constexpr auto page = GUM_PAGE_EXECUTE;

static gboolean sacnBaseAddrCb(GumAddress address, gsize size, gpointer user_data) {
    auto self = static_cast<MemorySignature*>(user_data);
    if (self->only_one) assert(self->target_address == 0);
    self->target_address = address + self->pattern_offset;
    self->targets.push_back(address + self->pattern_offset);
    fprintf(stdout, "\t %p\n", (void *) self->target_address);
    return true;
}

static gboolean findBaseAddrCb(const GumRangeDetails* details, gpointer user_data) {
    auto p = static_cast<std::pair<MemorySignature*, GumMatchPattern*>*>(user_data);
    gum_memory_scan(details->range, p->second, sacnBaseAddrCb, (void*)p->first);
    return true;
}

uintptr_t MemorySignature::scan(const char* m) {
    target_address = 0;
    auto match_pattern = gum_match_pattern_new_from_string(pattern);
    assert(match_pattern);
    fprintf(stdout, "%s Signature %s\n", m, pattern, (void *) target_address);
    auto ctx = std::pair{ this, match_pattern };
    gum_module_enumerate_ranges(m, page, findBaseAddrCb, (gpointer)&ctx);
    gum_match_pattern_unref(match_pattern);
    return target_address;
}
}
