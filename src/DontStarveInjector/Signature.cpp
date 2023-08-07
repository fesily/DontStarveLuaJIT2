#include <cassert>
#include <Windows.h>
#include "Signature.hpp"

static gboolean sacnBaseAddrCb(GumAddress address, gsize size, gpointer user_data)
{
    auto self = (Signature *)user_data;
    assert(self->target_address == 0);
    self->target_address = address + self->pattern_offset;
    return true;
}

static gboolean findBaseAddrCb(const GumRangeDetails *details, gpointer user_data)
{
    auto self = (Signature *)user_data;
    gum_memory_scan(details->range, self->match_pattern, sacnBaseAddrCb, user_data);
    return true;
}

GumAddress Signature::scan(const char *m)
{
    target_address = 0;
    match_pattern = gum_match_pattern_new_from_string(pattern);
    gum_module_enumerate_ranges(m, page, findBaseAddrCb, (gpointer)this);
    gum_match_pattern_unref(match_pattern);
    char buf[128];
    snprintf(buf, 128, "Signature %s: %p\n", pattern, (void *)target_address);
    OutputDebugStringA(buf);
    return target_address;
}