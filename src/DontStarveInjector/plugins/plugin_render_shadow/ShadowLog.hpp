#pragma once

// Per-frame dumps. Off by default even in Debug.
// Enable: #define DS_SHADOW_TRACE 1 before include, or -DDS_SHADOW_TRACE=1
#ifndef DS_SHADOW_TRACE
#define DS_SHADOW_TRACE 0
#endif

#if DS_SHADOW_TRACE
#include <spdlog/spdlog.h>
#define SHADOW_TRACE(...) spdlog::debug(__VA_ARGS__)
#else
#define SHADOW_TRACE(...) ((void)0)
#endif
