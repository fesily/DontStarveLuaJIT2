#pragma once

#ifdef ENABLE_FAKE_API
#define USE_FAKE_API 1
#else
#define USE_FAKE_API 0
#endif

#ifndef USE_GAME_IO
#define USE_GAME_IO ONLY_LUA51
#endif

#ifndef REPLACE_IO
#define REPLACE_IO !ONLY_LUA51
#endif

#ifndef DEBUG_GETSIZE_PATCH
#define DEBUG_GETSIZE_PATCH 1
#endif

