#ifndef NDEBUG
#error Performance builds require NDEBUG
#endif
#if defined(LUA_USE_ASSERT) || defined(LUA_USE_APICHECK)
#error Performance builds must disable Lua assertions and API checks
#endif
#if defined(LUAJIT_TEST_RETM) || defined(LUAJIT_TEST_STACK_OOM)
#error Performance builds must disable VM test diagnostics
#endif
