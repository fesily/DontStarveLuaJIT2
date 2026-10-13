#include <stddef.h>

int plt_test_symbol(void) { return 3; }
int plt_test_weak_symbol(void) { return 3; }
int luaL_loadbuffer(void *state, const char *buffer, size_t size, const char *name) { return 77; }
