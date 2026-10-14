int plt_test_symbol(void) { return 2; }
__attribute__((weak)) int plt_test_weak_symbol(void) { return 2; }

int plt_test_call_global(void) { return plt_test_symbol(); }
int plt_test_call_global_weak(void) { return plt_test_weak_symbol(); }
