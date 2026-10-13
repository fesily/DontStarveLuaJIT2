// These local names deliberately collide with dynamic import names in another TU.
static __attribute__((noinline)) int plt_test_symbol(void) { return 1; }
static __attribute__((noinline)) int plt_test_weak_symbol(void) { return 1; }

int plt_test_call_local(void) { return plt_test_symbol(); }
int plt_test_call_local_weak(void) { return plt_test_weak_symbol(); }
