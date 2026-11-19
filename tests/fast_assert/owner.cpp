// Fixture: the module that owns the fast_assert implementation (stands in for
// the Injector). Links fast_assert_owner, so every entry point is exported here.

#include <fast_assert/fast_assert.hpp>

#if defined(_WIN32)
#  define DS_FA_TEST_EXPORT extern "C" __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#  define DS_FA_TEST_EXPORT extern "C" __attribute__((visibility("default")))
#else
#  define DS_FA_TEST_EXPORT extern "C"
#endif

DS_FA_TEST_EXPORT void ds_fa_owner_set(fast_assert::Handler h) {
    fast_assert::set_handler(h);
}

DS_FA_TEST_EXPORT void* ds_fa_owner_get() {
    return reinterpret_cast<void*>(fast_assert::get_handler());
}
