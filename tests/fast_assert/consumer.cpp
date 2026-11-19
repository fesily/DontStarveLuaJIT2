// Fixture consumer module, built twice:
//   fa_test_consumer      links the header view plus the owner module and imports
//                         every fast_assert symbol -> must see the owner's slot
//   fa_test_consumer_own  links fast_assert_owner itself -> must keep its own copy

#include <fast_assert/fast_assert.hpp>

#if defined(_WIN32)
#  define DS_FA_TEST_EXPORT extern "C" __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#  define DS_FA_TEST_EXPORT extern "C" __attribute__((visibility("default")))
#else
#  define DS_FA_TEST_EXPORT extern "C"
#endif

namespace {
int g_local_calls = 0;
const char* g_local_last_message = nullptr;

void local_handler(const fast_assert::Failure& f) noexcept {
    ++g_local_calls;
    g_local_last_message = f.message;
}
} // namespace

DS_FA_TEST_EXPORT void ds_fa_consumer_set_self() {
    fast_assert::set_handler(&local_handler);
}

DS_FA_TEST_EXPORT void* ds_fa_consumer_get() {
    return reinterpret_cast<void*>(fast_assert::get_handler());
}

DS_FA_TEST_EXPORT void ds_fa_consumer_fail() {
    FAST_ASSERT(false, "consumer-assert");
}

DS_FA_TEST_EXPORT int ds_fa_consumer_local_calls() {
    return g_local_calls;
}
