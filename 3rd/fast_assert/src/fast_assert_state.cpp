// Handler slot of fast_assert: the single switchable handler for the process.
//
// Compiled with FAST_ASSERT_BUILD by exactly one module (the Injector); see
// include/fast_assert/export.hpp. Linking fast_assert_owner into a second module
// of the same process creates a second, independent implementation.

#include <fast_assert/fast_assert.hpp>

#include <atomic>

namespace fast_assert {
namespace {
std::atomic<Handler> slot{&abort_handler};
}

FAST_ASSERT_API void set_handler(Handler h) noexcept {
    slot.store(h ? h : &abort_handler, std::memory_order_release);
}

FAST_ASSERT_API Handler get_handler() noexcept {
    return slot.load(std::memory_order_acquire);
}
} // namespace fast_assert
