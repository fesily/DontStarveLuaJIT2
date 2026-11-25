// Vendored third-party library: fast_assert.
//
// The macro surface and the plain-old-data types live here. The implementation
// (reporting path + handler slot, src/fast_assert.cpp and
// src/fast_assert_state.cpp) is compiled into the `fast_assert_owner` target and
// linked by exactly one module per process — the Injector here, which exports
// every entry point (see include/fast_assert/export.hpp).

#ifndef FAST_ASSERT_FAST_ASSERT_HPP
#define FAST_ASSERT_FAST_ASSERT_HPP

#include <version>

#if !defined(__cpp_lib_unreachable) || __cpp_lib_unreachable < 202202L
#  error "fast_assert.hpp requires a standard library with std::unreachable()"
#endif
#if !defined(__has_cpp_attribute) || __has_cpp_attribute(assume) < 202207L
#  error "fast_assert.hpp requires a compiler implementing C++23 [[assume]]"
#endif

#include <source_location>
#include <utility>  // std::unreachable (NDEBUG UNREACHABLE)

#include "fast_assert/export.hpp"

namespace fast_assert {

enum class Kind {
    debug_assertion,
    assertion,
    assumption,
    panic,
    unreachable
};

struct Failure {
    Kind kind;
    const char* expression;   // nullptr for PANIC / UNREACHABLE
    const char* message;      // nullptr if not supplied
    std::source_location location;
};

using Handler = void (*)(const Failure&) noexcept;

// Everything below is implemented once by the owner module (the one built with
// FAST_ASSERT_BUILD — the Injector here) and imported by every other module.
FAST_ASSERT_API void ignore_handler(const Failure&) noexcept;
FAST_ASSERT_API void log_handler(const Failure& f) noexcept;
[[noreturn]] FAST_ASSERT_API void abort_handler(const Failure& f) noexcept;

// Process-wide handler slot. The handler may be switched at runtime, including
// while other threads run; the callback itself must remain valid for in-flight
// invocations.
FAST_ASSERT_API void set_handler(Handler h) noexcept;
FAST_ASSERT_API Handler get_handler() noexcept;

namespace detail {

struct OptionalMessage { const char* text = nullptr; };

FAST_ASSERT_API void fail(Kind kind, const char* expr, const char* message,
                          std::source_location loc) noexcept;

[[noreturn]] FAST_ASSERT_API void fail_unconditional(
    Kind kind, const char* message, std::source_location loc) noexcept;

} // namespace detail
} // namespace fast_assert

#define FAST_ASSERT_DETAIL_CHECK(kind, expr, ...)                          \
    do {                                                                   \
        if (!(expr)) [[unlikely]] {                                         \
            ::fast_assert::detail::fail(                                   \
                ::fast_assert::Kind::kind, #expr,                          \
                ::fast_assert::detail::OptionalMessage{__VA_ARGS__}.text,  \
                std::source_location::current());                          \
        }                                                                  \
    } while (false)

#define FAST_ASSERT(expr, ...)                                                  \
    FAST_ASSERT_DETAIL_CHECK(assertion, expr __VA_OPT__(,) __VA_ARGS__)

#ifndef NDEBUG
#  define FAST_DEBUG_ASSERT(expr, ...)                                          \
    FAST_ASSERT_DETAIL_CHECK(debug_assertion, expr __VA_OPT__(,) __VA_ARGS__)
#  define FAST_ASSUME(expr, ...)                                                \
    FAST_ASSERT_DETAIL_CHECK(assumption, expr __VA_OPT__(,) __VA_ARGS__)
#  define FAST_UNREACHABLE(...)                                                 \
    do {                                                                   \
        ::fast_assert::detail::fail_unconditional(                         \
            ::fast_assert::Kind::unreachable,                              \
            ::fast_assert::detail::OptionalMessage{__VA_ARGS__}.text,     \
            std::source_location::current());                              \
    } while (false)
#else
#  define FAST_DEBUG_ASSERT(...) ((void)0)
#  define FAST_ASSUME(expr, ...) do { [[assume(expr)]]; } while (false)
#  define FAST_UNREACHABLE(...) do { std::unreachable(); } while (false)
#endif

#define FAST_PANIC(...)                                                          \
    do {                                                                    \
        ::fast_assert::detail::fail_unconditional(                          \
            ::fast_assert::Kind::panic,                                     \
            ::fast_assert::detail::OptionalMessage{__VA_ARGS__}.text,      \
            std::source_location::current());                               \
    } while (false)

#endif // FAST_ASSERT_FAST_ASSERT_HPP
