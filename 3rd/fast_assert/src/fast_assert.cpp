// Reporting half of fast_assert: everything the macros need except the handler
// slot. Compiled once into the owner module and exported from there.

#include <fast_assert/fast_assert.hpp>

#include <cstdio>
#include <cstdlib>

namespace fast_assert {

FAST_ASSERT_API void ignore_handler(const Failure&) noexcept {}

FAST_ASSERT_API void log_handler(const Failure& f) noexcept {
    const char* label = "ASSERT";
    switch (f.kind) {
        case Kind::debug_assertion: label = "DEBUG_ASSERT"; break;
        case Kind::assertion:       label = "ASSERT";       break;
        case Kind::assumption:      label = "ASSUME";       break;
        case Kind::panic:           label = "PANIC";        break;
        case Kind::unreachable:     label = "UNREACHABLE";  break;
    }

    std::fprintf(stderr, "%s failed at %s:%u in %s", label,
                 f.location.file_name(), f.location.line(),
                 f.location.function_name());
    if (f.expression) std::fprintf(stderr, ": %s", f.expression);
    if (f.message)    std::fprintf(stderr, " (%s)", f.message);
    std::fputc('\n', stderr);
}

FAST_ASSERT_API void abort_handler(const Failure& f) noexcept {
    log_handler(f);
    std::abort();
}

namespace detail {

FAST_ASSERT_API void fail(Kind kind, const char* expr, const char* message,
                          std::source_location loc) noexcept {
    get_handler()(Failure{kind, expr, message, loc});
}

FAST_ASSERT_API void fail_unconditional(
    Kind kind, const char* message, std::source_location loc) noexcept {
    fail(kind, nullptr, message, loc);
    std::abort(); // PANIC / Debug UNREACHABLE cannot be suppressed.
}

} // namespace detail
} // namespace fast_assert
