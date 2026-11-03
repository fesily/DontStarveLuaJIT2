#include <doctest/doctest.h>

#include "../PathText.hpp"

#include <exception>
#include <filesystem>
#include <string>

namespace {

namespace fs = std::filesystem;

// A Klei save root can hold a name that was meant to be GBK but was stored one
// character per byte as Latin-1 (the "crazy slot machine" save folder). Every
// one of these code points is legal on NTFS; none of them map in CP936, so
// `fs::path::string()` throws ERROR_NO_UNICODE_TRANSLATION (1113) on a Chinese
// Windows.
constexpr char8_t kUnrepresentableName[] =
    u8"\u00b7\u00e8\u00bf\u00f1\u00cc\u00cf\u00bb\u00a2\u00bb\u00fa";

fs::path unrepresentable_path() {
    return fs::path{std::u8string{kUnrepresentableName}};
}

} // namespace

TEST_CASE("path_to_utf8 keeps every code point regardless of the ANSI code page") {
    const std::string utf8 = ds::util::path_to_utf8(unrepresentable_path());
    CHECK_EQ(utf8, std::string{reinterpret_cast<const char *>(kUnrepresentableName)});
}

TEST_CASE("path_to_native_lossy never throws on a name the ANSI code page cannot map") {
    const fs::path path = unrepresentable_path();
    bool narrow_throws = false;
    try {
        (void) path.string();
    } catch (const std::exception &) {
        narrow_throws = true;
    }
    if (!narrow_throws) {
        MESSAGE("active ANSI code page maps all test characters; "
                "only the no-throw contract is exercised here");
    }
    CHECK_NOTHROW((void) ds::util::path_to_native_lossy(path));
    CHECK_FALSE(ds::util::path_to_native_lossy(path).empty());
    if (narrow_throws) {
        CHECK_EQ(ds::util::path_to_native_lossy(path), ds::util::path_to_utf8(path));
    }
}

TEST_CASE("path_from_utf8 round-trips UTF-8 text") {
    const fs::path path = unrepresentable_path();
    CHECK(fs::path{ds::util::path_from_utf8(ds::util::path_to_utf8(path))} == path);
    CHECK(ds::util::path_from_utf8("").empty());
}
