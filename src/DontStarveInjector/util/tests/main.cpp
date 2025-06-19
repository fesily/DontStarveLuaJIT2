#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string_view>
#include <string>
#ifdef _WIN32
#include "../win_wfile.hpp"

auto TestFileRoot = std::string_view(SOURCE_DIR "/win_wfile");

template<size_t buf_size = 512>
std::string read_file(const std::string &filename, const char *mode = "r") {
    auto file_path = TestFileRoot.data() + filename;

    auto fp = wFile_interface::fopen(file_path.c_str(), mode);
    REQUIRE_NE(fp, nullptr);
    std::string content;
    char buf[buf_size] = {};
    while (true) {
        auto readed = fp->fread(buf, 1, sizeof(buf));
        if (readed == 0) break;
        content.append(buf, readed);
    }
    fp->fclose();
    return content;
}

using namespace std::literals;
TEST_CASE("read_file") {
    auto context = read_file("/1.txt"s);
    CHECK_EQ(context, "Hello\rWorld\r\r"sv);
}

TEST_CASE("read_file_win_control") {
    auto context = read_file("/2.txt"s);
    CHECK_EQ(context, "Hel\x1Ao\r"sv);
}

TEST_CASE("read_file_sect_modmain") {
    auto context = read_file("/modmain0.lua"s, "rb");
    CHECK_EQ(context.length(), 11957);
    context = read_file("/modmain0.lua"s, "r");
    CHECK_EQ(context.length(), 11957);
}

TEST_CASE("read_file_len") {
    auto context = read_file("/bug512.txt"s);
    CHECK_EQ(context.length(), 511);
    CHECK_EQ(context.back(), '\r');
    context = read_file("/bug512.txt"s, "rb");
    CHECK_EQ(context.length(), 512);
    CHECK_EQ(context.back(), '\n');
}

TEST_CASE("read_file_len_1023") {
    auto context = read_file("/bug1023.txt"s, "rb");
    CHECK_EQ(context.length(), 1024);
    CHECK_EQ(context[511], '\r');
    CHECK_EQ(context.back(), '0');
    context = read_file("/bug1023.txt"s);
    CHECK_EQ(context.length(), 1023);
    CHECK_EQ(context[511], '\r');
    CHECK_EQ(context.back(), '0');
}
#endif
