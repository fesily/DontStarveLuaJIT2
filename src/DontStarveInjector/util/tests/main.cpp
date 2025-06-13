#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string_view>
#ifdef _WIN32
#include "../win_wfile.hpp"

auto TestFileRoot = std::string_view(SOURCE_DIR "/win_wfile");
using namespace std::literals;
TEST_CASE("read_file") {
    auto file1 = TestFileRoot.data() + "/1.txt"s;
    auto fp = wFile_interface::fopen(file1.c_str(), "rt");
    CHECK(fp == nullptr);
    fp = wFile_interface::fopen(file1.c_str(), "r");
    CHECK(fp != nullptr);
    char buf[1024] = {};
    auto readed = fp->fread(buf, 1, sizeof(buf) - 1);
    CHECK(readed > 0);
    CHECK_EQ(std::string_view(buf, readed), "Hello\rWorld\r\r"sv);
    fp->fclose();
}

TEST_CASE("read_file_win_control") {
    auto file1 = TestFileRoot.data() + "/2.txt"s;
    auto fp = wFile_interface::fopen(file1.c_str(), "r");
    CHECK(fp != nullptr);
    char buf[1024] = {};
    auto readed = fp->fread(buf, 1, sizeof(buf) - 1);
    CHECK(readed > 0);
    CHECK_EQ(std::string_view(buf, readed), "Hel\x1Ao\r"sv);
    fp->fclose();
}

TEST_CASE("read_file_sect_modmain") {
    auto file1 = TestFileRoot.data() + "/modmain0.lua"s;
    auto fp = wFile_interface::fopen(file1.c_str(), "rb");
    CHECK(fp != nullptr);
    int all_count = 0;

    std::string all_buf;
    while (true) {
        char buf[1024] = {};
        auto readed = fp->fread(buf, 1, sizeof(buf) - 1);
        if (readed == 0) break;
        all_buf.append(buf, readed);
        all_count += readed;
    }
    CHECK_EQ(all_count, 11957);
    fp->fclose();
}
#endif
