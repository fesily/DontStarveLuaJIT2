// Offline unit tests: sha256 helper + zip extract allowlist / path-traversal reject.
#include "plugins/plugin_manager/PluginHash.hpp"
#include "plugins/plugin_manager/PluginZipExtract.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <zip.h>

namespace fs = std::filesystem;
using namespace ds::plugin_manager;

static fs::path make_temp_dir(const char *tag) {
    std::error_code ec;
    auto base = fs::temp_directory_path(ec) / (std::string("ds_t8_") + tag);
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    return base;
}

static void write_bytes(const fs::path &p, const std::string &s) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    assert(out.is_open());
    out.write(s.data(), static_cast<std::streamsize>(s.size()));
    assert(out);
}

static std::string read_bytes(const fs::path &p) {
    std::ifstream in(p, std::ios::binary);
    assert(in.is_open());
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static void test_sha256_known_vectors() {
    // FIPS / common test vectors
    assert(sha256_hex("") ==
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert(sha256_hex("abc") ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert(sha256_hex("hello") ==
           "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    assert(sha256_hex_equal(
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    assert(sha256_hex_equal(
        "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    printf("PASS: sha256_known_vectors\n");
}

static void test_sha256_file() {
    const auto dir = make_temp_dir("sha_file");
    const auto p = dir / "blob.bin";
    write_bytes(p, "abc");
    auto dig = sha256_file_hex(p);
    assert(dig.has_value());
    assert(*dig == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    std::error_code ec;
    fs::remove_all(dir, ec);
    printf("PASS: sha256_file\n");
}

static fs::path build_zip_with_entries(
    const fs::path &zip_path,
    const std::vector<std::pair<std::string, std::string>> &entries) {
    int zerr = 0;
    zip_t *za = zip_open(zip_path.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &zerr);
    assert(za);
    for (const auto &e : entries) {
        void *copy = malloc(e.second.size() ? e.second.size() : 1);
        assert(copy);
        if (!e.second.empty()) {
            memcpy(copy, e.second.data(), e.second.size());
        }
        zip_source_t *src = zip_source_buffer(za, copy, e.second.size(), 1);
        assert(src);
        assert(zip_file_add(za, e.first.c_str(), src, ZIP_FL_ENC_UTF_8) >= 0);
    }
    assert(zip_close(za) == 0);
    return zip_path;
}

static void test_zip_unsafe_detection() {
    assert(zip_entry_is_unsafe(".."));
    assert(zip_entry_is_unsafe("../evil.dll"));
    assert(zip_entry_is_unsafe("foo/../../x.dll"));
    assert(zip_entry_is_unsafe("/abs.dll"));
    assert(zip_entry_is_unsafe("C:/abs.dll"));
    assert(zip_entry_is_unsafe("nested/../escape.dll"));
    assert(!zip_entry_is_unsafe("plugin_dummy.dll"));
    assert(!zip_entry_is_unsafe("plugin_dummy.meta.json"));
    assert(zip_entry_safe_basename("../x").empty());
    assert(zip_entry_safe_basename("plugin_dummy.dll") == "plugin_dummy.dll");
    printf("PASS: zip_unsafe_detection\n");
}

static void test_zip_extract_allowlist_default() {
    const auto dir = make_temp_dir("zip_def");
    const auto zip = dir / "pkg.zip";
    build_zip_with_entries(zip, {
                                    {"plugin_dummy.dll", "MZ-dummy"},
                                    {"plugin_dummy.meta.json", "{\"id\":\"debug.dummy\"}"},
                                    {"readme.txt", "nope"},
                                });
    const auto out = dir / "out";
    std::string err;
    auto n = extract_plugin_zip(zip, out, /*allow_files=*/{}, &err);
    assert(n.has_value());
    assert(*n == 2);
    assert(read_bytes(out / "plugin_dummy.dll") == "MZ-dummy");
    assert(fs::exists(out / "plugin_dummy.meta.json"));
    assert(!fs::exists(out / "readme.txt"));
    std::error_code ec;
    fs::remove_all(dir, ec);
    printf("PASS: zip_extract_allowlist_default\n");
}

static void test_zip_extract_explicit_allowlist() {
    const auto dir = make_temp_dir("zip_allow");
    const auto zip = dir / "pkg.zip";
    build_zip_with_entries(zip, {
                                    {"plugin_dummy.dll", "MZ"},
                                    {"plugin_dummy.meta.json", "{}"},
                                    {"extra.txt", "x"},
                                });
    const auto out = dir / "out";
    std::string err;
    auto n = extract_plugin_zip(zip, out, {"plugin_dummy.dll"}, &err);
    assert(n.has_value());
    assert(*n == 1);
    assert(fs::exists(out / "plugin_dummy.dll"));
    assert(!fs::exists(out / "plugin_dummy.meta.json"));
    assert(!fs::exists(out / "extra.txt"));
    std::error_code ec;
    fs::remove_all(dir, ec);
    printf("PASS: zip_extract_explicit_allowlist\n");
}

static void test_zip_reject_dotdot() {
    const auto dir = make_temp_dir("zip_dot");
    const auto zip = dir / "evil.zip";
    // libzip may normalize names; craft with explicit .. segment.
    build_zip_with_entries(zip, {
                                    {"../evil.dll", "bad"},
                                });
    const auto out = dir / "out";
    std::string err;
    auto n = extract_plugin_zip(zip, out, {}, &err);
    assert(!n.has_value());
    assert(!err.empty());
    assert(!fs::exists(out / "evil.dll"));
    std::error_code ec;
    fs::remove_all(dir, ec);
    printf("PASS: zip_reject_dotdot\n");
}

static void test_zip_reject_nested() {
    const auto dir = make_temp_dir("zip_nest");
    const auto zip = dir / "nest.zip";
    build_zip_with_entries(zip, {
                                    {"subdir/plugin_dummy.dll", "MZ"},
                                });
    const auto out = dir / "out";
    std::string err;
    auto n = extract_plugin_zip(zip, out, {}, &err);
    assert(!n.has_value());
    assert(err.find("nested") != std::string::npos || err.find("unsafe") != std::string::npos);
    std::error_code ec;
    fs::remove_all(dir, ec);
    printf("PASS: zip_reject_nested\n");
}

static void test_zip_memory_extract() {
    const auto dir = make_temp_dir("zip_mem");
    const auto zip = dir / "pkg.zip";
    build_zip_with_entries(zip, {{"plugin_x.dll", "DLLDATA"}});
    const std::string bytes = read_bytes(zip);
    const auto out = dir / "out";
    std::string err;
    auto n = extract_plugin_zip_memory(bytes.data(), bytes.size(), out, {"plugin_x.dll"}, &err);
    assert(n.has_value());
    assert(*n == 1);
    assert(read_bytes(out / "plugin_x.dll") == "DLLDATA");
    std::error_code ec;
    fs::remove_all(dir, ec);
    printf("PASS: zip_memory_extract\n");
}

int main() {
    test_sha256_known_vectors();
    test_sha256_file();
    test_zip_unsafe_detection();
    test_zip_extract_allowlist_default();
    test_zip_extract_explicit_allowlist();
    test_zip_reject_dotdot();
    test_zip_reject_nested();
    test_zip_memory_extract();
    printf("ALL PASS plugin_hash_zip\n");
    return 0;
}
