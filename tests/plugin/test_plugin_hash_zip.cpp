// Offline unit tests: sha256 helper + zip extract allowlist / path-traversal reject.
#include "plugins/plugin_manager/PluginHash.hpp"
#include "plugins/plugin_manager/PluginZipExtract.hpp"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>


#include <zip.h>
#include <doctest/doctest.h>

namespace fs = std::filesystem;
using namespace ds::plugin_manager;

static fs::path make_temp_dir(const char *tag) {
    std::error_code ec;
    auto base = fs::temp_directory_path(ec) / (std::string("ds_t8_") + tag);
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    return base;
}

// Removes the scratch tree even when an assertion unwinds the case.
struct TempDirGuard {
    fs::path dir;
    explicit TempDirGuard(const fs::path &d) : dir(d) {}
    ~TempDirGuard() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

static void write_bytes(const fs::path &p, const std::string &s) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    REQUIRE(out.is_open());
    out.write(s.data(), static_cast<std::streamsize>(s.size()));
    REQUIRE(out);
}

static std::string read_bytes(const fs::path &p) {
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in.is_open());
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

TEST_CASE("test_plugin_hash_zip/sha256_known_vectors") {
    // FIPS / common test vectors
    REQUIRE_EQ(sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    REQUIRE_EQ(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    REQUIRE_EQ(sha256_hex("hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    REQUIRE(sha256_hex_equal(
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    REQUIRE(sha256_hex_equal(
        "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

TEST_CASE("test_plugin_hash_zip/sha256_file") {
    const auto dir = make_temp_dir("sha_file");
    TempDirGuard guard{dir};
    const auto p = dir / "blob.bin";
    write_bytes(p, "abc");
    auto dig = sha256_file_hex(p);
    REQUIRE(dig.has_value());
    REQUIRE_EQ(*dig, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static fs::path build_zip_with_entries(
    const fs::path &zip_path,
    const std::vector<std::pair<std::string, std::string>> &entries) {
    int zerr = 0;
    zip_t *za = zip_open(zip_path.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &zerr);
    REQUIRE(za);
    for (const auto &e : entries) {
        void *copy = malloc(e.second.size() ? e.second.size() : 1);
        REQUIRE(copy);
        if (!e.second.empty()) {
            memcpy(copy, e.second.data(), e.second.size());
        }
        zip_source_t *src = zip_source_buffer(za, copy, e.second.size(), 1);
        REQUIRE(src);
        REQUIRE_GE(zip_file_add(za, e.first.c_str(), src, ZIP_FL_ENC_UTF_8), 0);
    }
    REQUIRE_EQ(zip_close(za), 0);
    return zip_path;
}

TEST_CASE("test_plugin_hash_zip/zip_unsafe_detection") {
    REQUIRE(zip_entry_is_unsafe(".."));
    REQUIRE(zip_entry_is_unsafe("../evil.dll"));
    REQUIRE(zip_entry_is_unsafe("foo/../../x.dll"));
    REQUIRE(zip_entry_is_unsafe("/abs.dll"));
    REQUIRE(zip_entry_is_unsafe("C:/abs.dll"));
    REQUIRE(zip_entry_is_unsafe("nested/../escape.dll"));
    REQUIRE_FALSE(zip_entry_is_unsafe("plugin_dummy.dll"));
    REQUIRE_FALSE(zip_entry_is_unsafe("plugin_dummy.meta.json"));
    REQUIRE(zip_entry_safe_basename("../x").empty());
    REQUIRE_EQ(zip_entry_safe_basename("plugin_dummy.dll"), "plugin_dummy.dll");
}

TEST_CASE("test_plugin_hash_zip/zip_extract_empty_allowlist") {
    // Empty allowlist = every SAFE member (fixtures/tests); the manager always passes
    // manifest files[]. Unsafe members are still rejected regardless.
    const auto dir = make_temp_dir("zip_def");
    TempDirGuard guard{dir};
    const auto zip = dir / "pkg.zip";
    build_zip_with_entries(zip, {
                                    {"plugin_dummy.dll", "MZ-dummy"},
                                    {"plugin_dummy.meta.json", "{\"id\":\"debug.dummy\"}"},
                                    {"readme.txt", "kept"},
                                });
    const auto out = dir / "out";
    std::string err;
    auto n = extract_plugin_zip(zip, out, /*allow_files=*/{}, &err);
    REQUIRE(n.has_value());
    REQUIRE_EQ(*n, 3);
    REQUIRE_EQ(read_bytes(out / "plugin_dummy.dll"), "MZ-dummy");
    REQUIRE(fs::exists(out / "plugin_dummy.meta.json"));
    REQUIRE(fs::exists(out / "readme.txt"));
}

TEST_CASE("test_plugin_hash_zip/zip_extract_explicit_allowlist") {
    const auto dir = make_temp_dir("zip_allow");
    TempDirGuard guard{dir};
    const auto zip = dir / "pkg.zip";
    build_zip_with_entries(zip, {
                                    {"plugin_dummy.dll", "MZ"},
                                    {"plugin_dummy.meta.json", "{}"},
                                    {"extra.txt", "x"},
                                });
    const auto out = dir / "out";
    std::string err;
    auto n = extract_plugin_zip(zip, out, {"plugin_dummy.dll"}, &err);
    REQUIRE(n.has_value());
    REQUIRE_EQ(*n, 1);
    REQUIRE(fs::exists(out / "plugin_dummy.dll"));
    REQUIRE_FALSE(fs::exists(out / "plugin_dummy.meta.json"));
    REQUIRE_FALSE(fs::exists(out / "extra.txt"));
}

TEST_CASE("test_plugin_hash_zip/zip_reject_dotdot") {
    const auto dir = make_temp_dir("zip_dot");
    TempDirGuard guard{dir};
    const auto zip = dir / "evil.zip";
    // libzip may normalize names; craft with explicit .. segment.
    build_zip_with_entries(zip, {
                                    {"../evil.dll", "bad"},
                                });
    const auto out = dir / "out";
    std::string err;
    auto n = extract_plugin_zip(zip, out, {}, &err);
    REQUIRE_FALSE(n.has_value());
    REQUIRE_FALSE(err.empty());
    REQUIRE_FALSE(fs::exists(out / "evil.dll"));
}

TEST_CASE("test_plugin_hash_zip/zip_nested_members") {
    // Package layout: nested members (modinfo.lua, scripts/...) extract with their
    // subdirectories preserved; escaping paths are still rejected.
    {
        const auto dir = make_temp_dir("zip_nest_ok");
        TempDirGuard guard{dir};
        const auto zip = dir / "nest.zip";
        build_zip_with_entries(zip, {
                                        {"plugin_dummy.dll", "MZ"},
                                        {"scripts/a.lua", "return 1"},
                                    });
        const auto out = dir / "out";
        std::string err;
        auto n = extract_plugin_zip(zip, out,
                                    {"plugin_dummy.dll", "scripts/a.lua"}, &err);
        REQUIRE(n.has_value());
        REQUIRE_EQ(*n, 2);
        REQUIRE_EQ(read_bytes(out / "plugin_dummy.dll"), "MZ");
        REQUIRE_EQ(read_bytes(out / "scripts" / "a.lua"), "return 1");
    }
    {
        const auto dir = make_temp_dir("zip_nest_escape");
        TempDirGuard guard{dir};
        const auto zip = dir / "nest.zip";
        build_zip_with_entries(zip, {
                                        {"scripts/../../escape.lua", "bad"},
                                    });
        const auto out = dir / "out";
        std::string err;
        auto n = extract_plugin_zip(zip, out, {}, &err);
        REQUIRE_FALSE(n.has_value());
        const bool unsafe_err = err.find("unsafe") != std::string::npos ||
                                err.find("nested") != std::string::npos;
        REQUIRE(unsafe_err);
        REQUIRE_FALSE(fs::exists(dir / "escape.lua"));
    }
}

TEST_CASE("test_plugin_hash_zip/zip_memory_extract") {
    const auto dir = make_temp_dir("zip_mem");
    TempDirGuard guard{dir};
    const auto zip = dir / "pkg.zip";
    build_zip_with_entries(zip, {{"plugin_x.dll", "DLLDATA"}});
    const std::string bytes = read_bytes(zip);
    const auto out = dir / "out";
    std::string err;
    auto n = extract_plugin_zip_memory(bytes.data(), bytes.size(), out, {"plugin_x.dll"}, &err);
    REQUIRE(n.has_value());
    REQUIRE_EQ(*n, 1);
    REQUIRE_EQ(read_bytes(out / "plugin_x.dll"), "DLLDATA");
}

// Minimal stored zip with forged uncompressed size in local + central headers.
// Used to exercise extract caps without allocating 64 MiB of payload.
static std::string craft_zip_forged_uncompressed(const std::string &name,
                                                 std::uint32_t declared_uncomp,
                                                 const std::string &payload) {
    auto put_u16 = [](std::string &o, std::uint16_t v) {
        o.push_back(static_cast<char>(v & 0xff));
        o.push_back(static_cast<char>((v >> 8) & 0xff));
    };
    auto put_u32 = [](std::string &o, std::uint32_t v) {
        o.push_back(static_cast<char>(v & 0xff));
        o.push_back(static_cast<char>((v >> 8) & 0xff));
        o.push_back(static_cast<char>((v >> 16) & 0xff));
        o.push_back(static_cast<char>((v >> 24) & 0xff));
    };

    const std::uint32_t comp = static_cast<std::uint32_t>(payload.size());
    const std::uint16_t nlen = static_cast<std::uint16_t>(name.size());

    std::string local;
    put_u32(local, 0x04034b50u); // local header sig
    put_u16(local, 20);          // version needed
    put_u16(local, 0);           // flags
    put_u16(local, 0);           // method store
    put_u16(local, 0);           // time
    put_u16(local, 0);           // date
    put_u32(local, 0);           // crc (ignore; we fail before full validate)
    put_u32(local, comp);        // compressed size
    put_u32(local, declared_uncomp);
    put_u16(local, nlen);
    put_u16(local, 0); // extra
    local.append(name);
    local.append(payload);

    std::string central;
    put_u32(central, 0x02014b50u);
    put_u16(central, 20); // version made by
    put_u16(central, 20); // version needed
    put_u16(central, 0);
    put_u16(central, 0);
    put_u16(central, 0);
    put_u16(central, 0);
    put_u32(central, 0);
    put_u32(central, comp);
    put_u32(central, declared_uncomp);
    put_u16(central, nlen);
    put_u16(central, 0);
    put_u16(central, 0);
    put_u16(central, 0);
    put_u16(central, 0);
    put_u32(central, 0);
    put_u32(central, 0); // relative offset of local header
    central.append(name);

    std::string eocd;
    put_u32(eocd, 0x06054b50u);
    put_u16(eocd, 0);
    put_u16(eocd, 0);
    put_u16(eocd, 1);
    put_u16(eocd, 1);
    put_u32(eocd, static_cast<std::uint32_t>(central.size()));
    put_u32(eocd, static_cast<std::uint32_t>(local.size()));
    put_u16(eocd, 0);

    return local + central + eocd;
}

TEST_CASE("test_plugin_hash_zip/zip_reject_oversized_entry") {
    REQUIRE_EQ(kMaxZipEntryUncompressedBytes, 64ull * 1024ull * 1024ull);
    REQUIRE_EQ(kMaxZipTotalUncompressedBytes, 128ull * 1024ull * 1024ull);

    const auto dir = make_temp_dir("zip_over");
    TempDirGuard guard{dir};
    const auto zip = dir / "huge.zip";
    const std::uint32_t over =
        static_cast<std::uint32_t>(kMaxZipEntryUncompressedBytes) + 1u;
    const std::string bytes =
        craft_zip_forged_uncompressed("plugin_huge.dll", over, "Z");
    write_bytes(zip, bytes);

    const auto out = dir / "out";
    std::string err;
    auto n = extract_plugin_zip(zip, out, {"plugin_huge.dll"}, &err);
    REQUIRE_FALSE(n.has_value());
    REQUIRE_NE(err.find("exceeds"), std::string::npos);
    REQUIRE_FALSE(fs::exists(out / "plugin_huge.dll"));
}
