// Format gate for signatures_*.json (SignatureJson): the document carries a
// format_version plus one section per platform, so a single file can hold the
// Windows, Linux and macOS DBs at once. Reading validates the layout version
// and the platform section (anything else is reported as Unusable so the caller
// regenerates from scratch), and writing one platform keeps the others intact.

#include "SignatureJson.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

static int failures = 0;

static void expect(bool ok, const std::string &tag) {
    if (!ok) {
        std::fprintf(stderr, "FAIL %s\n", tag.c_str());
        ++failures;
    }
}

static std::string read_text(const fs::path &path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

static void write_text(const fs::path &path, const std::string &text) {
    std::ofstream out(path, std::ios::binary);
    out << text;
}

static nlohmann::json entry(uintptr_t offset, const char *pattern = "48 8B 05 ?? ?? ?? ??", int pattern_offset = 0) {
    return {{"offset", offset}, {"pattern", pattern}, {"pattern_offset", pattern_offset}};
}

static nlohmann::json section(uintptr_t version, nlohmann::json funcs) {
    return {{"version", version}, {"funcs", std::move(funcs)}};
}

static nlohmann::json document(int format_version, nlohmann::json platforms) {
    return {{"format_version", format_version}, {"platforms", std::move(platforms)}};
}

static SignatureJson reader(const fs::path &path) {
    SignatureJson json{/*isClient=*/true};
    json.file_path = path.string();
    return json;
}

struct PlatformWant {
    uintptr_t version;
    uintptr_t offset;
};

static PlatformWant want_for(const std::string &platform) {
    if (platform == "windows-x64")
        return {759671, 0x1234};
    if (platform == "windows-arm64")
        return {2, 0x77};
    if (platform == "linux-x64")
        return {756039, 0x4321};
    if (platform == "macos-x64")
        return {1, 0x99};
    return {3, 0x55}; // linux-arm64
}

static std::string foreign_platform(const std::string &own) {
    return own.starts_with("windows") ? "linux-x64" : "windows-x64";
}

// The runtime reads only its own platform section out of a multi-platform file.
static void test_reads_own_platform_section(const fs::path &dir) {
    const auto path = dir / "read_ok.json";
    write_text(path, document(SignatureJson::format_version,
                              {{"windows-x64", section(759671, {{"lua_gettop", entry(0x1234)}})},
                               {"windows-arm64", section(2, {{"lua_gettop", entry(0x77)}})},
                               {"linux-x64", section(756039, {{"lua_gettop", entry(0x4321)}})},
                               {"linux-arm64", section(3, {{"lua_gettop", entry(0x55)}})},
                               {"macos-x64", section(1, {{"lua_gettop", entry(0x99)}})}})
                          .dump());
    auto json = reader(path);
    const auto signatures = json.read_from_signatures();
    expect(signatures.has_value(), "multi-platform document is readable");
    expect(json.last_read_status == SignatureJson::ReadStatus::Ok, "multi-platform read status Ok");
    if (!signatures)
        return;
    const auto want = want_for(SignatureJson::platform_name());
    expect(signatures->version == want.version, "read the version of the own platform");
    expect(signatures->funcs.size() == 1, "read only the own platform entries");
    const auto got = signatures->funcs.find("lua_gettop");
    expect(got != signatures->funcs.end() && got->second.offset == want.offset,
           "read the offsets of the own platform");
    expect(got != signatures->funcs.end() && got->second.pattern_offset == 0, "pattern_offset round-trips");
}

// Any other layout version — including a document without the field — is
// refused as a whole; that is what triggers "regenerate from scratch".
static void test_rejects_other_format_versions(const fs::path &dir) {
    const auto own = std::string{SignatureJson::platform_name()};
    for (const int version: {SignatureJson::format_version - 1, 0, 999}) {
        const auto path = dir / ("read_format_" + std::to_string(version) + ".json");
        write_text(path, document(version, {{own, section(1, {{"lua_gettop", entry(0x10)}})}}).dump());
        auto json = reader(path);
        expect(!json.read_from_signatures(), "format_version " + std::to_string(version) + " is rejected");
        expect(json.last_read_status == SignatureJson::ReadStatus::Unusable,
               "format_version " + std::to_string(version) + " read status Unusable");
    }

    const auto legacy = dir / "read_legacy.json";
    write_text(legacy, nlohmann::json{{"version", 759671}, {"funcs", {{"lua_gettop", entry(0x10)}}}}.dump());
    auto json = reader(legacy);
    expect(!json.read_from_signatures(), "legacy document without format_version is rejected");
    expect(json.last_read_status == SignatureJson::ReadStatus::Unusable, "legacy document read status Unusable");
}

// A file written on another platform (no section for this one) is unusable
// here, but must not be mistaken for "no DB" — the tool rebuilds just this
// platform and keeps the foreign section. Bare system keys and unknown pairs
// are not sections at all.
static void test_rejects_missing_own_section(const fs::path &dir) {
    const auto path = dir / "read_foreign_only.json";
    write_text(path, document(SignatureJson::format_version,
                              {{"windows", section(1, {{"lua_gettop", entry(0x10)}})},
                               {"linux", section(2, {{"lua_gettop", entry(0x20)}})},
                               {"macos", section(3, {{"lua_gettop", entry(0x30)}})},
                               {"plan9-x64", section(4, {{"lua_gettop", entry(0x40)}})}})
                          .dump());
    auto json = reader(path);
    expect(!json.read_from_signatures(), "document without the own platform section is rejected");
    expect(json.last_read_status == SignatureJson::ReadStatus::Unusable,
           "missing platform section read status Unusable");
}

static void test_rejects_malformed_sections(const fs::path &dir) {
    const auto own = std::string{SignatureJson::platform_name()};
    const std::pair<const char *, nlohmann::json> cases[] = {
            {"not an object", nlohmann::json::array()},
            {"no version", nlohmann::json{{"funcs", {{"lua_gettop", entry(0x10)}}}}},
            {"version is a string", nlohmann::json{{"version", "759671"}, {"funcs", {{"lua_gettop", entry(0x10)}}}}},
            {"no funcs", nlohmann::json{{"version", 1}}},
            {"empty funcs", nlohmann::json{{"version", 1}, {"funcs", nlohmann::json::object()}}},
            {"entry without pattern",
             nlohmann::json{{"version", 1}, {"funcs", {{"lua_gettop", {{"offset", 0x10}}}}}}},
            {"entry with zero offset",
             nlohmann::json{{"version", 1}, {"funcs", {{"lua_gettop", entry(0)}}}}},
    };
    for (const auto &[tag, bad]: cases) {
        const auto path = dir / "read_malformed.json";
        write_text(path, document(SignatureJson::format_version, {{own, bad}}).dump());
        auto json = reader(path);
        expect(!json.read_from_signatures(), std::string{"malformed section is rejected: "} + tag);
        expect(json.last_read_status == SignatureJson::ReadStatus::Unusable,
               std::string{"malformed section read status Unusable: "} + tag);
    }
}

static void test_reports_missing_and_corrupt_files(const fs::path &dir) {
    auto absent = reader(dir / "does_not_exist.json");
    expect(!absent.read_from_signatures(), "absent file is not readable");
    expect(absent.last_read_status == SignatureJson::ReadStatus::Missing, "absent file read status Missing");

    const auto corrupt = dir / "read_corrupt.json";
    write_text(corrupt, "{ this is not json");
    auto json = reader(corrupt);
    expect(!json.read_from_signatures(), "corrupt document is rejected");
    expect(json.last_read_status == SignatureJson::ReadStatus::Unusable, "corrupt document read status Unusable");
}

// Writing replaces only the own platform section; everything else in the file
// (other platforms, even from another format_version) survives.
static void test_write_preserves_other_platforms(const fs::path &dir) {
    const auto path = dir / "write_merge.json";
    const auto own = std::string{SignatureJson::platform_name()};
    const auto foreign = foreign_platform(own);
    const auto foreign_section = section(756039, {{"lua_open", entry(0x4321)}});
    write_text(path, document(SignatureJson::format_version - 1,
                              {{foreign, foreign_section},
                               {own, section(1, {{"lua_gettop", entry(0x5)}})}})
                          .dump());

    constexpr uintptr_t written_version = 424242;
    Signatures signatures{};
    signatures.version = written_version;
    signatures.funcs["lua_gettop"] = {0x1111, "48 8B 05 ?? ?? ?? ??", 0};
    auto json = reader(path);
    json.update_signatures(signatures);

    const auto doc = nlohmann::json::parse(read_text(path));
    expect(doc["format_version"] == SignatureJson::format_version, "write stamps format_version");
    expect(doc.contains("platforms") && doc["platforms"].is_object(), "write keeps a platforms object");
    expect(doc["platforms"].contains(foreign) && doc["platforms"][foreign] == foreign_section,
           "write keeps the foreign platform section untouched");
    const auto own_json = doc["platforms"].contains(own) ? doc["platforms"][own] : nlohmann::json{};
    expect(own_json.value("version", 0) == written_version, "write stores the own platform version");
    expect(own_json["funcs"]["lua_gettop"]["offset"] == 0x1111, "write stores the own platform entry");

    auto reread = reader(path);
    const auto read = reread.read_from_signatures();
    expect(read.has_value(), "written document reads back");
    if (!read)
        return;
    expect(read->version == written_version, "round-trip version");
    const auto got = read->funcs.find("lua_gettop");
    expect(got != read->funcs.end() && got->second.offset == 0x1111, "round-trip offset");
    expect(got != read->funcs.end() && got->second.pattern == "48 8B 05 ?? ?? ?? ??", "round-trip pattern");
}

// A second write of the same platform must not duplicate or drop its entries.
static void test_write_is_idempotent(const fs::path &dir) {
    const auto path = dir / "write_twice.json";
    Signatures signatures{};
    signatures.version = 424242;
    signatures.funcs["lua_gettop"] = {0x1111, "48 8B 05 ?? ?? ?? ??", 0};
    signatures.funcs["lua_settop"] = {0x2222, "48 8B 05 ?? ?? ?? ?", 1};
    auto json = reader(path);
    json.update_signatures(signatures);
    json.update_signatures(signatures);

    auto reread = reader(path);
    const auto read = reread.read_from_signatures();
    expect(read.has_value(), "twice-written document reads back");
    if (!read)
        return;
    expect(read->funcs.size() == 2, "twice-written document keeps both entries");
    const auto got = read->funcs.find("lua_settop");
    expect(got != read->funcs.end() && got->second.offset == 0x2222 && got->second.pattern_offset == 1,
           "twice-written entry keeps offset and pattern_offset");
}

int main() {
    const auto dir = fs::temp_directory_path() /
                     ("ds_signature_json_format_" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::remove_all(dir);
    fs::create_directories(dir);

    // update_signatures() asserts the DB version matches the game version, so
    // point the (cached) version lookup at a temp file with the value used below.
    const auto version_file = dir / "version.txt";
    write_text(version_file, "424242");
    const auto version_path = version_file.string();
    SignatureJson::version_path = version_path.c_str();

    test_reads_own_platform_section(dir);
    const auto own = std::string{SignatureJson::platform_name()};
    expect(own.find('-') != std::string::npos && own.find('-') > 0 && own.find('-') + 1 < own.size(),
           "platform_name() is '<system>-<arch>'");
    test_rejects_other_format_versions(dir);
    test_rejects_missing_own_section(dir);
    test_rejects_malformed_sections(dir);
    test_reports_missing_and_corrupt_files(dir);
    test_write_preserves_other_platforms(dir);
    test_write_is_idempotent(dir);

    fs::remove_all(dir);
    if (failures != 0) {
        std::fprintf(stderr, "%d signature_json_format check(s) failed\n", failures);
        return 1;
    }
    std::printf("ALL PASS signature_json_format\n");
    return 0;
}
