// Format gate for signatures_*.json (SignatureJson): the document carries a
// format_version plus one section per platform, so a single file can hold the
// Windows, Linux and macOS DBs at once. Reading validates the layout version
// and the platform section (anything else is reported as Unusable so the caller
// regenerates from scratch), and writing one platform keeps the others intact.

#include "SignatureJson.hpp"

#include <filesystem>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>
#include <doctest/doctest.h>

namespace fs = std::filesystem;

static std::string read_text(const fs::path &path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

static void write_text(const fs::path &path, const std::string &text) {
    std::ofstream out(path, std::ios::binary);
    out << text;
}

// Owns the scratch dir and the process-global SignatureJson::version_path.
// update_signatures() asserts the DB version matches the game version, so the
// (cached) version lookup points at a temp file with the value used below. The
// c_str() the global points at outlives every use, and both the pointer's
// pre-existing value and the scratch dir are restored even when a CHECK fails.
struct SignatureJsonEnv {
    fs::path dir;
    std::string version_path;
    const char *previous = nullptr;

    explicit SignatureJsonEnv(const char *tag) {
        dir = fs::temp_directory_path() / (std::string("ds_signature_json_format_") + tag);
        std::error_code ec;
        fs::remove_all(dir, ec);
        fs::create_directories(dir, ec);
        const auto version_file = dir / "version.txt";
        write_text(version_file, "424242");
        version_path = version_file.string();
        previous = SignatureJson::version_path;
        SignatureJson::version_path = version_path.c_str();
    }

    ~SignatureJsonEnv() {
        SignatureJson::version_path = previous;
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

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
    CHECK_MESSAGE(signatures.has_value(), "multi-platform document is readable");
    { INFO("multi-platform read status Ok"); CHECK_EQ(json.last_read_status, SignatureJson::ReadStatus::Ok); }
    if (!signatures)
        return;
    const auto want = want_for(SignatureJson::platform_name());
    CHECK_MESSAGE(signatures->version == want.version, "read the version of the own platform");
    CHECK_MESSAGE(signatures->funcs.size() == 1, "read only the own platform entries");
    const auto got = signatures->funcs.find("lua_gettop");
    const bool got_offset = got != signatures->funcs.end() && got->second.offset == want.offset;
    CHECK_MESSAGE(got_offset, "read the offsets of the own platform");
    const bool got_pattern_offset = got != signatures->funcs.end() && got->second.pattern_offset == 0;
    CHECK_MESSAGE(got_pattern_offset, "pattern_offset round-trips");
}

// Any other layout version — including a document without the field — is
// refused as a whole; that is what triggers "regenerate from scratch".
static void test_rejects_other_format_versions(const fs::path &dir) {
    const auto own = std::string{SignatureJson::platform_name()};
    for (const int version: {SignatureJson::format_version - 1, 0, 999}) {
        const auto path = dir / ("read_format_" + std::to_string(version) + ".json");
        write_text(path, document(version, {{own, section(1, {{"lua_gettop", entry(0x10)}})}}).dump());
        auto json = reader(path);
        CHECK_MESSAGE(!json.read_from_signatures(), ("format_version " + std::to_string(version) + " is rejected"));
        { INFO(("format_version " + std::to_string(version) + " read status Unusable"));
            CHECK_EQ(json.last_read_status, SignatureJson::ReadStatus::Unusable); }
    }

    const auto legacy = dir / "read_legacy.json";
    write_text(legacy, nlohmann::json{{"version", 759671}, {"funcs", {{"lua_gettop", entry(0x10)}}}}.dump());
    auto json = reader(legacy);
    CHECK_MESSAGE(!json.read_from_signatures(), "legacy document without format_version is rejected");
    { INFO("legacy document read status Unusable"); CHECK_EQ(json.last_read_status, SignatureJson::ReadStatus::Unusable); }
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
    CHECK_MESSAGE(!json.read_from_signatures(), "document without the own platform section is rejected");
    { INFO("missing platform section read status Unusable");
        CHECK_EQ(json.last_read_status, SignatureJson::ReadStatus::Unusable); }
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
        CHECK_MESSAGE(!json.read_from_signatures(), (std::string{"malformed section is rejected: "} + tag));
        { INFO((std::string{"malformed section read status Unusable: "} + tag));
            CHECK_EQ(json.last_read_status, SignatureJson::ReadStatus::Unusable); }
    }
}

static void test_reports_missing_and_corrupt_files(const fs::path &dir) {
    auto absent = reader(dir / "does_not_exist.json");
    CHECK_MESSAGE(!absent.read_from_signatures(), "absent file is not readable");
    { INFO("absent file read status Missing"); CHECK_EQ(absent.last_read_status, SignatureJson::ReadStatus::Missing); }

    const auto corrupt = dir / "read_corrupt.json";
    write_text(corrupt, "{ this is not json");
    auto json = reader(corrupt);
    CHECK_MESSAGE(!json.read_from_signatures(), "corrupt document is rejected");
    { INFO("corrupt document read status Unusable"); CHECK_EQ(json.last_read_status, SignatureJson::ReadStatus::Unusable); }
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
    { INFO("write stamps format_version"); CHECK_EQ(doc["format_version"], SignatureJson::format_version); }
    const bool platforms_object = doc.contains("platforms") && doc["platforms"].is_object();
    CHECK_MESSAGE(platforms_object, "write keeps a platforms object");
    const bool foreign_kept = doc["platforms"].contains(foreign) &&
                              doc["platforms"][foreign] == foreign_section;
    CHECK_MESSAGE(foreign_kept, "write keeps the foreign platform section untouched");
    const auto own_json = doc["platforms"].contains(own) ? doc["platforms"][own] : nlohmann::json{};
    { INFO("write stores the own platform version"); CHECK_EQ(own_json.value("version", 0), written_version); }
    { INFO("write stores the own platform entry"); CHECK_EQ(own_json["funcs"]["lua_gettop"]["offset"], 0x1111); }

    auto reread = reader(path);
    const auto read = reread.read_from_signatures();
    CHECK_MESSAGE(read.has_value(), "written document reads back");
    if (!read)
        return;
    CHECK_MESSAGE(read->version == written_version, "round-trip version");
    const auto got = read->funcs.find("lua_gettop");
    const bool got_offset = got != read->funcs.end() && got->second.offset == 0x1111;
    CHECK_MESSAGE(got_offset, "round-trip offset");
    const bool got_pattern = got != read->funcs.end() && got->second.pattern == "48 8B 05 ?? ?? ?? ??";
    CHECK_MESSAGE(got_pattern, "round-trip pattern");
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
    CHECK_MESSAGE(read.has_value(), "twice-written document reads back");
    if (!read)
        return;
    CHECK_MESSAGE(read->funcs.size() == 2, "twice-written document keeps both entries");
    const auto got = read->funcs.find("lua_settop");
    const bool got_entry = got != read->funcs.end() && got->second.offset == 0x2222 &&
                           got->second.pattern_offset == 1;
    CHECK_MESSAGE(got_entry, "twice-written entry keeps offset and pattern_offset");
}

TEST_CASE("test_signature_json_format/platform_name_shape") {
    const auto own = std::string{SignatureJson::platform_name()};
    const bool shaped =
        own.find('-') != std::string::npos && own.find('-') > 0 && own.find('-') + 1 < own.size();
    CHECK_MESSAGE(shaped, "platform_name() is '<system>-<arch>'");
}

TEST_CASE("test_signature_json_format/reads_own_platform_section") {
    SignatureJsonEnv env{"read_ok"};
    test_reads_own_platform_section(env.dir);
}

TEST_CASE("test_signature_json_format/rejects_other_format_versions") {
    SignatureJsonEnv env{"read_format"};
    test_rejects_other_format_versions(env.dir);
}

TEST_CASE("test_signature_json_format/rejects_missing_own_section") {
    SignatureJsonEnv env{"read_foreign"};
    test_rejects_missing_own_section(env.dir);
}

TEST_CASE("test_signature_json_format/rejects_malformed_sections") {
    SignatureJsonEnv env{"read_malformed"};
    test_rejects_malformed_sections(env.dir);
}

TEST_CASE("test_signature_json_format/reports_missing_and_corrupt_files") {
    SignatureJsonEnv env{"missing_corrupt"};
    test_reports_missing_and_corrupt_files(env.dir);
}

TEST_CASE("test_signature_json_format/write_preserves_other_platforms") {
    SignatureJsonEnv env{"write_merge"};
    test_write_preserves_other_platforms(env.dir);
}

TEST_CASE("test_signature_json_format/write_is_idempotent") {
    SignatureJsonEnv env{"write_twice"};
    test_write_is_idempotent(env.dir);
}
