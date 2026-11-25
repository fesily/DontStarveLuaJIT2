#include "SignatureCache.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string_view>

#include <nlohmann/json.hpp>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace ds::sig {
namespace {

constexpr int kCacheFormatVersion = 1;

void copy_text(char *dst, size_t cap, std::string_view src) {
    if (cap == 0) {
        return;
    }
    const size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
    if (n != 0) {
        std::memcpy(dst, src.data(), n);
    }
    dst[n] = '\0';
}

void set_detail(char *detail, size_t cap, std::string_view text) {
    if (detail && cap) {
        copy_text(detail, cap, text);
    }
}

// Exclusive writer lock: a side file next to the cache, opened without sharing
// (Windows) / O_EXCL (POSIX). Advisory on purpose — a filesystem without working
// locking degrades to "no exclusion", never to a hard failure that blocks a run.
class FileLock {
public:
    explicit FileLock(const std::string &target) {
        path_ = target + ".lock";
#if defined(_WIN32)
        for (int attempt = 0; attempt < 200; ++attempt) {
            handle_ = ::CreateFileA(path_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle_ != INVALID_HANDLE_VALUE) {
                return;
            }
            ::Sleep(5);
        }
        handle_ = nullptr;
#else
        for (int attempt = 0; attempt < 200; ++attempt) {
            fd_ = ::open(path_.c_str(), O_CREAT | O_EXCL | O_RDWR, 0666);
            if (fd_ >= 0) {
                return;
            }
            ::usleep(5000);
        }
        fd_ = -1;
#endif
    }

    ~FileLock() {
#if defined(_WIN32)
        if (handle_) {
            ::CloseHandle(handle_);
            handle_ = nullptr;
            ::DeleteFileA(path_.c_str());
        }
#else
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
            ::unlink(path_.c_str());
        }
#endif
    }

    FileLock(const FileLock &) = delete;
    FileLock &operator=(const FileLock &) = delete;

    bool held() const {
#if defined(_WIN32)
        return handle_ != nullptr;
#else
        return fd_ >= 0;
#endif
    }

private:
    std::string path_;
#if defined(_WIN32)
    void *handle_ = nullptr;
#else
    int fd_ = -1;
#endif
};

nlohmann::json entry_to_json(const CacheRecord &record) {
    nlohmann::json hits = nlohmann::json::array();
    for (uint32_t i = 0; i < record.raw_hit_count && i < kMaxHits; ++i) {
        hits.push_back(record.raw_hit_rvas[i]);
    }
    nlohmann::json out{
            {"pattern", record.pattern},
            {"pattern_offset", record.pattern_offset},
            {"hits_policy", record.hits_policy},
            {"resolve_kind", record.resolve_kind},
            {"definition_revision", record.definition_revision},
            {"platform_mask", record.platform_mask},
            {"client_only", record.client_only != 0},
            {"raw_hit_rvas", std::move(hits)},
            {"target_rva", record.target_rva},
    };
    return out;
}

bool entry_from_json(const nlohmann::json &in, CacheRecord &record, std::string &why) {
    if (!in.is_object()) {
        why = "entry is not an object";
        return false;
    }
    const auto pattern = in.find("pattern");
    const auto pattern_offset = in.find("pattern_offset");
    const auto hits_policy = in.find("hits_policy");
    const auto resolve_kind = in.find("resolve_kind");
    const auto revision = in.find("definition_revision");
    const auto mask = in.find("platform_mask");
    const auto hits = in.find("raw_hit_rvas");
    const auto target = in.find("target_rva");
    if (pattern == in.end() || !pattern->is_string() || pattern->get<std::string>().empty()) {
        why = "entry has no string pattern";
        return false;
    }
    if (pattern_offset == in.end() || !pattern_offset->is_number_integer() || hits_policy == in.end() ||
        !hits_policy->is_number_integer() || resolve_kind == in.end() || !resolve_kind->is_number_integer() ||
        revision == in.end() || !revision->is_number_integer() || mask == in.end() ||
        !mask->is_number_integer()) {
        why = "entry is missing an integer rule field";
        return false;
    }
    if (hits == in.end() || !hits->is_array() || target == in.end() || !target->is_number_unsigned()) {
        why = "entry has no raw_hit_rvas array / target_rva";
        return false;
    }
    if (!in.contains("client_only") || !in["client_only"].is_boolean()) {
        why = "entry has no boolean client_only";
        return false;
    }
    const auto pattern_text = pattern->get<std::string>();
    if (pattern_text.size() >= kMaxPatternLen) {
        why = "pattern longer than the contract allows";
        return false;
    }
    record.pattern_offset = pattern_offset->get<int32_t>();
    record.hits_policy = hits_policy->get<int32_t>();
    record.resolve_kind = resolve_kind->get<int32_t>();
    record.definition_revision = revision->get<int32_t>();
    record.platform_mask = mask->get<uint32_t>();
    record.client_only = in["client_only"].get<bool>() ? 1 : 0;
    copy_text(record.pattern, sizeof(record.pattern), pattern_text);
    record.raw_hit_count = 0;
    for (const auto &hit : *hits) {
        if (!hit.is_number_unsigned() || record.raw_hit_count >= kMaxHits) {
            why = "raw_hit_rvas holds a non-integer or too many hits";
            return false;
        }
        record.raw_hit_rvas[record.raw_hit_count++] = hit.get<uint64_t>();
    }
    if (record.raw_hit_count == 0) {
        why = "raw_hit_rvas is empty";
        return false;
    }
    record.target_rva = target->get<uint64_t>();
    if (record.target_rva == 0) {
        why = "target_rva is zero";
        return false;
    }
    record.status = CacheStatus::Ok;
    return true;
}

// Shared read path for cache_read_entry(): parses the document, validates the
// format version and this platform's section and hands back the entry object.
bool load_entry_json(const char *file_path, uint32_t platform, const char *owner, const char *name,
                     nlohmann::json &doc, const nlohmann::json *&entry, const nlohmann::json *&module_meta,
                     CacheStatus &status, char *detail, size_t detail_cap) {
    entry = nullptr;
    module_meta = nullptr;
    status = CacheStatus::MissingFile;
    if (!file_path || !*file_path || !owner || !name) {
        set_detail(detail, detail_cap, "no cache path");
        return false;
    }
    std::ifstream in(file_path);
    if (!in.is_open()) {
        set_detail(detail, detail_cap, "cache file missing");
        return false;
    }
    try {
        in >> doc;
    } catch (const std::exception &error) {
        status = CacheStatus::InvalidFile;
        set_detail(detail, detail_cap, std::string{"cache is not valid JSON: "} + error.what());
        return false;
    }
    const auto format = doc.is_object() ? doc.find("format_version") : doc.end();
    if (format == doc.end() || !format->is_number_integer() || format->get<int>() != kCacheFormatVersion) {
        status = CacheStatus::InvalidFile;
        set_detail(detail, detail_cap, "cache format_version is not the one this build writes");
        return false;
    }
    const auto platforms = doc.find("platforms");
    if (platforms == doc.end() || !platforms->is_object()) {
        status = CacheStatus::InvalidFile;
        set_detail(detail, detail_cap, "cache has no platforms object");
        return false;
    }
    const auto section = platforms->find(std::string{platform_name(platform)});
    if (section == platforms->end()) {
        status = CacheStatus::MissingEntry;
        set_detail(detail, detail_cap, "cache has no section for this platform");
        return false;
    }
    const auto module = section->find("module");
    if (module == section->end() || !module->is_object()) {
        status = CacheStatus::InvalidFile;
        set_detail(detail, detail_cap, "platform section has no module identity");
        return false;
    }
    module_meta = &*module;
    const auto owners = section->find("owners");
    if (owners == section->end() || !owners->is_object()) {
        status = CacheStatus::InvalidFile;
        set_detail(detail, detail_cap, "platform section has no owners object");
        return false;
    }
    const auto owner_it = owners->find(owner);
    if (owner_it == owners->end() || !owner_it->is_object()) {
        status = CacheStatus::MissingEntry;
        set_detail(detail, detail_cap, "cache has no section for this owner");
        return false;
    }
    const auto entries = owner_it->find("entries");
    if (entries == owner_it->end() || !entries->is_object()) {
        status = CacheStatus::InvalidFile;
        set_detail(detail, detail_cap, "owner section has no entries object");
        return false;
    }
    const auto found = entries->find(name);
    if (found == entries->end()) {
        status = CacheStatus::MissingEntry;
        set_detail(detail, detail_cap, "cache has no record for this entry");
        return false;
    }
    entry = &*found;
    return true;
}

} // namespace

std::string module_content_digest(const char *path) {
    if (!path || !*path) {
        return {};
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return {};
    }
    uint64_t hash = 0xcbf29ce484222325ull;
    std::array<char, 64 * 1024> buffer{};
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto got = in.gcount();
        for (std::streamsize i = 0; i < got; ++i) {
            hash ^= static_cast<uint64_t>(static_cast<unsigned char>(buffer[static_cast<size_t>(i)]));
            hash *= 0x100000001b3ull;
        }
    }
    char hex[17];
    std::snprintf(hex, sizeof(hex), "%016llx", static_cast<unsigned long long>(hash));
    return std::string{hex};
}

CacheStatus cache_read_entry(const char *file_path, uint32_t platform, const char *owner, const char *name,
                             CacheRecord *out, char *detail, size_t detail_cap) {
    if (out) {
        *out = CacheRecord{};
    }
    if (!out) {
        return CacheStatus::InvalidFile;
    }
    nlohmann::json doc;
    const nlohmann::json *entry = nullptr;
    const nlohmann::json *module_meta = nullptr;
    CacheStatus status = CacheStatus::MissingFile;
    if (!load_entry_json(file_path, platform, owner, name, doc, entry, module_meta, status, detail,
                         detail_cap)) {
        out->status = status;
        return status;
    }
    std::string why;
    if (!entry_from_json(*entry, *out, why)) {
        out->status = CacheStatus::InvalidFile;
        set_detail(detail, detail_cap, why);
        return CacheStatus::InvalidFile;
    }
    const auto digest = module_meta->find("digest");
    const auto version = module_meta->find("version");
    const auto digest_text = digest != module_meta->end() && digest->is_string() ? digest->get<std::string>() : "";
    const auto version_text = version != module_meta->end() && version->is_string() ? version->get<std::string>() : "";
    if (digest_text.empty()) {
        out->status = CacheStatus::InvalidFile;
        set_detail(detail, detail_cap, "platform section carries no module digest");
        return CacheStatus::InvalidFile;
    }
    copy_text(out->module_digest, sizeof(out->module_digest), digest_text);
    copy_text(out->game_version, sizeof(out->game_version), version_text);
    out->status = CacheStatus::Ok;
    return CacheStatus::Ok;
}

bool cache_write_owner(const char *file_path, uint32_t platform, const char *owner,
                       const CacheFileIdentity &identity, const CacheWriteEntry *entries, size_t count,
                       char *detail, size_t detail_cap) {
    if (!file_path || !*file_path || !owner || !*owner) {
        set_detail(detail, detail_cap, "no cache path / owner");
        return false;
    }
    FileLock lock{file_path};
    // Merge into whatever is on disk: other platform sections and other owners
    // of this platform must survive a run that only touched one provider.
    nlohmann::json doc = nlohmann::json::object();
    {
        std::ifstream in(file_path);
        if (in.is_open()) {
            try {
                in >> doc;
            } catch (const std::exception &) {
                doc = nlohmann::json::object();
            }
        }
    }
    if (!doc.is_object()) {
        doc = nlohmann::json::object();
    }
    if (const auto format = doc.find("format_version");
        format == doc.end() || !format->is_number_integer() || format->get<int>() != kCacheFormatVersion) {
        // A document this build cannot read contributes nothing; its sections
        // cannot be trusted under the current contract.
        doc = nlohmann::json::object();
    }
    doc["format_version"] = kCacheFormatVersion;
    if (const auto platforms = doc.find("platforms");
        platforms == doc.end() || !platforms->is_object()) {
        doc["platforms"] = nlohmann::json::object();
    }
    auto &section = doc["platforms"][std::string{platform_name(platform)}];
    if (!section.is_object()) {
        section = nlohmann::json::object();
    }
    section["module"] = {{"digest", identity.module_digest},
                         {"size", identity.module_size},
                         {"version", identity.game_version}};
    if (const auto owners = section.find("owners"); owners == section.end() || !owners->is_object()) {
        section["owners"] = nlohmann::json::object();
    }
    nlohmann::json owner_json = nlohmann::json::object();
    owner_json["entries"] = nlohmann::json::object();
    for (size_t i = 0; i < count; ++i) {
        if (!entries[i].name || !entries[i].record) {
            continue;
        }
        owner_json["entries"][entries[i].name] = entry_to_json(*entries[i].record);
    }
    section["owners"][owner] = std::move(owner_json);

    // Write through a temporary so a crash never leaves a truncated document
    // that the next run has to rebuild from scratch.
    const std::string temp = std::string{file_path} + ".tmp";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            set_detail(detail, detail_cap, "cannot open the cache temp file for writing");
            return false;
        }
        out << doc.dump(2);
        out.flush();
        if (!out) {
            set_detail(detail, detail_cap, "cannot write the cache temp file");
            return false;
        }
    }
    std::error_code ec;
    std::filesystem::rename(temp, file_path, ec);
    if (ec) {
        std::filesystem::remove(temp, ec);
        set_detail(detail, detail_cap, "cannot replace the cache file");
        return false;
    }
    (void) lock.held();
    return true;
}

} // namespace ds::sig
