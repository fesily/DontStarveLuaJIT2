#include "BuildBin.hpp"
#include <spdlog/spdlog.h>
#include "ShadowLog.hpp"

#include <cstdint>


#include <zip.h>

#include <cctype>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

namespace ds::shadow {
namespace {

std::unordered_map<std::string, std::vector<BildVert>> g_bild;

bool LooksName(const char *s, size_t n) noexcept {
    if (s == nullptr || n == 0 || n > 64) {
        return false;
    }
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (!(std::isalnum(c) || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

#ifdef _WIN32
std::string GameAnimDir() {
    char buf[MAX_PATH]{};
    const DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return {};
    }
    std::string p(buf, n);
    const auto slash = p.find_last_of("\\/");
    if (slash == std::string::npos) {
        return {};
    }
    p.resize(slash); // bin64
    const auto slash2 = p.find_last_of("\\/");
    if (slash2 == std::string::npos) {
        return {};
    }
    p.resize(slash2);
    p += "\\data\\anim";
    return p;
}
#endif

bool ReadZipMember(const char *zip_path, const char *member, std::vector<uint8_t> *out) {
    if (zip_path == nullptr || member == nullptr || out == nullptr) {
        return false;
    }
    int err = 0;
    zip_t *z = zip_open(zip_path, ZIP_RDONLY, &err);
    if (z == nullptr) {
        return false;
    }
    zip_stat_t st{};
    if (zip_stat(z, member, 0, &st) != 0 || st.size == 0 || st.size > 8u * 1024u * 1024u) {
        zip_close(z);
        return false;
    }
    zip_file_t *f = zip_fopen(z, member, 0);
    if (f == nullptr) {
        zip_close(z);
        return false;
    }
    out->resize(static_cast<size_t>(st.size));
    const zip_int64_t n = zip_fread(f, out->data(), st.size);
    zip_fclose(f);
    zip_close(z);
    return n == static_cast<zip_int64_t>(st.size);
}

} // namespace

const char *ReadSBuildName(const uint8_t *sbuild) noexcept {
    if (sbuild == nullptr) {
        return nullptr;
    }
    static thread_local char buf[80];
    for (size_t off : {size_t{8}, size_t{16}, size_t{24}, size_t{32}}) {
        const uint8_t *p = sbuild + off;
        uint64_t size = 0;
        uint64_t cap = 0;
        std::memcpy(&size, p + 16, 8);
        std::memcpy(&cap, p + 24, 8);
        if (size == 0 || size > 64 || cap > 0x100000) {
            continue;
        }
        const char *s = nullptr;
        if (cap > 15) {
            std::memcpy(&s, p, 8);
        } else {
            s = reinterpret_cast<const char *>(p);
        }
        if (s == nullptr || !LooksName(s, static_cast<size_t>(size))) {
            continue;
        }
        std::memcpy(buf, s, static_cast<size_t>(size));
        buf[size] = 0;
        return buf;
    }
    return nullptr;
}

bool LoadBildVertsForName(const char *build_name, const BildVert **verts, size_t *count) noexcept {
    if (verts == nullptr || count == nullptr || build_name == nullptr || build_name[0] == 0) {
        return false;
    }
    const auto it = g_bild.find(build_name);
    if (it != g_bild.end()) {
        if (it->second.empty()) {
            return false;
        }
        *verts = it->second.data();
        *count = it->second.size();
        return true;
    }
#ifdef _WIN32
    const std::string root = GameAnimDir();
    const std::string paths[] = {root + "\\" + build_name + ".zip",
                                 root + "\\dynamic\\" + build_name + ".zip"};
    std::vector<uint8_t> bin;
    bool loaded = false;
    for (const auto &zp : paths) {
        if (ReadZipMember(zp.c_str(), "build.bin", &bin)) {
            loaded = true;
            break;
        }
    }
    auto &slot = g_bild[build_name];
    if (!loaded) {
        SHADOW_TRACE("[render.shadow] bild miss name={} root={}", build_name, root);
        return false;
    }
    size_t n = 0;
    if (!ParseBildVerts(bin.data(), bin.size(), nullptr, &n) || n == 0) {
        SHADOW_TRACE("[render.shadow] bild parse fail name={} bytes={}", build_name, bin.size());
        return false;
    }
    slot.resize(n);
    if (!ParseBildVerts(bin.data(), bin.size(), slot.data(), &n)) {
        slot.clear();
        return false;
    }
    SHADOW_TRACE("[render.shadow] bild load name={} verts={}", build_name, n);

    *verts = slot.data();
    *count = slot.size();
    return true;
#else
    (void)build_name;
    return false;
#endif
}

} // namespace ds::shadow
