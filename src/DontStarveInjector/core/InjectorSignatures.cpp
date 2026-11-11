#include "InjectorSignatures.hpp"

#include "ProviderDesc.hpp"

#include <frida-gum.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

#if defined(DS_SIG_HAVE_INJECTOR)
namespace ds::sig {
namespace {

// "DEV=databundles/scripts.zip" as a gum wildcard pattern. The engine compares
// that literal against the bundled-script name; renaming the literal in-place is
// how DisableGameScriptsZip makes the zip fall through to the unpacked scripts.
constexpr std::string_view kScriptsZipKey = "DEV=databundles/scripts.zip";

std::string string_to_hex_pattern(std::string_view text) {
    std::string hex;
    hex.reserve(text.size() * 3);
    char byte[4];
    for (const unsigned char ch : text) {
        std::snprintf(byte, sizeof(byte), "%02X ", ch);
        hex += byte;
    }
    if (!hex.empty()) {
        hex.pop_back();
    }
    return hex;
}

// Only the definitions of the target this build compiles for are emitted: a
// Windows build carries no other platform's pattern (and vice versa), so neither
// the image nor the runtime/cache table holds foreign entries.
EntryDef g_entries[] = {
#if defined(DS_SIG_TARGET_WINDOWS_X64)
        {
                .owner = "injector",
                .name = "injector.set_thread_name",
                .description = "Engine thread-name helper (win64) replaced with SetThreadDescription",
                .patterns = {"B9 88 13 6D 40"},
                .pattern_offset = -0x24,
                .platform_mask = kPlatformWindowsX64,
                .prot_flag = GUM_PAGE_EXECUTE,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
#endif
        {
                .owner = "injector",
                .name = "injector.scripts_zip",
                .description = "Bundled script-name literal patched in read-only data by DisableGameScriptsZip",
                .patterns = {nullptr}, // filled by prepare_entries()
                .pattern_offset = 0,
#if defined(DS_SIG_TARGET_WINDOWS_X64)
                .platform_mask = kPlatformWindowsX64,
#else
                .platform_mask = kPlatformLinuxX64,
#endif
                .prot_flag = GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 0, // optional feature: a miss is not an injector problem
                .reserved = 0,
                .verify = nullptr,
        },
};

std::string g_scripts_zip_pattern;

void prepare_entries() {
    if (g_scripts_zip_pattern.empty()) {
        g_scripts_zip_pattern = string_to_hex_pattern(kScriptsZipKey);
    }
    // By name: the table layout differs per target.
    for (auto &entry : g_entries) {
        if (entry.name != nullptr && std::strcmp(entry.name, "injector.scripts_zip") == 0) {
            entry.patterns[0] = g_scripts_zip_pattern.c_str();
        }
    }
}

const ProviderDesc g_desc{
        .owner = "injector",
        .provider_version = "1",
        .entries = g_entries,
        .entry_count = sizeof(g_entries) / sizeof(g_entries[0]),
        .repair = nullptr,
        .prepare = &prepare_entries,
};

} // namespace

const ProviderDesc &injector_provider_desc() {
    return g_desc;
}

} // namespace ds::sig
#endif // DS_SIG_HAVE_INJECTOR
