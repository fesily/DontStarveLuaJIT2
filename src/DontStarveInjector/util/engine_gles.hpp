#pragma once

// Live ANGLE/GLES entry point resolution against the engine's own IAT slots.
//
// The client engine imports ANGLE through its own IAT (module names
// "libGLESv2.dll" / "libEGL.dll", almost entirely by ordinal).
// plugin_render_angle rebinds those slots to the sideloaded ds_* ANGLE build
// for any explicit AngleBackend; with AngleBackend=auto the slots keep
// pointing at the game-resident ANGLE. Reading the slot values is therefore
// the resolution that always matches the renderer actually in use:
// GetModuleHandleA("libGLESv2.dll") always returns the game-resident module
// (its name is claimed at process start), whose GL context is never current
// once the IAT has been rebound — every call through it is a silent no-op
// (ANGLE entry points early-return without a context).
//
// Header-only: plugin_render_vbpool and plugin_render_shadow both resolve GL
// this way; it depends only on the Injector's module_enumerate_* exports.

#ifdef _WIN32

#include "config/InjectorHostConfig.hpp"
#include "util/module.hpp"

#include <Windows.h>
#include <cstring>
#include <string>
#include <unordered_map>

namespace engine_gles {

// Modules the live GL entry points may live in, in owner-probe order.
inline constexpr const char *kProbeModules[] = {"ds_GLESv2.dll", "libGLESv2.dll",
                                                "ds_libEGL.dll", "libEGL.dll"};

inline bool IsGlesImportModule(const char *module) {
    return _stricmp(module, "libGLESv2.dll") == 0 || _stricmp(module, "libEGL.dll") == 0;
}

// Ordinal → export name for the game-resident ANGLE module. The engine links
// against that module by ordinal, so its export table is the name source (the
// same map plugin_render_angle's rebind builds).
inline const std::unordered_map<uint16_t, std::string> &GameResidentOrdinalNames() {
    static const std::unordered_map<uint16_t, std::string> names = [] {
        std::unordered_map<uint16_t, std::string> out;
        if (HMODULE gles = GetModuleHandleA("libGLESv2.dll")) {
            module_enumerate_exports(
                gles,
                +[](const ExportDetails *details, void *user_data) -> bool {
                    auto *map = static_cast<std::unordered_map<uint16_t, std::string> *>(user_data);
                    if (details->name != nullptr && details->ordinal != 0) {
                        map->emplace(details->ordinal, details->name);
                    }
                    return true;
                },
                &out);
        }
        return out;
    }();
    return names;
}

// Name of an import entry (resolving ordinal-only entries through the
// game-resident module export table). nullptr when it is not a GLES/EGL import
// we can name.
inline const char *ImportEntryName(const ImportDetails *details) {
    if (details->module == nullptr || !IsGlesImportModule(details->module)) {
        return nullptr;
    }
    if (details->name != nullptr) {
        return details->name;
    }
    if (_stricmp(details->module, "libGLESv2.dll") != 0) {
        return nullptr; // the ordinal map is only valid for libGLESv2 exports
    }
    const auto &ordinals = GameResidentOrdinalNames();
    const auto it = ordinals.find(details->ordinal);
    return it == ordinals.end() ? nullptr : it->second.c_str();
}

struct EntryHit {
    const char *wanted = nullptr;
    void *live = nullptr;
};

inline bool VisitEntry(const ImportDetails *details, void *user_data) {
    auto *hit = static_cast<EntryHit *>(user_data);
    const char *name = ImportEntryName(details);
    if (name == nullptr || std::strcmp(name, hit->wanted) != 0) {
        return true;
    }
    hit->live = details->address; // current IAT slot value = the live entry point
    return false;                 // stop enumeration
}

// Live entry point the engine will call for `name` (its IAT slot value), or
// nullptr when the engine does not import it.
inline void *ResolveEntry(const char *name) {
    EntryHit hit;
    hit.wanted = name;
    if (HMODULE main_module = GetModuleHandleW(nullptr)) {
        module_enumerate_imports(main_module, &VisitEntry, &hit);
    }
    return hit.live;
}

// Leaf name of the module owning `entry` for `name`, or "unknown".
inline const char *EntryOwner(const char *name, const void *entry) {
    if (name == nullptr || entry == nullptr) {
        return "unknown";
    }
    for (const char *candidate : kProbeModules) {
        if (HMODULE module = GetModuleHandleA(candidate)) {
            if (GetProcAddress(module, name) == entry) {
                return candidate;
            }
        }
    }
    return "unknown";
}

struct LiveModuleInfo {
    HMODULE module = nullptr;
    const char *owner = "unknown"; // candidate module name, or "unknown"
};

struct OwnerProbe {
    LiveModuleInfo info;
};

inline bool VisitOwner(const ImportDetails *details, void *user_data) {
    auto *probe = static_cast<OwnerProbe *>(user_data);
    const char *name = ImportEntryName(details);
    if (name == nullptr || details->address == nullptr) {
        return true;
    }
    const char *owner = EntryOwner(name, details->address);
    if (std::strcmp(owner, "unknown") == 0) {
        return true; // keep looking for an entry whose owner can be named
    }
    probe->info.module = GetModuleHandleA(owner);
    probe->info.owner = owner;
    return false; // stop enumeration
}

// Module owning the engine's live GL entry points, or {nullptr, "unknown"}.
// Cached: the IAT is finalized before any render plugin loads (render.angle
// rebinds at EarlyNative, and this is only used while rendering).
inline LiveModuleInfo LiveModule() {
    static const LiveModuleInfo info = [] {
        OwnerProbe probe;
        if (HMODULE main_module = GetModuleHandleW(nullptr)) {
            module_enumerate_imports(main_module, &VisitOwner, &probe);
        }
        return probe.info;
    }();
    return info;
}

} // namespace engine_gles

#endif // _WIN32
