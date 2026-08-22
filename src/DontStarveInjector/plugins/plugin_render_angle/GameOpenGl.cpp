#include "GameOpenGl.hpp"
#include "AngleConfig.hpp"

#ifdef _WIN32

#include "DstAngleBackend.hpp"
#include "config/InjectorHostConfig.hpp"
#include "config/ResolvedConfig.hpp"
#include "core/PluginPath.hpp"
#include "util/module.hpp"

#include <Windows.h>
#include <spdlog/spdlog.h>

#include <egl/egl.h>
#include <GLES2/gl2.h>
#include <egl/eglext.h>
#include <egl/eglext_angle.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace {

    using PFNEGLGETPLATFORMDISPLAYEXTPROC = EGLDisplay(EGLAPIENTRYP)(EGLenum platform,
                                                                     void *native_display,
                                                                     const EGLint *attrib_list);
    using PFNEGLGETDISPLAYPROC = EGLDisplay(EGLAPIENTRYP)(EGLNativeDisplayType display_id);
    using PFNEGLINITIALIZEPROC = EGLBoolean(EGLAPIENTRYP)(EGLDisplay dpy, EGLint *major, EGLint *minor);
    using PFNEGLGETERRORPROC = EGLint(EGLAPIENTRYP)(void);
    using PFNEGLQUERYSTRINGPROC = const char *(EGLAPIENTRYP)(EGLDisplay dpy, EGLint name);
    using PFNEGLCREATEWINDOWSURFACEPROC = EGLSurface(EGLAPIENTRYP)(EGLDisplay dpy,
                                                                   EGLConfig config,
                                                                   EGLNativeWindowType win,
                                                                   const EGLint *attrib_list);
    using PFNEGLMAKECURRENTPROC = EGLBoolean(EGLAPIENTRYP)(EGLDisplay dpy,
                                                           EGLSurface draw,
                                                           EGLSurface read,
                                                           EGLContext ctx);
    using PFNEGLGETPROCADDRESSPROC = __eglMustCastToProperFunctionPointerType(EGLAPIENTRYP)(const char *procname);
    using PFNGLGETSTRINGPROC = const GLubyte *(GL_APIENTRYP)(GLenum name);

    struct WrappedSymbol {
        const char *name;
        FARPROC proc;
    };

    constexpr const char *kSteamOverlayLayerName = "VK_LAYER_VALVE_steam_overlay";

    HMODULE g_angle_glesv2 = nullptr;
    HMODULE g_angle_egl = nullptr;

    bool g_angle_egl_initialized{false};
    bool g_display_supports_post_sub_buffer{false};
    std::atomic_bool g_render_backend_captured{false};
    std::string g_render_backend_name;

    FARPROC ResolveWrappedEglSymbol(const char *name);
    FARPROC ResolveWrappedSymbol(const char *name, const WrappedSymbol *symbols, std::size_t symbol_count);

    static bool EqualsIgnoreCase(std::string_view left, std::string_view right) {
        if (left.size() != right.size()) {
            return false;
        }
        return std::equal(left.begin(), left.end(), right.begin(), right.end(), [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
        });
    }

    static bool PathLeafEqualsIgnoreCase(const std::filesystem::path &path, std::string_view leaf) {
        return EqualsIgnoreCase(path.filename().string(), leaf);
    }

    static bool ContainsIgnoreCase(std::string_view text, std::string_view needle) {
        if (needle.empty() || text.size() < needle.size()) {
            return false;
        }

        for (std::size_t index = 0; index + needle.size() <= text.size(); ++index) {
            if (EqualsIgnoreCase(text.substr(index, needle.size()), needle)) {
                return true;
            }
        }
        return false;
    }

    static std::string GetEnvironmentValue(const char *name) {
        if (name == nullptr || name[0] == '\0') {
            return {};
        }

        const auto required_length = GetEnvironmentVariableA(name, nullptr, 0);
        if (required_length == 0) {
            return {};
        }

        std::string value;
        value.resize(required_length);
        const auto copied = GetEnvironmentVariableA(name, value.data(), required_length);
        if (copied == 0) {
            return {};
        }

        if (!value.empty() && value.back() == '\0') {
            value.pop_back();
        } else if (copied < value.size()) {
            value.resize(copied);
        }
        return value;
    }

    static bool IsVulkanPlatformRequested() {
        static bool result = []() {
            DstAngleBackend backend = DstAngleBackend::Auto;
            (void) ds::config::ensure_resolved();
            if (auto *rc = ds::config::current()) {
                backend = from_string(ds::render_angle::angle_backend(*rc));
                if (backend == DstAngleBackend::Unknown) {
                    spdlog::warn("unknown AngleBackend '{}', defaulting to auto",
                                 ds::render_angle::angle_backend(*rc));
                    backend = DstAngleBackend::Auto;
                }
            }
            if (backend != DstAngleBackend::Auto) {
                SetEnvironmentVariableA("ANGLE_DEFAULT_PLATFORM", to_string(backend).data());
            }
            return backend == DstAngleBackend::Vulkan;
        }();
        return result;
    }

    static bool ContainsDisabledLayer(std::string_view disabled_layers, std::string_view layer_name) {
        std::size_t token_start = 0;
        while (token_start < disabled_layers.size()) {
            const auto token_end = disabled_layers.find_first_of(",; \t\r\n", token_start);
            const auto token = disabled_layers.substr(token_start, token_end - token_start);
            if (!token.empty() && EqualsIgnoreCase(token, layer_name)) {
                return true;
            }
            if (token_end == std::string_view::npos) {
                break;
            }
            token_start = token_end + 1;
        }
        return false;
    }

    static std::string DetectBackendFromRendererString(std::string_view renderer) {
        if (renderer.empty()) {
            return {};
        }
        if (ContainsIgnoreCase(renderer, "direct3d11on12") || ContainsIgnoreCase(renderer, "d3d11on12")) {
            return "D3D11on12";
        }
        if (ContainsIgnoreCase(renderer, "direct3d11") || ContainsIgnoreCase(renderer, "d3d11")) {
            return "D3D11";
        }
        if (ContainsIgnoreCase(renderer, "direct3d9") || ContainsIgnoreCase(renderer, "d3d9")) {
            return "D3D9";
        }
        if (ContainsIgnoreCase(renderer, "vulkan")) {
            return "Vulkan";
        }
        if (ContainsIgnoreCase(renderer, "opengl es")) {
            return "GLES";
        }
        if (ContainsIgnoreCase(renderer, "opengl")) {
            return "OpenGL";
        }
        if (ContainsIgnoreCase(renderer, "metal")) {
            return "Metal";
        }
        if (ContainsIgnoreCase(renderer, "swiftshader")) {
            return "SwiftShader";
        }
        return {};
    }

    static std::string GetRequestedRenderBackendName() {
        const auto requested_platform = GetEnvironmentValue("ANGLE_DEFAULT_PLATFORM");
        if (requested_platform.empty()) {
            return {};
        }
        if (EqualsIgnoreCase(requested_platform, "vulkan")) {
            return "Vulkan?";
        }
        if (EqualsIgnoreCase(requested_platform, "d3d11")) {
            return "D3D11?";
        }
        if (EqualsIgnoreCase(requested_platform, "d3d9")) {
            return "D3D9?";
        }
        if (EqualsIgnoreCase(requested_platform, "gl")) {
            return "OpenGL?";
        }
        if (EqualsIgnoreCase(requested_platform, "gles")) {
            return "GLES?";
        }
        return requested_platform;
    }

    static FARPROC ResolveDllExport(HMODULE mod, const char *name) {
        if (!mod || !name || name[0] == '\0') {
            return nullptr;
        }
        return GetProcAddress(mod, name);
    }

    static FARPROC ResolveGameGlesSymbol(const char *name) {
        return ResolveDllExport(g_angle_glesv2, name);
    }

    static FARPROC ResolveGameEglSymbol(const char *name) {
        if (auto wrapped = ResolveWrappedEglSymbol(name)) {
            return wrapped;
        }
        if (auto p = ResolveDllExport(g_angle_egl, name)) {
            return p;
        }
        // Some EGL entry points live in GLESv2 in ANGLE layouts.
        return ResolveDllExport(g_angle_glesv2, name);
    }

    static FARPROC RealEglExport(const char *name) {
        if (auto p = ResolveDllExport(g_angle_egl, name)) {
            return p;
        }
        return ResolveDllExport(g_angle_glesv2, name);
    }

    static void CaptureCurrentRenderBackend() {
        if (g_render_backend_captured.load(std::memory_order_acquire)) {
            return;
        }

        auto glGetStringFn = reinterpret_cast<PFNGLGETSTRINGPROC>(ResolveGameGlesSymbol("glGetString"));
        if (!glGetStringFn) {
            return;
        }

        const auto *renderer = reinterpret_cast<const char *>(glGetStringFn(GL_RENDERER));
        if (renderer == nullptr || renderer[0] == '\0') {
            return;
        }

        auto backend_name = DetectBackendFromRendererString(renderer);
        if (backend_name.empty()) {
            backend_name = renderer;
        }

        g_render_backend_name = std::move(backend_name);
        g_render_backend_captured.store(true, std::memory_order_release);
        spdlog::info("detected ANGLE render backend: {} renderer={}", g_render_backend_name, renderer);
    }

    static void EnsureVulkanLayerDisableEnvironment() {
        if (!IsVulkanPlatformRequested()) {
            return;
        }

        auto disabled_layers = GetEnvironmentValue("VK_LOADER_LAYERS_DISABLE");
        if (ContainsDisabledLayer(disabled_layers, kSteamOverlayLayerName)) {
            return;
        }

        if (!disabled_layers.empty()) {
            disabled_layers.append(",");
        }
        disabled_layers.append(kSteamOverlayLayerName);

        if (SetEnvironmentVariableA("VK_LOADER_LAYERS_DISABLE", disabled_layers.c_str()) == 0) {
            spdlog::warn("failed to set VK_LOADER_LAYERS_DISABLE for Vulkan mode");
        }
    }

    static std::filesystem::path ThisPluginDir() {
        HMODULE self = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(&ThisPluginDir),
                                &self) ||
            !self) {
            return {};
        }
        wchar_t path[MAX_PATH]{};
        if (GetModuleFileNameW(self, path, MAX_PATH) == 0) {
            return {};
        }
        return std::filesystem::path(path).parent_path();
    }

    static std::filesystem::path ModDepsDir() {
        // Prefer Injector-owned PluginPath helpers (mod root / deps).
        const auto inj = ds::plugin::injector_module_dir();
        if (!inj.empty()) {
            std::error_code ec;
            // Canonical package: Injector.dll at mod root → mod/deps.
            auto deps = ds::plugin::mod_deps_dir(inj);
            if (!deps.empty() && std::filesystem::is_directory(deps, ec)) {
                return deps;
            }
            // Legacy: Injector under bin64 — derive via plugins/ layout.
            deps = ds::plugin::mod_deps_dir(
                    ds::plugin::mod_root_from_plugins_dir(ds::plugin::plugins_dir_from_module_dir(inj)));
            if (!deps.empty() && std::filesystem::is_directory(deps, ec)) {
                return deps;
            }
        }

        for (const auto &plugins_dir : ds::plugin::default_plugin_search_dirs()) {
            const auto deps = ds::plugin::mod_deps_dir(ds::plugin::mod_root_from_plugins_dir(plugins_dir));
            std::error_code ec;
            if (!deps.empty() && std::filesystem::is_directory(deps, ec)) {
                return deps;
            }
        }

        // Fallback: walk from this plugin DLL toward Mod/deps.
        // Canonical package: .../Mod/plugins/plugin_render_angle/plugin_render_angle.dll
        // Flat plugins:      .../Mod/plugins/plugin_render_angle.dll
        const auto plugin_dir = ThisPluginDir();
        if (plugin_dir.empty()) {
            return {};
        }
        if (PathLeafEqualsIgnoreCase(plugin_dir, "plugin_render_angle") &&
            PathLeafEqualsIgnoreCase(plugin_dir.parent_path(), "plugins")) {
            return plugin_dir.parent_path().parent_path() / "deps";
        }
        if (PathLeafEqualsIgnoreCase(plugin_dir, "plugins")) {
            return plugin_dir.parent_path() / "deps";
        }
        return plugin_dir.parent_path().parent_path().parent_path() / "deps";
    }

    // Sideload basenames: must NOT match game-resident libGLESv2.dll / libEGL.dll.
    // Engine already loads bin64 copies before EarlyNative; same-name deps bind to those
    // modules (egl_err=127). Unique names allow our shared ANGLE to coexist; game IAT
    // still rebinds import module names "libEGL.dll"/"libGLESv2.dll" to our exports.
    static constexpr const wchar_t *kSideloadGlesName = L"ds_GLESv2.dll";
    static constexpr const wchar_t *kSideloadEglName = L"ds_libEGL.dll";

    static std::string ModulePathString(HMODULE mod) {
        if (!mod) {
            return {};
        }
        wchar_t path[MAX_PATH]{};
        if (GetModuleFileNameW(mod, path, MAX_PATH) == 0) {
            return {};
        }
        return std::filesystem::path(path).string();
    }

    static bool TryLoadAnglePair(const std::filesystem::path &dir) {
        if (dir.empty()) {
            return false;
        }

        std::error_code ec;
        const auto gles = dir / kSideloadGlesName;
        const auto egl = dir / kSideloadEglName;
        if (!std::filesystem::is_regular_file(gles, ec) || !std::filesystem::is_regular_file(egl, ec)) {
            return false;
        }

        // Load GLESv2 first so ds_libEGL's import of ds_GLESv2.dll resolves in this dir.
        HMODULE gles_mod = LoadLibraryExW(gles.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        const DWORD gles_err = GetLastError();
        HMODULE egl_mod = gles_mod
                                  ? LoadLibraryExW(egl.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH)
                                  : nullptr;
        const DWORD egl_err = GetLastError();
        if (!gles_mod || !egl_mod) {
            spdlog::error("ANGLE sideload failed gles={} egl={} gles_err={} egl_err={}",
                          gles.string(),
                          egl.string(),
                          gles_mod ? 0u : static_cast<unsigned>(gles_err),
                          egl_mod ? 0u : static_cast<unsigned>(egl_err));
            if (gles_mod) {
                FreeLibrary(gles_mod);
            }
            if (egl_mod) {
                FreeLibrary(egl_mod);
            }
            return false;
        }

        // Refuse if loader still bound us to game basenames (should not happen with sideload names).
        const auto gles_path = ModulePathString(gles_mod);
        const auto egl_path = ModulePathString(egl_mod);
        const auto gles_leaf = std::filesystem::path(gles_path).filename().string();
        const auto egl_leaf = std::filesystem::path(egl_path).filename().string();
        if (!EqualsIgnoreCase(gles_leaf, "ds_GLESv2.dll") || !EqualsIgnoreCase(egl_leaf, "ds_libEGL.dll")) {
            spdlog::error("ANGLE sideload resolved unexpected modules gles={} egl={}", gles_path, egl_path);
            FreeLibrary(gles_mod);
            FreeLibrary(egl_mod);
            return false;
        }

        g_angle_glesv2 = gles_mod;
        g_angle_egl = egl_mod;
        spdlog::info("ANGLE sideload loaded gles={} egl={}", gles_path, egl_path);
        return true;
    }

    static bool EnsureAngleDllsLoaded() {
        if (g_angle_glesv2 && g_angle_egl) {
            return true;
        }

        // Never fall back to bare LoadLibrary("libGLESv2.dll") — game already owns those names.
        if (TryLoadAnglePair(ThisPluginDir())) {
            return true;
        }
        if (TryLoadAnglePair(ModDepsDir())) {
            return true;
        }

        spdlog::error("ANGLE sideload missing: need {} and {} under plugin dir or Mod/deps "
                      "(game-resident libGLESv2/libEGL are not used for rebind)",
                      std::filesystem::path(kSideloadGlesName).string(),
                      std::filesystem::path(kSideloadEglName).string());
        return false;
    }

    static EGLDisplay EGLAPIENTRY MyEglGetDisplay(EGLNativeDisplayType native_display) {
        auto real_get_display = reinterpret_cast<PFNEGLGETDISPLAYPROC>(RealEglExport("eglGetDisplay"));
        if (!real_get_display) {
            return EGL_NO_DISPLAY;
        }

        if (!IsVulkanPlatformRequested()) {
            return real_get_display(native_display);
        }

        auto real_get_proc = reinterpret_cast<PFNEGLGETPROCADDRESSPROC>(RealEglExport("eglGetProcAddress"));
        auto get_platform_display = real_get_proc
                                            ? reinterpret_cast<PFNEGLGETPLATFORMDISPLAYEXTPROC>(
                                                      real_get_proc("eglGetPlatformDisplayEXT"))
                                            : nullptr;
        if (get_platform_display == nullptr) {
            return real_get_display(native_display);
        }

        const EGLint platform_attribs[] = {
                EGL_PLATFORM_ANGLE_TYPE_ANGLE, EGL_PLATFORM_ANGLE_TYPE_VULKAN_ANGLE,
                EGL_NONE};
        auto display = get_platform_display(EGL_PLATFORM_ANGLE_ANGLE,
                                            reinterpret_cast<void *>(native_display),
                                            platform_attribs);
        return display != EGL_NO_DISPLAY ? display : real_get_display(native_display);
    }

    static EGLBoolean EGLAPIENTRY MyEglInitialize(EGLDisplay dpy, EGLint *major, EGLint *minor) {
        auto real_initialize = reinterpret_cast<PFNEGLINITIALIZEPROC>(RealEglExport("eglInitialize"));
        if (!real_initialize) {
            return EGL_FALSE;
        }

        const auto result = real_initialize(dpy, major, minor);
        if (result == EGL_FALSE) {
            auto real_get_error = reinterpret_cast<PFNEGLGETERRORPROC>(RealEglExport("eglGetError"));
            const auto egl_error = real_get_error ? real_get_error() : EGL_BAD_ALLOC;
            spdlog::error("eglInitialize failed: eglError=0x{:04X} angleDefaultPlatform={}",
                          static_cast<unsigned int>(egl_error),
                          IsVulkanPlatformRequested() ? "vulkan" : "<other>");
            return result;
        }

        auto real_query_string = reinterpret_cast<PFNEGLQUERYSTRINGPROC>(RealEglExport("eglQueryString"));
        const auto *extensions = real_query_string ? real_query_string(dpy, EGL_EXTENSIONS) : nullptr;
        const bool supports_post_sub_buffer =
                extensions != nullptr && strstr(extensions, "EGL_NV_post_sub_buffer") != nullptr;
        g_display_supports_post_sub_buffer = supports_post_sub_buffer;

        return result;
    }

    static EGLSurface EGLAPIENTRY MyEglCreateWindowSurface(EGLDisplay dpy,
                                                           EGLConfig config,
                                                           EGLNativeWindowType win,
                                                           const EGLint *attrib_list) {
        auto real_create = reinterpret_cast<PFNEGLCREATEWINDOWSURFACEPROC>(RealEglExport("eglCreateWindowSurface"));
        if (!real_create) {
            return EGL_NO_SURFACE;
        }

        std::vector<EGLint> sanitized_attribs;
        const EGLint *effective_attribs = attrib_list;
        if (attrib_list != nullptr && !g_display_supports_post_sub_buffer) {
            for (const EGLint *current = attrib_list; *current != EGL_NONE; current += 2) {
                if (current[0] == EGL_POST_SUB_BUFFER_SUPPORTED_NV) {
                    continue;
                }

                sanitized_attribs.push_back(current[0]);
                sanitized_attribs.push_back(current[1]);
            }

            if (!sanitized_attribs.empty()) {
                sanitized_attribs.push_back(EGL_NONE);
                effective_attribs = sanitized_attribs.data();
            } else if (attrib_list[0] != EGL_NONE) {
                sanitized_attribs.push_back(EGL_NONE);
                effective_attribs = sanitized_attribs.data();
            }
        }

        auto surface = real_create(dpy, config, win, effective_attribs);
        if (surface == EGL_NO_SURFACE) {
            spdlog::error("eglCreateWindowSurface failed");
        }

        return surface;
    }

    static EGLBoolean EGLAPIENTRY MyEglMakeCurrent(EGLDisplay dpy,
                                                   EGLSurface draw,
                                                   EGLSurface read,
                                                   EGLContext ctx) {
        auto real_make_current = reinterpret_cast<PFNEGLMAKECURRENTPROC>(RealEglExport("eglMakeCurrent"));
        if (!real_make_current) {
            return EGL_FALSE;
        }

        const auto result = real_make_current(dpy, draw, read, ctx);
        if (result == EGL_TRUE && ctx != EGL_NO_CONTEXT) {
            CaptureCurrentRenderBackend();
        }
        return result;
    }

    static __eglMustCastToProperFunctionPointerType EGLAPIENTRY MyEglGetProcAddress(const char *procname) {
        if (auto wrapped_symbol = ResolveWrappedEglSymbol(procname)) {
            return reinterpret_cast<__eglMustCastToProperFunctionPointerType>(wrapped_symbol);
        }

        auto real = reinterpret_cast<PFNEGLGETPROCADDRESSPROC>(
                GetProcAddress(g_angle_egl ? g_angle_egl : g_angle_glesv2, "eglGetProcAddress"));
        if (!real) {
            return nullptr;
        }
        return real(procname);
    }

    FARPROC ResolveWrappedSymbol(const char *name, const WrappedSymbol *symbols, std::size_t symbol_count) {
        if (name == nullptr) {
            return nullptr;
        }

        for (std::size_t index = 0; index < symbol_count; ++index) {
            if (strcmp(name, symbols[index].name) == 0) {
                return symbols[index].proc;
            }
        }

        return nullptr;
    }

    template<typename T>
    bool WriteProtectedValue(T *slot, T value) {
        DWORD old_protect = 0;
        if (!VirtualProtect(slot, sizeof(T), PAGE_READWRITE, &old_protect)) {
            return false;
        }

        *slot = value;

        DWORD ignored = 0;
        return VirtualProtect(slot, sizeof(T), old_protect, &ignored) != 0;
    }

    struct ImportRebindContext {
        std::string module_name;
        FARPROC (*resolver)(const char *){nullptr};
        HMODULE original_module{nullptr};
        std::unordered_map<uint16_t, std::string> ordinal_to_name;
    };

    void BuildOrdinalNameMap(ImportRebindContext *ctx) {
        if (!ctx || !ctx->original_module) {
            return;
        }
        module_enumerate_exports(ctx->original_module, +[](const ExportDetails *details, void *user_data) -> bool {
        auto *map_ctx = static_cast<ImportRebindContext *>(user_data);
        if (details->name != nullptr && details->ordinal != 0) {
            map_ctx->ordinal_to_name.emplace(details->ordinal, details->name);
        }
        return true; }, ctx);
    }

    FARPROC ResolveWrappedEglSymbol(const char *name) {
        static const WrappedSymbol kWrappedEglSymbols[] = {
                {"eglGetDisplay", reinterpret_cast<FARPROC>(MyEglGetDisplay)},
                {"eglInitialize", reinterpret_cast<FARPROC>(MyEglInitialize)},
                {"eglCreateWindowSurface", reinterpret_cast<FARPROC>(MyEglCreateWindowSurface)},
                {"eglMakeCurrent", reinterpret_cast<FARPROC>(MyEglMakeCurrent)},
                {"eglGetProcAddress", reinterpret_cast<FARPROC>(MyEglGetProcAddress)},
        };

        return ResolveWrappedSymbol(name, kWrappedEglSymbols, sizeof(kWrappedEglSymbols) / sizeof(kWrappedEglSymbols[0]));
    }

    void RebindModuleImports(HMODULE target_module,
                             const char *import_module_name,
                             FARPROC (*resolver)(const char *),
                             HMODULE original_module) {
        ImportRebindContext context{import_module_name, resolver, original_module, {}};
        BuildOrdinalNameMap(&context);

        module_enumerate_imports(target_module, +[](const ImportDetails *details, void *user_data) -> bool {
        auto &ctx = *static_cast<ImportRebindContext *>(user_data);
        if (!details->module || !EqualsIgnoreCase(details->module, ctx.module_name)) {
            return true;
        }

        FARPROC replacement = nullptr;
        std::string resolved_name;
        if (details->name != nullptr) {
            replacement = ctx.resolver ? ctx.resolver(details->name) : nullptr;
        } else if (details->ordinal != 0) {
            auto name_it = ctx.ordinal_to_name.find(details->ordinal);
            if (name_it != ctx.ordinal_to_name.end()) {
                resolved_name = name_it->second;
                replacement = ctx.resolver ? ctx.resolver(resolved_name.c_str()) : nullptr;
            }
        }

        if (!replacement) {
            spdlog::warn("failed to resolve replacement import {}!{}{}", ctx.module_name,
                details->name != nullptr ? details->name : "ordinal#",
                details->name != nullptr ? "" : std::to_string(details->ordinal));
            return true;
        }

        auto slot = static_cast<void **>(details->slot);
        if (!WriteProtectedValue(slot, reinterpret_cast<void *>(replacement))) {
            spdlog::error("failed to patch IAT slot for {}!{}{}", ctx.module_name,
                details->name != nullptr ? details->name : "ordinal#",
                details->name != nullptr ? "" : std::to_string(details->ordinal));
            return true;
        }
        return true; }, &context);
    }

    void RebindMainModuleAngleImports() {
        auto main_module = GetModuleHandleW(nullptr);
        if (!main_module) {
            return;
        }

        // Game imports ANGLE by ordinal. Ordinal tables differ between stock bin64 ANGLE
        // and our shared build — map ordinals from the *game-resident* modules, then resolve
        // replacement procs by name from the sideload modules (g_angle_*).
        HMODULE ordinal_egl = GetModuleHandleW(L"libEGL.dll");
        HMODULE ordinal_gles = GetModuleHandleW(L"libGLESv2.dll");
        if (!ordinal_egl) {
            spdlog::warn("game-resident libEGL.dll not found; ordinal IAT map may be wrong");
            ordinal_egl = g_angle_egl;
        }
        if (!ordinal_gles) {
            spdlog::warn("game-resident libGLESv2.dll not found; ordinal IAT map may be wrong");
            ordinal_gles = g_angle_glesv2;
        }

        RebindModuleImports(main_module, "libEGL.dll", &ResolveGameEglSymbol, ordinal_egl);
        RebindModuleImports(main_module, "libGLESv2.dll", &ResolveGameGlesSymbol, ordinal_gles);
    }

}// namespace

DONTSTARVEINJECTOR_GAME_API void InitGameOpenGl() {
    if (g_angle_egl_initialized) {
        return;
    }
    if (!InjectorCtx::instance()->DontStarveInjectorIsClient) {
        return;
    }
    (void) ds::config::ensure_resolved();
    std::string_view angle_backend = "auto";
    const bool has_rc = ds::config::current() != nullptr;
    if (auto *rc = ds::config::current()) {
        angle_backend = ds::render_angle::angle_backend(*rc);
    }
    const auto backend = from_string(angle_backend);
    if (!has_rc || backend == DstAngleBackend::Auto) {
        return;
    }
    if (backend == DstAngleBackend::Unknown) {
        // Feature active path with unknown value: default to auto (no rebind).
        spdlog::warn("unknown AngleBackend '{}', skipping ANGLE rebind", angle_backend);
        return;
    }

    if (!EnsureAngleDllsLoaded()) {
        return;
    }
    EnsureVulkanLayerDisableEnvironment();
    RebindMainModuleAngleImports();
    // VBPool resolves GL entry points via GetProcAddress(libGLESv2); do not
    // hard-call into plugin_render_vbpool from angle (Path A M-R1 decouple).
    g_angle_egl_initialized = true;
}



DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_get_render_backend_name() {
    if (g_render_backend_captured.load(std::memory_order_acquire) && !g_render_backend_name.empty()) {
        return g_render_backend_name.c_str();
    }

    static std::string requested_backend_name = GetRequestedRenderBackendName();
    return requested_backend_name.empty() ? nullptr : requested_backend_name.c_str();
}

#else

DONTSTARVEINJECTOR_GAME_API void InitGameOpenGl() {
}

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_get_render_backend_name() {
    return nullptr;
}

#endif
