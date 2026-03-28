#include "GameOpenGl.hpp"

#ifdef _WIN32

#include "config.hpp"
#include "util/module.hpp"
#include "angle_iat_generated.hpp"
#include "gameModConfig.hpp"

#include <Windows.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <optional>

#include <egl/eglext.h>
#include <egl/eglext_angle.h>

namespace {

    using PFNEGLGETPLATFORMDISPLAYEXTPROC = EGLDisplay(EGLAPIENTRYP)(EGLenum platform,
                                                                     void *native_display,
                                                                     const EGLint *attrib_list);

    struct WrappedSymbol {
        const char *name;
        FARPROC proc;
    };

    constexpr const char *kSteamOverlayLayerName = "VK_LAYER_VALVE_steam_overlay";

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
            DstAngleBackend backend = InjectorConfig::instance()->DST_ANGLE_BACKEND;
            if (backend == DstAngleBackend::Auto) {
                const auto platform = GetEnvironmentValue("ANGLE_DEFAULT_PLATFORM");
                if (!platform.empty())
                    return _stricmp(platform.c_str(), "vulkan") == 0;
            }
            auto configs = GameJitModConfig::instance();
            if (configs)
                backend = from_string(configs->angle_backend);
            if (backend != DstAngleBackend::Auto) 
                SetEnvironmentVariableA("ANGLE_DEFAULT_PLATFORM", to_string(backend).data());
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

    static void CaptureCurrentRenderBackend() {
        if (g_render_backend_captured.load(std::memory_order_acquire)) {
            return;
        }

        const auto *renderer = reinterpret_cast<const char *>(glGetString(GL_RENDERER));
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

    static EGLDisplay EGLAPIENTRY MyEglGetDisplay(EGLNativeDisplayType native_display) {
        if (!IsVulkanPlatformRequested()) {
            return eglGetDisplay(native_display);
        }

        auto get_platform_display = reinterpret_cast<PFNEGLGETPLATFORMDISPLAYEXTPROC>(eglGetProcAddress("eglGetPlatformDisplayEXT"));
        if (get_platform_display == nullptr) {
            return eglGetDisplay(native_display);
        }

        const EGLint platform_attribs[] = {
                EGL_PLATFORM_ANGLE_TYPE_ANGLE, EGL_PLATFORM_ANGLE_TYPE_VULKAN_ANGLE,
                EGL_NONE};
        auto display = get_platform_display(EGL_PLATFORM_ANGLE_ANGLE,
                                            reinterpret_cast<void *>(native_display),
                                            platform_attribs);
        return display != EGL_NO_DISPLAY ? display : eglGetDisplay(native_display);
    }

    static EGLBoolean EGLAPIENTRY MyEglInitialize(EGLDisplay dpy, EGLint *major, EGLint *minor) {
        const auto result = eglInitialize(dpy, major, minor);
        if (result == EGL_FALSE) {
            const auto egl_error = eglGetError();
            spdlog::error("eglInitialize failed: eglError=0x{:04X} angleDefaultPlatform={}",
                          static_cast<unsigned int>(egl_error),
                          IsVulkanPlatformRequested() ? "vulkan" : "<other>");
            return result;
        }

        const auto *extensions = eglQueryString(dpy, EGL_EXTENSIONS);
        const bool supports_post_sub_buffer =
                extensions != nullptr && strstr(extensions, "EGL_NV_post_sub_buffer") != nullptr;
        g_display_supports_post_sub_buffer = supports_post_sub_buffer;

        return result;
    }

    static EGLSurface EGLAPIENTRY MyEglCreateWindowSurface(EGLDisplay dpy,
                                                           EGLConfig config,
                                                           EGLNativeWindowType win,
                                                           const EGLint *attrib_list) {
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

        auto surface = eglCreateWindowSurface(dpy, config, win, effective_attribs);
        if (surface == EGL_NO_SURFACE) {
            spdlog::error("eglCreateWindowSurface failed");
        }

        return surface;
    }

    static EGLBoolean EGLAPIENTRY MyEglMakeCurrent(EGLDisplay dpy,
                                                   EGLSurface draw,
                                                   EGLSurface read,
                                                   EGLContext ctx) {
        const auto result = eglMakeCurrent(dpy, draw, read, ctx);
        if (result == EGL_TRUE && ctx != EGL_NO_CONTEXT) {
            CaptureCurrentRenderBackend();
        }
        return result;
    }

    static __eglMustCastToProperFunctionPointerType EGLAPIENTRY MyEglGetProcAddress(const char *procname) {
        if (auto wrapped_symbol = ResolveWrappedEglSymbol(procname)) {
            return reinterpret_cast<__eglMustCastToProperFunctionPointerType>(wrapped_symbol);
        }

        return eglGetProcAddress(procname);
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

    FARPROC ResolveGameEglSymbol(const char *name) {
        if (auto wrapped_symbol = ResolveWrappedEglSymbol(name)) {
            return wrapped_symbol;
        }
        return angle_iat_generated::ResolveStaticEglSymbol(name);
    }

    void RebindModuleImports(HMODULE target_module, const char *import_module_name, FARPROC (*resolver)(const char *)) {
        ImportRebindContext context{import_module_name, resolver, GetModuleHandleA(import_module_name), {}};
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

        RebindModuleImports(main_module, "libEGL.dll", &ResolveGameEglSymbol);
        RebindModuleImports(main_module, "libGLESv2.dll", &angle_iat_generated::ResolveStaticGlesSymbol);
    }

}// namespace

void InitGameOpenGl() {
    if (g_angle_egl_initialized) {
        return;
    }
    if (!InjectorCtx::instance()->DontStarveInjectorIsClient) {
        return;
    }

    EnsureVulkanLayerDisableEnvironment();
    RebindMainModuleAngleImports();

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

void InitGameOpenGl() {
}

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_get_render_backend_name() {
    return nullptr;
}

#endif
