﻿#include "frida-gum.h"
#include "config.hpp"

#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <unordered_set>
#include <unordered_map>
#include <cstdarg>
#include <string>
#include <string_view>
#include <mutex>
#include <optional>
#include "util/zipfile.hpp"
#include "util/gum_platform.hpp"
#include "util/platform.hpp"

#include <spdlog/spdlog.h>
#include <tracy/Tracy.hpp>

#include <thread>
#include <chrono>
#include <vector>
#include <cassert>

using namespace std::literals;

static std::unordered_set<file_interface *> NoFileHandlers;
static std::unordered_map<std::string, std::unique_ptr<zip_manager_interface>> zipPaths = []() {
    std::unordered_map<std::string, std::unique_ptr<zip_manager_interface>> zipPaths;
#define ZIP_PATH_VALUE_KEAY(name) \
    zipPaths[#name] = nullptr
    ZIP_PATH_VALUE_KEAY(anim_dynamic);
    ZIP_PATH_VALUE_KEAY(bigportraits);
    ZIP_PATH_VALUE_KEAY(fonts);
    ZIP_PATH_VALUE_KEAY(images);
    ZIP_PATH_VALUE_KEAY(klump);
    ZIP_PATH_VALUE_KEAY(scripts);
    ZIP_PATH_VALUE_KEAY(shaders);
#undef ZIP_PATH_VALUE_KEAY
    return zipPaths;
}();

static std::filesystem::path to_path(const char *p) {
    try {
        return std::filesystem::path(p);
    }
    catch (const std::exception &) {
        return std::filesystem::path((char8_t *) p);
    }
}

static std::optional<std::filesystem::path> get_workshop_dir() {
    auto dir = std::filesystem::relative(std::filesystem::path("..") / ".." / ".." / "workshop");
    const auto cmd = get_cwd();
    auto flag = "-ugc_directory";
    if (cmd.contains(flag)) {
        const auto cmds = get_cwds();
        auto iter = std::find(cmds.begin(), cmds.end(), flag);
        if (iter != cmds.end()) {
            iter++;
            if (iter != cmds.end()) {
                const auto &value = *iter;
                dir = value;
                spdlog::info("workshop_dir ugc_directory: {}", value);
            }
        }
    }
    return dir / "content" / "322330";
}

static FILE *lj_fopen(char const *f, const char *mode) noexcept {
    auto path = to_path(f);
    auto path_s = path.string();
    // TODO：在w的情况下是不是行为不一致
    auto fp = fopen(path_s.c_str(), mode);
    if (fp)
        return fp;

    static const auto workshop_dir = get_workshop_dir();
    constexpr auto mods_root = "../mods/workshop-"sv;
    if (path_s.starts_with(mods_root) && workshop_dir) {
        auto mod_path = std::filesystem::path(path_s.substr(mods_root.size()));
        // auto mod_name = *mod_path.begin();
        auto real_path = workshop_dir.value() / mod_path;
        auto fp = fopen(real_path.string().c_str(), mode);
        return fp;
    }

    if (mode[0] == 'w' || (mode[0] == 'a' && mode[1] == '+')) {
        // write mode
    } else {
        // read mode
        // try zip
        auto key = (*path.begin()).string();
        if (zipPaths.contains(key)) {
            auto zip_manager = zipPaths[key].get();
            if (!zip_manager) {
                auto real_zip_path = std::filesystem::path{"databundles"} / key;
                real_zip_path = real_zip_path.replace_extension(".zip");
                zipPaths[key] = create_zip_manager(std::move(real_zip_path));
                zip_manager = zipPaths[key].get();
            }
            auto handler = zip_manager->fopen(path);
            NoFileHandlers.emplace(handler);
            return (FILE *) handler;
        }
    }
    return nullptr;
}

static int lj_fclose(FILE *fp) noexcept {
    if (NoFileHandlers.contains((file_interface *) fp)) {
        NoFileHandlers.erase((file_interface *) fp);
        int res = ((file_interface *) fp)->fclose();
        delete fp;
        return res;
    }
    return fclose(fp);
}

static int lj_fscanf(FILE *const fp, char const *const format, ...) noexcept {
    if (NoFileHandlers.contains((file_interface *) fp)) {
        va_list args;
        va_start(args, format);
        auto res = ((file_interface *) fp)->fscanf(format, args);
        va_end(args);
        return res;
    }
    return fclose(fp);
}

static char *lj_fgets(char *_Buffer, int _MaxCount, FILE *fp) noexcept {
    if (NoFileHandlers.contains((file_interface *) fp)) {
        return ((file_interface *) fp)->fgets(_Buffer, _MaxCount);
    }
    return fgets(_Buffer, _MaxCount, fp);
}

static size_t lj_fread(
        void *_Buffer,
        size_t _ElementSize,
        size_t _ElementCount,
        FILE *fp) noexcept {
    if (NoFileHandlers.contains((file_interface *) fp)) {
        return ((file_interface *) fp)->fread(_Buffer, _ElementSize, _ElementCount);
    }
    return fread(_Buffer, _ElementSize, _ElementCount, fp);
}

static size_t lj_fwrite(
        void const *_Buffer,
        size_t _ElementSize,
        size_t _ElementCount,
        FILE *fp) noexcept {
    if (NoFileHandlers.contains((file_interface *) fp)) {
        return ((file_interface *) fp)->fwrite(_Buffer, _ElementSize, _ElementCount);
    }
    return fwrite(_Buffer, _ElementSize, _ElementCount, fp);
}

static int lj_ferror(FILE *fp) noexcept {
    if (NoFileHandlers.contains((file_interface *) fp)) {
        return ((file_interface *) fp)->ferror();
    }
    return ferror(fp);
}

#ifdef _WIN32

static int lj_fseeki64(
    FILE *fp,
    __int64 _Offset,
    int _Origin) noexcept
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        return ((file_interface *)fp)->fseeko(_Offset, _Origin);
    }
    return _fseeki64(fp, _Offset, _Origin);
}

static __int64 lj_ftelli64(FILE *fp) noexcept
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        return ((file_interface *)fp)->ftello();
    }
    return _ftelli64(fp);
}

#else

static int lj_fseeko(FILE *fp, off_t _Offset, int _Origin) {
    if (NoFileHandlers.contains((file_interface *) fp)) {
        return ((file_interface *) fp)->fseeko(_Offset, _Origin);
    }
    return fseeko(fp, _Offset, _Origin);
}

static off_t lj_ftello(FILE *fp) {
    if (NoFileHandlers.contains((file_interface *) fp)) {
        return ((file_interface *) fp)->ftello();
    }
    return ftello(fp);
}

#endif

static void lj_clearerr(FILE *fp) noexcept {
    if (NoFileHandlers.contains((file_interface *) fp)) {
        return ((file_interface *) fp)->clearerr();
    }
    return clearerr(fp);
}

static int lj_need_transform_path() noexcept {
    static bool has_lua_debug_flag = [] {
        auto cmd = get_cwd();
        if (cmd.contains("DST_Secondary") || cmd.contains("DST_Master")) {
            cmd = get_cwd(getParentId());
        }
        return cmd.contains("-enable_lua_debugger");
    }();
    spdlog::info("lj_need_transform_path: {}", has_lua_debug_flag);
    return has_lua_debug_flag;
}

static uint32_t lj_jit_default_flags() noexcept {
    auto path = getExePath();
    return path.string().contains("nullrenderer") ? 1 : 0;
}

static int fullgc_mb = 0;
void (* lua_gc_func)(void *L, int,int);
void lj_gc_fullgc_external(void* L, void (* oldfn)(void *L)){
    
    if (fullgc_mb == 0) {
        ZoneScopedN("lua_full_gc");
        oldfn(L);
    }
    else {
        ZoneScopedN("lua_small_gc");
        lua_gc_func(L, 5, fullgc_mb << 10);
    }
}
extern "C" DONTSTARVEINJECTOR_API void disable_fullgc(int mb) {
    fullgc_mb = mb;
}

#define SET_LUAJIT_API_FUNC(name)                                 \
    {                                                             \
        auto ptr = (void **)loadlibproc(hluajitModule, #name);    \
        if (ptr)                                                  \
            *ptr = (void *)&name;                                 \
    }

void init_luajit_io(module_handler_t hluajitModule) {
    SET_LUAJIT_API_FUNC(lj_fclose);
    SET_LUAJIT_API_FUNC(lj_ferror);
    SET_LUAJIT_API_FUNC(lj_fgets);
    SET_LUAJIT_API_FUNC(lj_fopen);
    SET_LUAJIT_API_FUNC(lj_fread);
    SET_LUAJIT_API_FUNC(lj_fscanf);
#ifdef _WIN32
    SET_LUAJIT_API_FUNC(lj_fseeki64);
    SET_LUAJIT_API_FUNC(lj_ftelli64);
#else
    SET_LUAJIT_API_FUNC(lj_fseeko)
    SET_LUAJIT_API_FUNC(lj_ftello)
#endif
    SET_LUAJIT_API_FUNC(lj_fwrite);
    SET_LUAJIT_API_FUNC(lj_clearerr);
    SET_LUAJIT_API_FUNC(lj_need_transform_path);
    SET_LUAJIT_API_FUNC(lj_gc_fullgc_external);
    lua_gc_func = (decltype(lua_gc_func))loadlibproc(hluajitModule, "lua_gc");
}

void init_luajit_jit_opt(module_handler_t hluajitModule) {
    SET_LUAJIT_API_FUNC(lj_jit_default_flags);
}
