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

#include <steam_api.h>
#include <thread>
#include <chrono>
#include <vector>

static bool get_mod_folder(ISteamUGC *ugc, PublishedFileId_t id, std::filesystem::path &res)
{
    auto state = ugc->GetItemState(id);
    if (state & k_EItemStateInstalled)
    {
        uint64 punSizeOnDisk;
        uint32 punTimeStamp;
        char path[260];
        if (ugc->GetItemInstallInfo(id, &punSizeOnDisk, path, 255, &punTimeStamp))
        {
            res = std::filesystem::path(path).parent_path();
            return true;
        }
    }
    return false;
}

using namespace std::literals;

static std::unordered_set<file_interface *> NoFileHandlers;
static std::unordered_map<std::filesystem::path, std::unique_ptr<zip_manager_interface>> zipPaths = []()
{
    std::unordered_map<std::filesystem::path, std::unique_ptr<zip_manager_interface>> zipPaths;
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

static std::filesystem::path to_path(const char *p)
{
    try
    {
        return std::filesystem::path(p);
    }
    catch (const std::exception &)
    {
        return std::filesystem::path((char8_t*)p);
    }
}

static std::mutex mtx;

static std::optional<std::filesystem::path> init_steam_workshop_dir()
{
    if (!SteamAPI_Init())
    {
        return std::nullopt;
    }
    std::filesystem::path dir;
    auto ugc = SteamUGC();
    if (get_mod_folder(ugc, 3010545764, dir))
    {
        return dir;
    }
    auto len = ugc->GetNumSubscribedItems();
    std::vector<PublishedFileId_t> PublishedFileIds;
    PublishedFileIds.resize(len);
    PublishedFileIds.resize(ugc->GetSubscribedItems(PublishedFileIds.data(), len));
    for (auto PublishedFileId : PublishedFileIds)
    {
        if (get_mod_folder(ugc, PublishedFileId, dir))
        {
            break;
        }
    }
    return dir;
}

static std::optional<std::filesystem::path> get_workshop_dir()
{
    static auto dir = init_steam_workshop_dir();
    return dir;
}

static FILE *lj_fopen(char const *f, const char *mode) noexcept
{
    auto path = to_path(f);
    auto path_s = path.string();
    // TODO：在w的情况下是不是行为不一致
    auto fp = fopen(path_s.c_str(), mode);
    if (fp)
        return fp;

    constexpr auto mods_root = "../mods/workshop-"sv;
    if (path_s.starts_with(mods_root) && get_workshop_dir())
    {
        auto mod_path = std::filesystem::path(path_s.substr(mods_root.size()));
        // auto mod_name = *mod_path.begin();
        auto real_path = get_workshop_dir().value() / mod_path;
        auto fp = fopen(real_path.string().c_str(), mode);
        return fp;
    }

    if (mode[0] == 'w' || (mode[0] == 'a' && mode[1] == '+'))
    {
        // write mode
    }
    else
    {
        // read mode
        // try zip
        auto key = *path.begin();
        if (zipPaths.contains(key))
        {
            auto zip_manager = zipPaths[key].get();
            if (!zip_manager)
            {
                auto real_zip_path = std::filesystem::path{"databundles"} / key;
                real_zip_path = real_zip_path.replace_extension(".zip");
                zipPaths[key] = create_zip_manager(std::move(real_zip_path));
                zip_manager = zipPaths[key].get();
            }
            auto handler = zip_manager->fopen(path);
            NoFileHandlers.emplace(handler);
            return (FILE *)handler;
        }
    }
    return nullptr;
}

static int lj_fclose(FILE *fp) noexcept
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        NoFileHandlers.erase((file_interface *)fp);
        int res = ((file_interface *)fp)->fclose();
        delete fp;
        return res;
    }
    return fclose(fp);
}
static int lj_fscanf(FILE *const fp, char const *const format, ...) noexcept
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        va_list args;
        va_start(args, format);
        auto res = ((file_interface *)fp)->fscanf(format, args);
        va_end(args);
        return res;
    }
    return fclose(fp);
}
static char *lj_fgets(char *_Buffer, int _MaxCount, FILE *fp) noexcept
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        return ((file_interface *)fp)->fgets(_Buffer, _MaxCount);
    }
    return fgets(_Buffer, _MaxCount, fp);
}
static size_t lj_fread(
    void *_Buffer,
    size_t _ElementSize,
    size_t _ElementCount,
    FILE *fp) noexcept
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        return ((file_interface *)fp)->fread(_Buffer, _ElementSize, _ElementCount);
    }
    return fread(_Buffer, _ElementSize, _ElementCount, fp);
}
static size_t lj_fwrite(
    void const *_Buffer,
    size_t _ElementSize,
    size_t _ElementCount,
    FILE *fp) noexcept
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        return ((file_interface *)fp)->fwrite(_Buffer, _ElementSize, _ElementCount);
    }
    return fwrite(_Buffer, _ElementSize, _ElementCount, fp);
}

static int lj_ferror(FILE *fp) noexcept
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        return ((file_interface *)fp)->ferror();
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

static int lj_fseeko(FILE *fp, __off_t _Offset, int _Origin)
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        return ((file_interface *)fp)->fseeko(_Offset, _Origin);
    }
    return fseeko(fp, _Offset, _Origin);
}
static __off64_t lj_ftello(FILE *fp)
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        return ((file_interface *)fp)->ftello();
    }
    return ftello(fp);
}
#endif

static void lj_clearerr(FILE *fp) noexcept
{
    if (NoFileHandlers.contains((file_interface *)fp))
    {
        return ((file_interface *)fp)->clearerr();
    }
    return clearerr(fp);
}

#include "util/platform.hpp"

static int lj_need_transform_path() noexcept
{
    static bool has_lua_debug_flag = []{
        std::string_view cmd = get_cwd();
        return cmd.contains("-enable_lua_debugger");
    }();
    return has_lua_debug_flag;
}

void init_luajit_io(module_handler_t hluajitModule)
{
#define INIT_LUAJIT_IO(name)                                      \
    {                                                             \
        auto ptr = (void **)loadlibproc(hluajitModule, #name); \
        if (ptr)                                                  \
            *ptr = (void *)&name;                                 \
    }

    INIT_LUAJIT_IO(lj_fclose);
    INIT_LUAJIT_IO(lj_ferror);
    INIT_LUAJIT_IO(lj_fgets);
    INIT_LUAJIT_IO(lj_fopen);
    INIT_LUAJIT_IO(lj_fread);
    INIT_LUAJIT_IO(lj_fscanf);
#ifdef _WIN32
    INIT_LUAJIT_IO(lj_fseeki64);
    INIT_LUAJIT_IO(lj_ftelli64);
#else
    INIT_LUAJIT_IO(lj_fseeko)
    INIT_LUAJIT_IO(lj_ftello)
#endif
    INIT_LUAJIT_IO(lj_fwrite);
    INIT_LUAJIT_IO(lj_clearerr);
    INIT_LUAJIT_IO(lj_need_transform_path);
#undef INIT_LUAJIT_IO
}
