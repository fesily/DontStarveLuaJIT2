#define NOMINMAX

#include "SignatureJson.hpp"
#include "frida-gum.h"

#include "CoreVmSignatures.hpp"
#include "SignatureRunner.hpp"
#include "platform.hpp"

#ifndef GAMEDIR
#error "not defined GAME_DIR"
#endif

#ifndef LUA51_PATH
#error "not defined LUA51_PATH"
#endif

#ifndef PROJECT_DIR
#error "not defined PROJECT_DIR"
#endif

const char *game_path = GAMEDIR R"(\bin64\dontstarve_steam_x64.exe)";
const char *game_server_path = GAMEDIR R"(\bin64\dontstarve_dedicated_server_nullrenderer_x64.exe)";
const char *lua51_path = LUA51_PATH;
const char *worker_dir = PROJECT_DIR "/Mod";

bool loadModule(const char *path) {
    GError *err = nullptr;
    if (!gum_module_load(path, &err)) {
        g_error_free(err);
        fprintf(stderr, "load module error:%s-%s\n", path, err->message);
        return false;
    }
    return true;
}

int check(const char *path, bool isClient) {
    using namespace std::literals;
    SignatureJson sj{isClient};
    sj.file_path = (std::filesystem::path{worker_dir} /
                    ("signatures_"s + (isClient ? "client"s : "server"s) + ".json"))
                           .string();
    auto signatures = sj.read_from_signatures();
    if (!signatures) {
        fprintf(stderr, "cannot read %s (platform %s, format_version %d)\n", sj.file_path.c_str(),
                SignatureJson::platform_name(), SignatureJson::format_version);
        return 1;
    }
    fprintf(stderr, "game_path:\t%s\n", path);
    if (!loadModule(path))
        return 1;
    // Lua anchor from the shared core.vm definition (never a second local copy of
    // the pattern): this checker only compares the Lua offsets against the
    // hand-maintained reference table, it does not own any signature.
    ds::sig::ContextView ctx{};
    ctx.platform = ds::sig::host_platform();
    ctx.is_client = isClient ? 1 : 0;
    ctx.module_path = path;
    if (auto *module = gum_process_find_module_by_name(path)) {
        if (auto *range = gum_module_get_range(module)) {
            ctx.module_base = range->base_address;
            ctx.module_size = range->size;
        }
    }
    ds::sig::ProviderV1 provider{};
    ds::sig::ResolveReport anchor{};
    if (!ds::sig::make_provider(&ds::core_vm::signature_provider(), &provider) ||
        !provider.resolve(provider.self, "core.vm.lua_module", &ctx, &anchor) || anchor.target_va == 0) {
        fprintf(stderr, "cannot find the lua module base addr (%s)\n", anchor.detail);
        return 1;
    }
    using namespace std::literals;
    SignatureJson sjCopy{isClient};
    auto p = std::filesystem::path{PROJECT_DIR} / "tests" / "windows_x64" / (("Signatures_"s + (isClient ? "client" : "server")) + ".txt.json");
    sjCopy.file_path = p.string();
    auto sCopy = sjCopy.read_from_signatures();
    if (!sCopy) {
        fprintf(stderr, "cannot read reference %s (regenerate it in format_version %d with a '%s' section)\n",
                p.string().c_str(), SignatureJson::format_version, SignatureJson::platform_name());
        return 1;
    }

    auto count = 0;
    for (auto [func, info]: signatures->funcs) {
        const auto ida_offset = sCopy->funcs.at(func).offset;
        if (ida_offset != info.offset) {
            fprintf(stderr, "[%s]%s [%d]-[%d]\n", func.c_str(), "can't match the address", (int) ida_offset, (int) info.offset);
            count++;
        }
    }
    return count;
}

int main() {
    gum_init_embedded();
    auto lua51_path1 = getenv("GAME_PATH");
    if (lua51_path1) {
        game_path = lua51_path1;
    }
    fprintf(stderr, "lua51_path:\t%s\n", lua51_path);
    if (!loadModule(lua51_path))
        return 1;
    set_worker_directory(worker_dir);
    SignatureJson::version_path = GAMEDIR "/version.txt";
    return check(game_path, true) + check(game_server_path, false);
}