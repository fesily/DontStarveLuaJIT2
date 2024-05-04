#define NOMINMAX
#include "frida-gum.h"
#include "SignatureJson.hpp"

#include "LuaModule.hpp"
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
const char *worker_dir = PROJECT_DIR "/Mod/bin64/windows";

bool loadModule(const char *path)
{
    GError *err = nullptr;
    if (!gum_module_load(path, &err))
    {
        g_error_free(err);
        fprintf(stderr, "load module error:%s-%s\n", path, err->message);
        return false;
    }
    return true;
}

struct disamer
{
    csh hcs;
    cs_insn *insn;
    const uint8_t *mem;
    size_t offset;
    uint64_t address;
    bool end;
    bool onlyInsn;
    disamer(csh h, void *func)
    {
        hcs = h;
        insn = cs_malloc(hcs);
        mem = (uint8_t *)func;
        offset = 99999;
        address = GUM_ADDRESS(mem);
        end = false;
    }
    ~disamer()
    {
        cs_free(insn, 1);
    }

    cs_insn *next()
    {
        if (!cs_disasm_iter(hcs, &mem, &offset, &address, insn))
        {
            end = true;
            return NULL;
        }
        switch (insn->id)
        {
        case X86_INS_LEA:
            if (insn->bytes[0] == 0x48 && insn->bytes[1] == 0x8D && insn->bytes[3] == 0x15)
            {
                return NULL;
            }
            break;
        case X86_INS_CALL:
        case X86_INS_JMP:
            return NULL;
        case X86_INS_INT3:
            end = true;
            return NULL;
        default:
            break;
        }
        return insn;
    }
};

static bool isSameFuncByDisasm(disamer &disamer1, disamer &disamer2)
{
    while (1)
    {
        cs_insn *insn1 = disamer1.next();
        cs_insn *insn2 = disamer2.next();
        if (!insn1)
        {
            if (insn2)
                return false;
            if (disamer1.end)
                return disamer2.end;
            if (disamer1.insn->id != disamer2.insn->id)
                return false;
        }
        else
        {
            if (insn1->size != insn2->size)
                return false;
            if (std::string_view(insn1->op_str).find("rip") != std::string_view::npos)
            {
                return insn1->id == insn2->id;
            }
            if (memcmp(insn1->bytes, insn2->bytes, insn1->size) != 0)
                return false;
        }
    }
    return true;
}

static bool checkLuaFunc(void *func1, void *func2, std::string &ecmsg)
{
    csh hcs;
    cs_arch_register_x86();
    auto ec = cs_open(CS_ARCH_X86, CS_MODE_64, &hcs);
    if (ec != CS_ERR_OK)
        return false;
    bool ret = true;
    {
        disamer disamer1(hcs, func1), disamer2(hcs, func2);
        ret = isSameFuncByDisasm(disamer1, disamer2);
        if (!ret)
        {
            if (disamer1.insn)
            {
                ecmsg += disamer1.insn->mnemonic;
                ecmsg += " ";
                ecmsg += disamer1.insn->op_str;
            }
            else
            {
                ecmsg += "unkown disamer1";
            }
            ecmsg += '\n';

            if (disamer2.insn)
            {
                ecmsg += disamer2.insn->mnemonic;
                ecmsg += " ";
                ecmsg += disamer2.insn->op_str;
            }
            else
            {
                ecmsg += "unkown disamer2";
            }
        }
    }
    cs_close(&hcs);
    return ret;
}

int check(const char *path, bool isClient)
{
    SignatureJson sj{isClient};
    auto signatures = sj.read_from_signatures().value();
    fprintf(stderr, "game_path:\t%s\n", path);
    if (!loadModule(path))
        return 1;
    if (luaModuleSignature.scan(path) == 0)
    {
        fprintf(stderr, "%s", "can find lua module base addr\n");
        return 1;
    }

    auto count = 0;
    for (auto [func, offset] : signatures.funcs)
    {
        auto func_addr = luaModuleSignature.target_address + GPOINTER_TO_INT(offset);
        auto dll_func = gum_module_find_export_by_name(lua51_path, func.data());
        if (dll_func == 0)
        {
            fprintf(stderr, " dll_func:[%s] is null\n", func.data());
            count++;
            continue;
        }
        std::string ecmsg;
        auto k2 = create_signature((void *)dll_func, {});
        auto k1 = create_signature((void *)func_addr, {});
        if (k1 != k2)
        {
            size_t limit = std::min(k1.size(), k2.size());
            for (size_t i = 0; i < limit; i++)
            {
                if (k1[i] != k2[i])
                {
                    fprintf(stderr,"%llu\n\t\tdll:%s\texe:%s\n", i, k1[i].c_str(), k2[i].c_str());
                }
            }

            fprintf(stderr, "%s signature not equal\n", func.data());
        }
        if (!checkLuaFunc((void *)func_addr, (void *)dll_func, ecmsg))
        {
            count++;
            fprintf(stderr, "%s signature not equal\n%s\n\n", func.data(), ecmsg.c_str());
        }
    }
    return count;
}

int main()
{
    gum_init_embedded();
    auto lua51_path1 = getenv("GAME_PATH");
    if (lua51_path1)
    {
        game_path = lua51_path1;
    }
    fprintf(stderr, "lua51_path:\t%s\n", lua51_path);
    if (!loadModule(lua51_path))
        return 1;
    set_worker_directory(worker_dir);
    SignatureJson::version_path = GAMEDIR "/version.txt";
    return check(game_path, true) + check(game_server_path, false);
}