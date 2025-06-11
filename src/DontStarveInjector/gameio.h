#pragma once
#include <stdint.h>
typedef struct _GumModule GumModule;
void init_luajit_io(GumModule *luaModule);

void init_luajit_jit_opt(GumModule *luaModule);

void BInitWorkshopForGameServerHook(uint32_t unWorkshopDepotID, const char *pszFolder);
