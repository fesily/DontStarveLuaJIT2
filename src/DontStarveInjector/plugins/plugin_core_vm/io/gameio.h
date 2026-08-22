#pragma once
#include "config/InjectorHostConfig.hpp"
#include <cstdio>
#include <stdint.h>
typedef struct _GumModule GumModule;

// gameio lives in plugin_core_vm. Export from that module; other TUs in the same DLL
// see a plain declaration. L0 resolves select C exports via GetProcAddress.
#if defined(DS_CORE_VM_BUILD)
#  if defined(_WIN32)
#    define GAME_IO_API extern "C" __declspec(dllexport)
#  else
#    define GAME_IO_API extern "C" __attribute__((visibility("default")))
#  endif
#else
#  define GAME_IO_API extern "C"
#endif

GAME_IO_API void init_luajit_io(GumModule *luaModule);

DONTSTARVEINJECTOR_GAME_API void BInitWorkshopForGameServerHook(uint32_t unWorkshopDepotID, const char *pszFolder);

GAME_IO_API FILE *lj_fopen(char const *f, const char *mode) noexcept;
GAME_IO_API int lj_fclose(FILE *fp) noexcept;
GAME_IO_API int lj_fscanf(FILE *const fp, char const *const format, ...) noexcept;
GAME_IO_API char *lj_fgets(char *buffer, int maxCount, FILE *fp) noexcept;
GAME_IO_API size_t lj_fread(void *buffer, size_t elementSize, size_t elementCount, FILE *fp) noexcept;
GAME_IO_API size_t lj_fwrite(void const *buffer, size_t elementSize, size_t elementCount, FILE *fp) noexcept;
GAME_IO_API int lj_ferror(FILE *fp) noexcept;
GAME_IO_API int lj_feof(FILE *fp) noexcept;
GAME_IO_API void lj_clearerr(FILE *fp) noexcept;
GAME_IO_API int lj_fflush(FILE *fp) noexcept;
GAME_IO_API int lj_setvbuf(FILE *fp, char *buf, int mode, size_t size) noexcept;
#ifdef _WIN32
GAME_IO_API int lj_fseeki64(FILE *fp, __int64 offset, int origin) noexcept;
GAME_IO_API __int64 lj_ftelli64(FILE *fp) noexcept;
#define lj_fseek(fp, offset, origin) lj_fseeki64(fp, (__int64)(offset), origin)
#define lj_ftell(fp) ((long)lj_ftelli64(fp))
#else
GAME_IO_API int lj_fseeko(FILE *fp, off_t offset, int origin);
GAME_IO_API off_t lj_ftello(FILE *fp);
#define lj_fseek(fp, offset, origin) lj_fseeko(fp, (off_t)(offset), origin)
#define lj_ftell(fp) ((long)lj_ftello(fp))
#endif
