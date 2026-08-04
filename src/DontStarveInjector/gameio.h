#pragma once
#include "config.hpp"
#include <cstdio>
#include <stdint.h>
typedef struct _GumModule GumModule;
DS_INJECTOR_CXX_API void init_luajit_io(GumModule *luaModule);

DS_INJECTOR_CXX_API void BInitWorkshopForGameServerHook(uint32_t unWorkshopDepotID, const char *pszFolder);

DS_INJECTOR_CXX_API FILE *lj_fopen(char const *f, const char *mode) noexcept;
DS_INJECTOR_CXX_API int lj_fclose(FILE *fp) noexcept;
DS_INJECTOR_CXX_API int lj_fscanf(FILE *const fp, char const *const format, ...) noexcept;
DS_INJECTOR_CXX_API char *lj_fgets(char *buffer, int maxCount, FILE *fp) noexcept;
DS_INJECTOR_CXX_API size_t lj_fread(void *buffer, size_t elementSize, size_t elementCount, FILE *fp) noexcept;
DS_INJECTOR_CXX_API size_t lj_fwrite(void const *buffer, size_t elementSize, size_t elementCount, FILE *fp) noexcept;
DS_INJECTOR_CXX_API int lj_ferror(FILE *fp) noexcept;
DS_INJECTOR_CXX_API int lj_feof(FILE *fp) noexcept;
DS_INJECTOR_CXX_API void lj_clearerr(FILE *fp) noexcept;
DS_INJECTOR_CXX_API int lj_fflush(FILE *fp) noexcept;
DS_INJECTOR_CXX_API int lj_setvbuf(FILE *fp, char *buf, int mode, size_t size) noexcept;
#ifdef _WIN32
DS_INJECTOR_CXX_API int lj_fseeki64(FILE *fp, __int64 offset, int origin) noexcept;
DS_INJECTOR_CXX_API __int64 lj_ftelli64(FILE *fp) noexcept;
#define lj_fseek(fp, offset, origin) lj_fseeki64(fp, (__int64)(offset), origin)
#define lj_ftell(fp) ((long)lj_ftelli64(fp))
#else
DS_INJECTOR_CXX_API int lj_fseeko(FILE *fp, off_t offset, int origin);
DS_INJECTOR_CXX_API off_t lj_ftello(FILE *fp);
#define lj_fseek(fp, offset, origin) lj_fseeko(fp, (off_t)(offset), origin)
#define lj_ftell(fp) ((long)lj_ftello(fp))
#endif
