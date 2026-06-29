#pragma once
#include <cstdio>
#include <stdint.h>
typedef struct _GumModule GumModule;
void init_luajit_io(GumModule *luaModule);

void init_luajit_jit_opt(GumModule *luaModule);

void BInitWorkshopForGameServerHook(uint32_t unWorkshopDepotID, const char *pszFolder);

FILE *lj_fopen(char const *f, const char *mode) noexcept;
int lj_fclose(FILE *fp) noexcept;
int lj_fscanf(FILE *const fp, char const *const format, ...) noexcept;
char *lj_fgets(char *buffer, int maxCount, FILE *fp) noexcept;
size_t lj_fread(void *buffer, size_t elementSize, size_t elementCount, FILE *fp) noexcept;
size_t lj_fwrite(void const *buffer, size_t elementSize, size_t elementCount, FILE *fp) noexcept;
int lj_ferror(FILE *fp) noexcept;
int lj_feof(FILE *fp) noexcept;
void lj_clearerr(FILE *fp) noexcept;
int lj_fflush(FILE *fp) noexcept;
int lj_setvbuf(FILE *fp, char *buf, int mode, size_t size) noexcept;
#ifdef _WIN32
int lj_fseeki64(FILE *fp, __int64 offset, int origin) noexcept;
__int64 lj_ftelli64(FILE *fp) noexcept;
#define lj_fseek(fp, offset, origin) lj_fseeki64(fp, (__int64)(offset), origin)
#define lj_ftell(fp) ((long)lj_ftelli64(fp))
#else
int lj_fseeko(FILE *fp, off_t offset, int origin);
off_t lj_ftello(FILE *fp);
#define lj_fseek(fp, offset, origin) lj_fseeko(fp, (off_t)(offset), origin)
#define lj_ftell(fp) ((long)lj_ftello(fp))
#endif
