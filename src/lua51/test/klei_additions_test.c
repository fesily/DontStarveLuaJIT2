/*
** Klei-additions regression test (lua_setfuncchunkname/getfuncchunkname, lio path guard,
** lua_isunsafedataallowed, extended numeral scanner).
**
** Build (MinGW, x86_64), from src/lua51/src:
**   for f in lapi lauxlib lbaselib lcode ldblib ldebug ldo ldump lfunc lgc linit **            liolib llex lmathlib lmem lobject lopcodes loslib lparser lstate **            lstring lstrlib ltable ltablib ltm lundump lvm lzio; do
**     gcc -m64 -O2 -c -I. -o "$OUT/$f.o" "$f.c"; done
**   gcc -m64 -O1 -I. -o klei_additions_test ../test/klei_additions_test.c "$OUT"/*.o
** (loadlib.c is left out; the test stubs luaopen_package and opens io through
**  a protected C call, like the game does.)
*/
#include <stdio.h>
#include <string.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lstate.h"   /* the client writes L->allowed_unsafedata directly */

static int fails = 0;
static void check(int cond, const char *what) {
  printf("%s %s\n", cond ? "PASS" : "FAIL", what);
  if (!cond) fails++;
}

static int run(lua_State *L, const char *src, const char *chunk) {
  int st = luaL_loadbuffer(L, src, strlen(src), chunk);
  if (st == 0) st = lua_pcall(L, 0, 1, 0);
  return st;
}

#include <stdlib.h>
/* luaopen_io installs the io table as the C functions' environment, which
** needs a calling function, so run it from a protected C call like the game. */
static int open_io_cb (lua_State *L) { luaopen_io(L); return 0; }

static void *t_alloc (void *ud, void *ptr, size_t osize, size_t nsize) {
  (void)ud; (void)osize;
  if (nsize == 0) { free(ptr); return NULL; }
  return realloc(ptr, nsize);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  lua_State *L = lua_newstate(t_alloc, NULL);
  luaopen_base(L);
  luaopen_table(L);
  luaopen_string(L);
  luaopen_math(L);
  if (lua_cpcall(L, open_io_cb, NULL) != 0)
    fprintf(stderr, "open_io failed: %s\n", lua_tostring(L, -1));
  luaopen_os(L);
  luaopen_debug(L);

  /* --- 1. numeral extension ------------------------------------------- */
  check(run(L, "return 0x1f", "=n") == 0 && lua_tonumber(L, -1) == 31,
        "numeral 0x1f = 31");
  lua_settop(L, 0);
  check(run(L, "return 0x1p4", "=n") == 0 && lua_tonumber(L, -1) == 16,
        "numeral 0x1p4 = 16");
  lua_settop(L, 0);
  check(run(L, "return 1.5e2", "=n") == 0 && lua_tonumber(L, -1) == 150,
        "numeral 1.5e2 = 150");
  lua_settop(L, 0);
  check(run(L, "return 12", "=n") == 0 && lua_tonumber(L, -1) == 12,
        "numeral 12 = 12 (plain path)");
  lua_settop(L, 0);

  /* --- 2. lua_setfuncchunkname walks the proto tree -------------------- */
  {
    const char *src =
      "local function inner() return 1 end\n"
      "return function() return inner() end\n";
    int st = luaL_loadbuffer(L, src, strlen(src), "=orig");
    check(st == 0, "loadbuffer for chunkname test");
    if (st == 0) {
      lua_setfuncchunkname(L, -1, "scripts/foo.lua");
      check(lua_getfuncchunkname(L, -1) != NULL &&
            strcmp(lua_getfuncchunkname(L, -1), "scripts/foo.lua") == 0,
            "getfuncchunkname returns the stored path");
      {
        const void *ptr = lua_topointer(L, -1);
        Closure *cl = (Closure *)ptr;
        Proto *pr = cl->l.p;
        int i, all = (pr->chunkname != NULL &&
                      strcmp(getstr(pr->chunkname), "scripts/foo.lua") == 0);
        for (i = 0; i < pr->sizep; i++) {
          if (pr->p[i]->chunkname == NULL ||
              strcmp(getstr(pr->p[i]->chunkname), "scripts/foo.lua") != 0)
            all = 0;
        }
        check(all, "setchunkname covers main + nested protos");
        /* the string must survive a full collection (lgc traverseproto) */
        run(L, "collectgarbage('collect') collectgarbage('collect') return 1", "=gc");
        lua_settop(L, 1);
        all = (pr->chunkname != NULL &&
               strcmp(getstr(pr->chunkname), "scripts/foo.lua") == 0);
        check(all, "chunkname survives two full GC cycles");
      }
      check(lua_pcall(L, 0, 1, 0) == 0, "setchunkname then run");
      check(lua_pcall(L, 0, 1, 0) == 0 && lua_tonumber(L, -1) == 1,
            "nested function still works after setchunkname");
    }
    lua_settop(L, 0);
  }

  /* --- 3. io path guard ---------------------------------------------- */
  {
    const char *cases[][2] = {
      { "return io.open('/abs.txt','r')", "absolute path rejected" },
      { "return io.open('C:/x.txt','r')", "drive path rejected" },
      { "return io.open('../../x.txt','r')", "double parent rejected" },
      { "return io.open('foo/../../x.txt','r')", "escape rejected" },
      { "return io.open('../other/x.txt','r')", "parent into non-data dir rejected" },
    };
    size_t i;
    for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
      int st = run(L, cases[i][0], "=io");
      const char *msg = (st != 0) ? lua_tostring(L, -1) : "";
      check(st != 0 && msg != NULL && strstr(msg, "invalid filepath") != NULL,
            cases[i][1]);
      lua_settop(L, 0);
    }
#define NO_GUARD_ERROR(src, what) do { \
      int st_ = run(L, (src), "=io"); \
      const char *msg_ = (st_ != 0) ? lua_tostring(L, -1) : ""; \
      check(!(st_ != 0 && msg_ != NULL && strstr(msg_, "invalid filepath")), (what)); \
      if (st_ != 0 && msg_) fprintf(stderr, "   [%s] -> %s\n", (src), msg_); \
      lua_settop(L, 0); \
    } while (0)

    NO_GUARD_ERROR("return io.open('../data/__klei_probe_missing.txt','r')",
                   "../data/<file> accepted by the guard");
    NO_GUARD_ERROR("return io.open('unsafedata/__klei_probe.png','w')",
                   "flag off: unsafedata/<id> falls back to the normal guard");
    NO_GUARD_ERROR("return io.open('plain_rel.txt','w')",
                   "flag off: plain relative write allowed");

    /* the client turns the byte on directly (0x1401293e0 does the same) */
    L->allowed_unsafedata = 1;
    check(lua_isunsafedataallowed(L) == 1, "lua_isunsafedataallowed reads the byte");
    NO_GUARD_ERROR("return io.open('unsafedata/__klei_probe.png','w')",
                   "flag on: unsafedata/<id>.<ext> write allowed");
    NO_GUARD_ERROR("return io.open('unsafedata/__klei_probe.json','w')",
                   "flag on: .json id allowed");
    {
      int st = run(L, "return io.open('unsafedata/__klei_probe.exe','w')", "=io");
      const char *msg = (st != 0) ? lua_tostring(L, -1) : "";
      check(st != 0 && msg != NULL && strstr(msg, "invalid filepath") != NULL,
            "flag on: bad extension rejected");
      lua_settop(L, 0);
    }
    {
      int st = run(L, "return io.open('plain_rel.txt','w')", "=io");
      const char *msg = (st != 0) ? lua_tostring(L, -1) : "";
      check(st != 0 && msg != NULL && strstr(msg, "invalid filepath") != NULL,
            "flag on: writes outside unsafedata/ rejected");
      lua_settop(L, 0);
    }
    NO_GUARD_ERROR("return io.open('unsafedata/__klei_probe.png','r')",
                   "flag on: reads are not restricted");
    L->allowed_unsafedata = 0;
    check(lua_isunsafedataallowed(L) == 0, "lua_isunsafedataallowed after reset");
    remove("plain_rel.txt");
    remove("unsafedata/__klei_probe.png");
    remove("unsafedata/__klei_probe.json");
  }

  lua_close(L);
  printf(fails ? "RESULT: %d FAILURE(S)\n" : "RESULT: all checks passed\n", fails);
  return fails != 0;
}

/* loadlib.o is excluded from this harness; linit.c only needs the symbol. */
int luaopen_package (lua_State *L) { (void)L; return 0; }
