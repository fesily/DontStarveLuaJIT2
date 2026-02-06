/*
** $Id: liolib.c,v 2.73.1.4 2010/05/14 15:33:51 roberto Exp $
** Standard I/O (and system) library
** See Copyright Notice in lua.h
*/


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../GameLua.hpp"

#undef LUA_FILEHANDLE
#define LUA_FILEHANDLE "IO2FILE*"

#define IO_INPUT	1
#define IO_OUTPUT	2

/* popen/pclose compatibility */
#ifdef _WIN32
#define lua_popen(L,cmd,mode)	(_popen(cmd,mode))
#define lua_pclose(L,file)		(_pclose(file))
#else
#define lua_popen(L,cmd,mode)	(popen(cmd,mode))
#define lua_pclose(L,file)		(pclose(file))
#endif


static const char *const fnames[] = {"input", "output"};


static int pushresult (GameLuaContext &ctx, lua_State *L, int i, const char *filename) {
  int en = errno;  /* calls to Lua API may change this value */
  if (i) {
    ctx->_lua_pushboolean(L, 1);
    return 1;
  }
  else {
    ctx->_lua_pushnil(L);
    if (filename)
      ctx->_lua_pushfstring(L, "%s: %s", filename, strerror(en));
    else
      ctx->_lua_pushfstring(L, "%s", strerror(en));
    ctx->_lua_pushinteger(L, en);
    return 3;
  }
}


static void fileerror (GameLuaContext &ctx, lua_State *L, int arg, const char *filename) {
  ctx->_lua_pushfstring(L, "%s: %s", filename, strerror(errno));
  ctx->_luaL_argerror(L, arg, ctx->_lua_tostring(L, -1));
}


#define tofilep(ctx, L)	((FILE **)ctx->_luaL_checkudata(L, 1, LUA_FILEHANDLE))


static int io_type (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  void *ud;
  ctx->_luaL_checkany(L, 1);
  ud = ctx->_lua_touserdata(L, 1);
  ctx->_lua_getfield(L, LUA_REGISTRYINDEX, LUA_FILEHANDLE);
  if (ud == NULL || !ctx->_lua_getmetatable(L, 1) || !ctx->_lua_rawequal(L, -2, -1))
    ctx->_lua_pushnil(L);  /* not a file */
  else if (*((FILE **)ud) == NULL)
    ctx->_lua_pushliteral(L, "closed file");
  else
    ctx->_lua_pushliteral(L, "file");
  return 1;
}


static FILE *tofile (GameLuaContext &ctx, lua_State *L) {
  FILE **f = tofilep(ctx, L);
  if (*f == NULL)
    ctx->_luaL_error(L, "attempt to use a closed file");
  return *f;
}



/*
** When creating file handles, always creates a `closed' file handle
** before opening the actual file; so, if there is a memory error, the
** file is not left opened.
*/
static FILE **newfile (GameLuaContext &ctx, lua_State *L) {
  FILE **pf = (FILE **)ctx->_lua_newuserdata(L, sizeof(FILE *));
  *pf = NULL;  /* file handle is currently `closed' */
  ctx->_luaL_getmetatable(L, LUA_FILEHANDLE);
  ctx->_lua_setmetatable(L, -2);
  return pf;
}


/*
** function to (not) close the standard files stdin, stdout, and stderr
*/
static int io_noclose (GameLuaContext &ctx, lua_State *L) {
  ctx->_lua_pushnil(L);
  ctx->_lua_pushliteral(L, "cannot close standard file");
  return 2;
}


/*
** function to close 'popen' files
*/
static int io_pclose (GameLuaContext &ctx, lua_State *L) {
  FILE **p = tofilep(ctx, L);
  int ok = (lua_pclose(L, *p) == 0);
  *p = NULL;
  return pushresult(ctx, L, ok, NULL);
}


/*
** function to close regular files
*/
static int io_fclose (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  FILE **p = tofilep(ctx, L);
  int ok = (fclose(*p) == 0);
  *p = NULL;
  return pushresult(ctx, L, ok, NULL);
}


static int aux_close (GameLuaContext &ctx, lua_State *L) {
  ctx->_lua_getfenv(L, 1);
  ctx->_lua_getfield(L, -1, "__close");
  return (ctx->_lua_tocfunction(L, -1))(L);
}


static int io_close (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  if (ctx->_lua_isnone(L, 1))
    ctx->_lua_rawgeti(L, LUA_ENVIRONINDEX, IO_OUTPUT);
  tofile(ctx, L);  /* make sure argument is a file */
  return aux_close(ctx,L);
}


static int io_gc (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  FILE *f = *tofilep(ctx, L);
  /* ignore closed files */
  if (f != NULL)
    aux_close(ctx, L);
  return 0;
}


static int io_tostring (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  FILE *f = *tofilep(ctx, L);
  if (f == NULL)
    ctx->_lua_pushliteral(L, "file (closed)");
  else
    ctx->_lua_pushfstring(L, "file (%p)", f);
  return 1;
}


static int io_open (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  const char *filename = ctx->_luaL_checkstring(L, 1);
  const char *mode = ctx->_luaL_optstring(L, 2, "r");
  FILE **pf = newfile(ctx, L);
  *pf = fopen(filename, mode);
  return (*pf == NULL) ? pushresult(ctx, L, 0, filename) : 1;
}


/*
** this function has a separated environment, which defines the
** correct __close for 'popen' files
*/
static int io_popen (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  const char *filename = ctx->_luaL_checkstring(L, 1);
  const char *mode = ctx->_luaL_optstring(L, 2, "r");
  FILE **pf = newfile(ctx, L);
  *pf = lua_popen(L, filename, mode);
  return (*pf == NULL) ? pushresult(ctx, L, 0, filename) : 1;
}


static int io_tmpfile (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  FILE **pf = newfile(ctx, L);
  *pf = tmpfile();
  return (*pf == NULL) ? pushresult(ctx, L, 0, NULL) : 1;
}


static FILE *getiofile (GameLuaContext &ctx, lua_State *L, int findex) {
  FILE *f;
  ctx->_lua_rawgeti(L, LUA_ENVIRONINDEX, findex);
  f = *(FILE **)ctx->_lua_touserdata(L, -1);
  if (f == NULL)
    ctx->_luaL_error(L, "standard %s file is closed", fnames[findex - 1]);
  return f;
}


static int g_iofile (GameLuaContext &ctx, lua_State *L, int f, const char *mode) {
  if (!ctx->_lua_isnoneornil(L, 1)) {
    const char *filename = ctx->_lua_tostring(L, 1);
    if (filename) {
      FILE **pf = newfile(ctx, L);
      *pf = fopen(filename, mode);
      if (*pf == NULL)
        fileerror(ctx, L, 1, filename);
    }
    else {
      tofile(ctx, L);  /* check that it's a valid file handle */
      ctx->_lua_pushvalue(L, 1);
    }
    ctx->_lua_rawseti(L, LUA_ENVIRONINDEX, f);
  }
  /* return current value */
  ctx->_lua_rawgeti(L, LUA_ENVIRONINDEX, f);
  return 1;
}


static int io_input (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  return g_iofile(ctx, L, IO_INPUT, "r");
}


static int io_output (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  return g_iofile(ctx, L, IO_OUTPUT, "w");
}


static int io_readline (lua_State *L);


static void aux_lines (GameLuaContext &ctx, lua_State *L, int idx, int toclose) {
  ctx->_lua_pushvalue(L, idx);
  ctx->_lua_pushboolean(L, toclose);  /* close/not close file when finished */
  ctx->_lua_pushcclosure(L, io_readline, 2);
}


static int f_lines (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  tofile(ctx, L);  /* check that it's a valid file handle */
  aux_lines(ctx, L, 1, 0);
  return 1;
}


static int io_lines (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  if (ctx->_lua_isnoneornil(L, 1)) {  /* no arguments? */
    /* will iterate over default input */
    ctx->_lua_rawgeti(L, LUA_ENVIRONINDEX, IO_INPUT);
    return f_lines(L);
  }
  else {
    const char *filename = ctx->_luaL_checkstring(L, 1);
    FILE **pf = newfile(ctx, L);
    *pf = fopen(filename, "r");
    if (*pf == NULL)
      fileerror(ctx, L, 1, filename);
    aux_lines(ctx, L, ctx->_lua_gettop(L), 1);
    return 1;
  }
}


/*
** {======================================================
** READ
** =======================================================
*/


static int read_number (GameLuaContext &ctx, lua_State *L, FILE *f) {
  lua_Number d;
  if (fscanf(f, LUA_NUMBER_SCAN, &d) == 1) {
    ctx->_lua_pushnumber(L, d);
    return 1;
  }
  else {
    ctx->_lua_pushnil(L);  /* "result" to be removed */
    return 0;  /* read fails */
  }
}


static int test_eof (GameLuaContext &ctx, lua_State *L, FILE *f) {
  int c = getc(f);
  ungetc(c, f);
  ctx->_lua_pushlstring(L, NULL, 0);
  return (c != EOF);
}


static int read_line (GameLuaContext &ctx, lua_State *L, FILE *f) {
  luaL_Buffer b;
  ctx->_luaL_buffinit(L, &b);
  for (;;) {
    size_t l;
    char *p = ctx->_luaL_prepbuffer(&b);
    if (fgets(p, LUAL_BUFFERSIZE, f) == NULL) {  /* eof? */
      ctx->_luaL_pushresult(&b);  /* close buffer */
      return (ctx->_lua_objlen(L, -1) > 0);  /* check whether read something */
    }
    l = strlen(p);
    if (l == 0 || p[l-1] != '\n')
      ctx->_luaL_addlstring(&b, p, l);
    else {
      ctx->_luaL_addlstring(&b, p, l - 1);  /* do not include `eol' */
      ctx->_luaL_pushresult(&b);  /* close buffer */
      return 1;  /* read at least an `eol' */
    }
  }
}


static int read_chars (GameLuaContext &ctx, lua_State *L, FILE *f, size_t n) {
  size_t rlen;  /* how much to read */
  size_t nr;  /* number of chars actually read */
  luaL_Buffer b;
  ctx->_luaL_buffinit(L, &b);
  rlen = LUAL_BUFFERSIZE;  /* try to read that much each time */
  do {
    char *p = ctx->_luaL_prepbuffer(&b);
    if (rlen > n) rlen = n;  /* cannot read more than asked */
    nr = fread(p, sizeof(char), rlen, f);
    ctx->_luaL_addlstring(&b, p, nr);
    n -= nr;  /* still have to read `n' chars */
  } while (n > 0 && nr == rlen);  /* until end of count or eof */
  ctx->_luaL_pushresult(&b);  /* close buffer */
  return (n == 0 || ctx->_lua_objlen(L, -1) > 0);
}


static int g_read (GameLuaContext &ctx, lua_State *L, FILE *f, int first) {
  int nargs = ctx->_lua_gettop(L) - 1;
  int success;
  int n;
  clearerr(f);
  if (nargs == 0) {  /* no arguments? */
    success = read_line(ctx, L, f);
    n = first+1;  /* to return 1 result */
  }
  else {  /* ensure stack space for all results and for auxlib's buffer */
    ctx->_luaL_checkstack(L, nargs+LUA_MINSTACK, "too many arguments");
    success = 1;
    for (n = first; nargs-- && success; n++) {
      if (ctx->_lua_type(L, n) == LUA_TNUMBER) {
        size_t l = (size_t)ctx->_lua_tointeger(L, n);
        success = (l == 0) ? test_eof(ctx, L, f) : read_chars(ctx, L, f, l);
      }
      else {
        const char *p = ctx->_lua_tostring(L, n);
        ctx->_luaL_argcheck(L, p && p[0] == '*', n, "invalid option");
        switch (p[1]) {
          case 'n':  /* number */
            success = read_number(ctx, L, f);
            break;
          case 'l':  /* line */
            success = read_line(ctx, L, f);
            break;
          case 'a':  /* file */
            read_chars(ctx, L, f, ~((size_t)0));  /* read MAX_SIZE_T chars */
            success = 1; /* always success */
            break;
          default:
            return ctx->_luaL_argerror(L, n, "invalid format");
        }
      }
    }
  }
  if (ferror(f))
    return pushresult(ctx, L, 0, NULL);
  if (!success) {
    ctx->_lua_pop(L, 1);  /* remove last result */
    ctx->_lua_pushnil(L);  /* push nil instead */
  }
  return n - first;
}


static int io_read (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  return g_read(ctx, L, getiofile(ctx, L, IO_INPUT), 1);
}


static int f_read (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  return g_read(ctx, L, tofile(ctx, L), 2);
}


static int io_readline (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  FILE *f = *(FILE **)ctx->_lua_touserdata(L, lua_upvalueindex(1));
  int sucess;
  if (f == NULL)  /* file is already closed? */
    ctx->_luaL_error(L, "file is already closed");
  sucess = read_line(ctx, L, f);
  if (ferror(f))
    return ctx->_luaL_error(L, "%s", strerror(errno));
  if (sucess) return 1;
  else {  /* EOF */
    if (ctx->_lua_toboolean(L, lua_upvalueindex(2))) {  /* generator created file? */
      ctx->_lua_settop(L, 0);
      ctx->_lua_pushvalue(L, lua_upvalueindex(1));
      aux_close(ctx, L);  /* close it */
    }
    return 0;
  }
}

/* }====================================================== */


static int g_write (GameLuaContext &ctx, lua_State *L, FILE *f, int arg) {
  int nargs = ctx->_lua_gettop(L) - 1;
  int status = 1;
  for (; nargs--; arg++) {
    if (ctx->_lua_type(L, arg) == LUA_TNUMBER) {
      /* optimization: could be done exactly as for strings */
      status = status &&
          fprintf(f, LUA_NUMBER_FMT, ctx->_lua_tonumber(L, arg)) > 0;
    }
    else {
      size_t l;
      const char *s = ctx->_luaL_checklstring(L, arg, &l);
      status = status && (fwrite(s, sizeof(char), l, f) == l);
    }
  }
  return pushresult(ctx, L, status, NULL);
}


static int io_write (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  return g_write(ctx, L, getiofile(ctx, L, IO_OUTPUT), 1);
}


static int f_write (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  return g_write(ctx, L, tofile(ctx, L), 2);
}


static int f_seek (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  static const int mode[] = {SEEK_SET, SEEK_CUR, SEEK_END};
  static const char *const modenames[] = {"set", "cur", "end", NULL};
  FILE *f = tofile(ctx, L);
  int op = ctx->_luaL_checkoption(L, 2, "cur", modenames);
  long offset = (long)ctx->_luaL_optinteger(L, 3, 0);
  op = fseek(f, offset, mode[op]);
  if (op)
    return pushresult(ctx, L, 0, NULL);  /* error */
  else {
    ctx->_lua_pushinteger(L, ftell(f));
    return 1;
  }
}


static int f_setvbuf (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  static const int mode[] = {_IONBF, _IOFBF, _IOLBF};
  static const char *const modenames[] = {"no", "full", "line", NULL};
  FILE *f = tofile(ctx, L);
  int op = ctx->_luaL_checkoption(L, 2, NULL, modenames);
  lua_Integer sz = ctx->_luaL_optinteger(L, 3, LUAL_BUFFERSIZE);
  int res = setvbuf(f, NULL, mode[op], sz);
  return pushresult(ctx, L, res == 0, NULL);
}



static int io_flush (lua_State *L) {
    auto& ctx = GetGameLuaContext();
  return pushresult(ctx, L, fflush(getiofile(ctx, L, IO_OUTPUT)) == 0, NULL);
}


static int f_flush (lua_State *L) {
    auto& ctx = GetGameLuaContext();
  return pushresult(ctx, L, fflush(tofile(ctx, L)) == 0, NULL);
}


static const luaL_Reg iolib[] = {
  {"close", io_close},
  {"flush", io_flush},
  {"input", io_input},
  {"lines", io_lines},
  {"open", io_open},
  {"output", io_output},
  {"popen", io_popen},
  {"read", io_read},
  {"tmpfile", io_tmpfile},
  {"type", io_type},
  {"write", io_write},
  {NULL, NULL}
};


static const luaL_Reg flib[] = {
  {"close", io_close},
  {"flush", f_flush},
  {"lines", f_lines},
  {"read", f_read},
  {"seek", f_seek},
  {"setvbuf", f_setvbuf},
  {"write", f_write},
  {"__gc", io_gc},
  {"__tostring", io_tostring},
  {NULL, NULL}
};


static void createmeta (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  ctx->_luaL_newmetatable(L, LUA_FILEHANDLE);  /* create metatable for file handles */
  ctx->_lua_pushvalue(L, -1);  /* push metatable */
  ctx->_lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
  ctx->_luaL_register(L, NULL, flib);  /* file methods */
}


static void createstdfile (lua_State *L, FILE *f, int k, const char *fname) {
  auto &ctx = GetGameLuaContext();
  *newfile(ctx, L) = f;
  if (k > 0) {
    ctx->_lua_pushvalue(L, -1);
    ctx->_lua_rawseti(L, LUA_ENVIRONINDEX, k);
  }
  ctx->_lua_pushvalue(L, -2);  /* copy environment */
  ctx->_lua_setfenv(L, -2);  /* set it */
  ctx->_lua_setfield(L, -3, fname);
}


static void newfenv (lua_State *L, lua_CFunction cls) {
  auto &ctx = GetGameLuaContext();
  ctx->_lua_createtable(L, 0, 1);
  ctx->_lua_pushcfunction(L, cls);
  ctx->_lua_setfield(L, -2, "__close");
}


int luaopen_io2 (lua_State *L) {
  auto &ctx = GetGameLuaContext();
  createmeta(L);
  newfenv(L, io_fclose);
  ctx->_lua_replace(L, LUA_ENVIRONINDEX);
  /* open library */
  ctx->_luaL_register(L, "io2", iolib);
  return 1;
}

