extern "C" {
#include "../../lua51/src/lstate.h"
#include "../../lua51/src/ldebug.h"
}

void lua51_setallocf(lua_State *L, lua_Alloc f, void *ud) {
    G(L)->ud = ud;
    G(L)->frealloc = f;
}
lua_Alloc lua51_getallocf(lua_State *L, void **ud) {
    if (ud) *ud = G(L)->ud;
    return G(L)->frealloc;
}
int lua51_sethook(lua_State *L, lua_Hook func, int mask, int count) {
    if (func == NULL || mask == 0) { /* turn off hooks? */
        mask = 0;
        func = NULL;
    }
    L->hook = func;
    L->basehookcount = count;
    resethookcount(L);
    L->hookmask = cast_byte(mask);
    return 1;
}
int lua51_gethookcount(lua_State *L) {
    return L->basehookcount;
}


static int currentpc(lua_State *L, CallInfo *ci) {
    if (!isLua(ci)) return -1; /* function is not a Lua function? */
    if (ci == L->ci)
        ci->savedpc = L->savedpc;
    return pcRel(ci->savedpc, ci_func(ci)->l.p);
}

static Proto *getluaproto(CallInfo *ci) {
    return (isLua(ci) ? ci_func(ci)->l.p : NULL);
}
#define api_incr_top(L)                    \
    {                                      \
        api_check(L, L->top < L->ci->top); \
        L->top++;                          \
    }

void luaA_pushobject(lua_State *L, const TValue *o) {
    setobj2s(L, L->top, o);
    api_incr_top(L);
}
/*
** Look for n-th local variable at line `line' in function `func'.
** Returns NULL if not found.
*/
const char *luaF_getlocalname(const Proto *f, int local_number, int pc) {
    int i;
    for (i = 0; i < f->sizelocvars && f->locvars[i].startpc <= pc; i++) {
        if (pc < f->locvars[i].endpc) { /* is variable active? */
            local_number--;
            if (local_number == 0)
                return getstr(f->locvars[i].varname);
        }
    }
    return NULL; /* not found */
}


static const char *findlocal(lua_State *L, CallInfo *ci, int n) {
    const char *name;
    Proto *fp = getluaproto(ci);
    if (fp && (name = luaF_getlocalname(fp, n, currentpc(L, ci))) != NULL)
        return name; /* is a local variable in a Lua function */
    else {
        StkId limit = (ci == L->ci) ? L->top : (ci + 1)->func;
        if (limit - ci->base >= n && n > 0) /* is 'n' inside 'ci' stack? */
            return "(*temporary)";
        else
            return NULL;
    }
}

const char *lua51_getlocal(lua_State *L, const lua_Debug *ar, int n) {
    CallInfo *ci = L->base_ci + ar->i_ci;
    const char *name = findlocal(L, ci, n);
    lua_lock(L);
    if (name)
        luaA_pushobject(L, ci->base + (n - 1));
    lua_unlock(L);
    return name;
}

const char *lua51_setlocal(lua_State *L, const lua_Debug *ar, int n) {
    CallInfo *ci = L->base_ci + ar->i_ci;
    const char *name = findlocal(L, ci, n);
    lua_lock(L);
    if (name)
        setobjs2s(L, ci->base + (n - 1), L->top - 1);
    L->top--; /* pop value */
    lua_unlock(L);
    return name;
}
