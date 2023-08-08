
#pragma once
#pragma once
#pragma once
#pragma region Input Buffer SAL 1 compatibility macros
#pragma endregion Input Buffer SAL 1 compatibility macros
#pragma once
#pragma once
#pragma pack(push, 8)
#pragma warning(push)
#pragma warning(disable:   4514 4820 )
        typedef unsigned int uintptr_t;
        typedef char* va_list;
#pragma warning(pop)
#pragma pack(pop)
#pragma warning(push)
#pragma warning(disable:   4514 4820 )
__pragma(pack(push, 8))
    typedef unsigned int     size_t;
    typedef int              ptrdiff_t;
    typedef int              intptr_t;
    typedef _Bool __vcrt_bool;
    typedef unsigned short wchar_t;
    void __cdecl __security_init_cookie(void);
        void __fastcall __security_check_cookie(  uintptr_t _StackCookie);
        __declspec(noreturn) void __cdecl __report_gsfailure(void);
extern uintptr_t __security_cookie;
__pragma(pack(pop))
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable:   4514 4820 )
__pragma(pack(push, 8))
__pragma(pack(pop))
#pragma warning(pop)
#pragma once
#pragma once
#pragma warning(push)
#pragma warning(disable: 4324  4514 4574 4710 4793 4820 4995 4996 28719 28726 28727 )
__pragma(pack(push, 8))
    typedef _Bool __crt_bool;
 void __cdecl _invalid_parameter_noinfo(void);
 __declspec(noreturn) void __cdecl _invalid_parameter_noinfo_noreturn(void);
__declspec(noreturn)
 void __cdecl _invoke_watson(
      wchar_t const* _Expression,
      wchar_t const* _FunctionName,
      wchar_t const* _FileName,
            unsigned int _LineNo,
            uintptr_t _Reserved);
typedef int                           errno_t;
typedef unsigned short                wint_t;
typedef unsigned short                wctype_t;
typedef long                          __time32_t;
typedef __int64                       __time64_t;
typedef struct __crt_locale_data_public
{
      unsigned short const* _locale_pctype;
      int _locale_mb_cur_max;
               unsigned int _locale_lc_codepage;
} __crt_locale_data_public;
typedef struct __crt_locale_pointers
{
    struct __crt_locale_data*    locinfo;
    struct __crt_multibyte_data* mbcinfo;
} __crt_locale_pointers;
typedef __crt_locale_pointers* _locale_t;
typedef struct _Mbstatet
{
    unsigned long _Wchar;
    unsigned short _Byte, _State;
} _Mbstatet;
typedef _Mbstatet mbstate_t;
        typedef __time64_t time_t;
    typedef size_t rsize_t;
__pragma(pack(pop))
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable: 4324  4514 4574 4710 4793 4820 4995 4996 28719 28726 28727 )
__pragma(pack(push, 8))
     int* __cdecl _errno(void);
     errno_t __cdecl _set_errno(  int _Value);
     errno_t __cdecl _get_errno(  int* _Value);
 extern unsigned long  __cdecl __threadid(void);
 extern uintptr_t __cdecl __threadhandle(void);
__pragma(pack(pop))
#pragma warning(pop)
#pragma once
#pragma warning(push)
#pragma warning(disable:   4514 4820 )
__pragma(pack(push, 8))
__pragma(pack(pop))
#pragma warning(pop)
typedef struct lua_State lua_State;
typedef int (*lua_CFunction) (lua_State *L);
typedef const char * (*lua_Reader) (lua_State *L, void *ud, size_t *sz);
typedef int (*lua_Writer) (lua_State *L, const void* p, size_t sz, void* ud);
typedef void * (*lua_Alloc) (void *ud, void *ptr, size_t osize, size_t nsize);
typedef double lua_Number;
typedef ptrdiff_t lua_Integer;
extern lua_State *(lua_newstate) (lua_Alloc f, void *ud);
extern void       (lua_close) (lua_State *L);
extern lua_State *(lua_newthread) (lua_State *L);
extern lua_CFunction (lua_atpanic) (lua_State *L, lua_CFunction panicf);
extern int   (lua_gettop) (lua_State *L);
extern void  (lua_settop) (lua_State *L, int idx);
extern void  (lua_pushvalue) (lua_State *L, int idx);
extern void  (lua_remove) (lua_State *L, int idx);
extern void  (lua_insert) (lua_State *L, int idx);
extern void  (lua_replace) (lua_State *L, int idx);
extern int   (lua_checkstack) (lua_State *L, int sz);
extern void  (lua_xmove) (lua_State *from, lua_State *to, int n);
extern int             (lua_isnumber) (lua_State *L, int idx);
extern int             (lua_isstring) (lua_State *L, int idx);
extern int             (lua_iscfunction) (lua_State *L, int idx);
extern int             (lua_isuserdata) (lua_State *L, int idx);
extern int             (lua_type) (lua_State *L, int idx);
extern const char     *(lua_typename) (lua_State *L, int tp);
extern int            (lua_equal) (lua_State *L, int idx1, int idx2);
extern int            (lua_rawequal) (lua_State *L, int idx1, int idx2);
extern int            (lua_lessthan) (lua_State *L, int idx1, int idx2);
extern lua_Number      (lua_tonumber) (lua_State *L, int idx);
extern lua_Integer     (lua_tointeger) (lua_State *L, int idx);
extern int             (lua_toboolean) (lua_State *L, int idx);
extern const char     *(lua_tolstring) (lua_State *L, int idx, size_t *len);
extern size_t          (lua_objlen) (lua_State *L, int idx);
extern lua_CFunction   (lua_tocfunction) (lua_State *L, int idx);
extern void	       *(lua_touserdata) (lua_State *L, int idx);
extern lua_State      *(lua_tothread) (lua_State *L, int idx);
extern const void     *(lua_topointer) (lua_State *L, int idx);
extern void  (lua_pushnil) (lua_State *L);
extern void  (lua_pushnumber) (lua_State *L, lua_Number n);
extern void  (lua_pushinteger) (lua_State *L, lua_Integer n);
extern void  (lua_pushlstring) (lua_State *L, const char *s, size_t l);
extern void  (lua_pushstring) (lua_State *L, const char *s);
extern const char *(lua_pushvfstring) (lua_State *L, const char *fmt,
                                                      va_list argp);
extern const char *(lua_pushfstring) (lua_State *L, const char *fmt, ...);
extern void  (lua_pushcclosure) (lua_State *L, lua_CFunction fn, int n);
extern void  (lua_pushboolean) (lua_State *L, int b);
extern void  (lua_pushlightuserdata) (lua_State *L, void *p);
extern int   (lua_pushthread) (lua_State *L);
extern void  (lua_gettable) (lua_State *L, int idx);
extern void  (lua_getfield) (lua_State *L, int idx, const char *k);
extern void  (lua_rawget) (lua_State *L, int idx);
extern void  (lua_rawgeti) (lua_State *L, int idx, int n);
extern void  (lua_createtable) (lua_State *L, int narr, int nrec);
extern void *(lua_newuserdata) (lua_State *L, size_t sz);
extern int   (lua_getmetatable) (lua_State *L, int objindex);
extern void  (lua_getfenv) (lua_State *L, int idx);
extern void  (lua_settable) (lua_State *L, int idx);
extern void  (lua_setfield) (lua_State *L, int idx, const char *k);
extern void  (lua_rawset) (lua_State *L, int idx);
extern void  (lua_rawseti) (lua_State *L, int idx, int n);
extern int   (lua_setmetatable) (lua_State *L, int objindex);
extern int   (lua_setfenv) (lua_State *L, int idx);
extern void  (lua_call) (lua_State *L, int nargs, int nresults);
extern int   (lua_pcall) (lua_State *L, int nargs, int nresults, int errfunc);
extern int   (lua_cpcall) (lua_State *L, lua_CFunction func, void *ud);
extern int   (lua_load) (lua_State *L, lua_Reader reader, void *dt,
                                        const char *chunkname);
extern int (lua_dump) (lua_State *L, lua_Writer writer, void *data);
extern int  (lua_yield) (lua_State *L, int nresults);
extern int  (lua_resume) (lua_State *L, int narg);
extern int  (lua_status) (lua_State *L);
extern int (lua_gc) (lua_State *L, int what, int data);
extern int   (lua_error) (lua_State *L);
extern int   (lua_next) (lua_State *L, int idx);
extern void  (lua_concat) (lua_State *L, int n);
extern lua_Alloc (lua_getallocf) (lua_State *L, void **ud);
extern void lua_setallocf (lua_State *L, lua_Alloc f, void *ud);
extern void lua_setlevel	(lua_State *from, lua_State *to);
typedef struct lua_Debug lua_Debug;
typedef void (*lua_Hook) (lua_State *L, lua_Debug *ar);
extern int lua_getstack (lua_State *L, int level, lua_Debug *ar);
extern int lua_getinfo (lua_State *L, const char *what, lua_Debug *ar);
extern const char *lua_getlocal (lua_State *L, const lua_Debug *ar, int n);
extern const char *lua_setlocal (lua_State *L, const lua_Debug *ar, int n);
extern const char *lua_getupvalue (lua_State *L, int funcindex, int n);
extern const char *lua_setupvalue (lua_State *L, int funcindex, int n);
extern int lua_sethook (lua_State *L, lua_Hook func, int mask, int count);
extern lua_Hook lua_gethook (lua_State *L);
extern int lua_gethookmask (lua_State *L);
extern int lua_gethookcount (lua_State *L);
struct lua_Debug {
  int event;
  const char *name;
  const char *namewhat;
  const char *what;
  const char *source;
  int currentline;
  int nups;
  int linedefined;
  int lastlinedefined;
  char short_src[60];
  int i_ci;
};
typedef unsigned int lu_int32;
typedef size_t lu_mem;
typedef ptrdiff_t l_mem;
typedef unsigned char lu_byte;
typedef union { double u; void *s; long l; } L_Umaxalign;
typedef double l_uacNumber;
typedef lu_int32 Instruction;
typedef union GCObject GCObject;
typedef struct GCheader {
  GCObject *next; lu_byte tt; lu_byte marked;
} GCheader;
typedef union {
  GCObject *gc;
  void *p;
  lua_Number n;
  int b;
} Value;
typedef struct lua_TValue {
  Value value; int tt;
} TValue;
typedef TValue *StkId;
typedef union TString {
  L_Umaxalign dummy;
  struct {
    GCObject *next; lu_byte tt; lu_byte marked;
    lu_byte reserved;
    unsigned int hash;
    size_t len;
  } tsv;
} TString;
typedef union Udata {
  L_Umaxalign dummy;
  struct {
    GCObject *next; lu_byte tt; lu_byte marked;
    struct Table *metatable;
    struct Table *env;
    size_t len;
  } uv;
} Udata;
typedef struct Proto {
  GCObject *next; lu_byte tt; lu_byte marked;
  TValue *k;
  Instruction *code;
  struct Proto **p;
  int *lineinfo;
  struct LocVar *locvars;
  TString **upvalues;
  TString  *source;
  int sizeupvalues;
  int sizek;
  int sizecode;
  int sizelineinfo;
  int sizep;
  int sizelocvars;
  int linedefined;
  int lastlinedefined;
  GCObject *gclist;
  lu_byte nups;
  lu_byte numparams;
  lu_byte is_vararg;
  lu_byte maxstacksize;
} Proto;
typedef struct LocVar {
  TString *varname;
  int startpc;
  int endpc;
} LocVar;
typedef struct UpVal {
  GCObject *next; lu_byte tt; lu_byte marked;
  TValue *v;
  union {
    TValue value;
    struct {
      struct UpVal *prev;
      struct UpVal *next;
    } l;
  } u;
} UpVal;
typedef struct CClosure {
  GCObject *next; lu_byte tt; lu_byte marked; lu_byte isC; lu_byte nupvalues; GCObject *gclist; struct Table *env;
  lua_CFunction f;
  TValue upvalue[1];
} CClosure;
typedef struct LClosure {
  GCObject *next; lu_byte tt; lu_byte marked; lu_byte isC; lu_byte nupvalues; GCObject *gclist; struct Table *env;
  struct Proto *p;
  UpVal *upvals[1];
} LClosure;
typedef union Closure {
  CClosure c;
  LClosure l;
} Closure;
typedef union TKey {
  struct {
    Value value; int tt;
    struct Node *next;
  } nk;
  TValue tvk;
} TKey;
typedef struct Node {
  TValue i_val;
  TKey i_key;
} Node;
typedef struct Table {
  GCObject *next; lu_byte tt; lu_byte marked;
  lu_byte flags;
  lu_byte lsizenode;
  struct Table *metatable;
  TValue *array;
  Node *node;
  Node *lastfree;
  GCObject *gclist;
  int sizearray;
} Table;
extern const TValue luaO_nilobject_;
extern int luaO_log2 (unsigned int x);
extern int luaO_int2fb (unsigned int x);
extern int luaO_fb2int (int x);
extern int luaO_rawequalObj (const TValue *t1, const TValue *t2);
extern int luaO_str2d (const char *s, lua_Number *result);
extern const char *luaO_pushvfstring (lua_State *L, const char *fmt,
                                                       va_list argp);
extern const char *luaO_pushfstring (lua_State *L, const char *fmt, ...);
extern void luaO_chunkid (char *out, const char *source, size_t len);
typedef enum {
  TM_INDEX,
  TM_NEWINDEX,
  TM_GC,
  TM_MODE,
  TM_EQ,
  TM_ADD,
  TM_SUB,
  TM_MUL,
  TM_DIV,
  TM_MOD,
  TM_POW,
  TM_UNM,
  TM_LEN,
  TM_LT,
  TM_LE,
  TM_CONCAT,
  TM_CALL,
  TM_N
} TMS;
extern const char *const luaT_typenames[];
extern const TValue *luaT_gettm (Table *events, TMS event, TString *ename);
extern const TValue *luaT_gettmbyobj (lua_State *L, const TValue *o,
                                                       TMS event);
extern void luaT_init (lua_State *L);
extern void *luaM_realloc_ (lua_State *L, void *block, size_t oldsize,
                                                          size_t size);
extern void *luaM_toobig (lua_State *L);
extern void *luaM_growaux_ (lua_State *L, void *block, int *size,
                               size_t size_elem, int limit,
                               const char *errormsg);
typedef struct Zio ZIO;
typedef struct Mbuffer {
  char *buffer;
  size_t n;
  size_t buffsize;
} Mbuffer;
extern char *luaZ_openspace (lua_State *L, Mbuffer *buff, size_t n);
extern void luaZ_init (lua_State *L, ZIO *z, lua_Reader reader,
                                        void *data);
extern size_t luaZ_read (ZIO* z, void* b, size_t n);
extern int luaZ_lookahead (ZIO *z);
struct Zio {
  size_t n;
  const char *p;
  lua_Reader reader;
  void* data;
  lua_State *L;
};
extern int luaZ_fill (ZIO *z);
struct lua_longjmp;
typedef struct stringtable {
  GCObject **hash;
  lu_int32 nuse;
  int size;
} stringtable;
typedef struct CallInfo {
  StkId base;
  StkId func;
  StkId	top;
  const Instruction *savedpc;
  int nresults;
  int tailcalls;
} CallInfo;
typedef struct global_State {
  stringtable strt;
  lua_Alloc frealloc;
  void *ud;
  lu_byte currentwhite;
  lu_byte gcstate;
  int sweepstrgc;
  GCObject *rootgc;
  GCObject **sweepgc;
  GCObject *gray;
  GCObject *grayagain;
  GCObject *weak;
  GCObject *tmudata;
  Mbuffer buff;
  lu_mem GCthreshold;
  lu_mem totalbytes;
  lu_mem estimate;
  lu_mem gcdept;
  int gcpause;
  int gcstepmul;
  lua_CFunction panic;
  TValue l_registry;
  struct lua_State *mainthread;
  UpVal uvhead;
  struct Table *mt[(8+1)];
  TString *tmname[TM_N];
} global_State;
struct lua_State {
  GCObject *next; lu_byte tt; lu_byte marked;
  lu_byte status;
  StkId top;
  StkId base;
  global_State *l_G;
  CallInfo *ci;
  const Instruction *savedpc;
  StkId stack_last;
  StkId stack;
  CallInfo *end_ci;
  CallInfo *base_ci;
  int stacksize;
  int size_ci;
  unsigned short nCcalls;
  unsigned short baseCcalls;
  lu_byte hookmask;
  lu_byte allowhook;
  int basehookcount;
  int hookcount;
  lua_Hook hook;
  TValue l_gt;
  TValue env;
  GCObject *openupval;
  GCObject *gclist;
  struct lua_longjmp *errorJmp;
  ptrdiff_t errfunc;
  char reserved[8];
  void* __unknown;
};
union GCObject {
  GCheader gch;
  union TString ts;
  union Udata u;
  union Closure cl;
  struct Table h;
  struct Proto p;
  struct UpVal uv;
  struct lua_State th;
};
extern lua_State *luaE_newthread (lua_State *L);
extern void luaE_freethread (lua_State *L, lua_State *L1);
