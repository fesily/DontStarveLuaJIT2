// DontStarveInjector.cpp : Defines the exported functions for the DLL application.
//
#include <spdlog/spdlog.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_NONSTDC_NO_WARNINGS
#include <windows.h>
#include <spdlog/sinks/msvc_sink.h>
#else
#include <pthread.h>
#endif

#include <string>
#include <algorithm>
#include <map>
#include <cstdint>
#include <list>
#include <atomic>


#if USE_LISTENER
#include <frida-gum.h>
#endif

#include "config.hpp"
#include "util/inlinehook.hpp"
#include "LuaModule.hpp"
#include "DontStarveSignature.hpp"
#include "util/platform.hpp"
#include "ctx.hpp"
#include "spdlog/sinks/basic_file_sink.h"
#include "ModuleSections.hpp"
#include "disasm.h"
#include "ScanCtx.hpp"


#if !ONLY_LUA51
#include <lua.hpp>
#endif

using namespace std;

G_NORETURN void showError(const std::string_view &msg) {
#ifdef _WIN32
    MessageBoxA(NULL, msg.data(), "error!", 0);
#else
    spdlog::error("error: {}", msg);
#endif
    std::exit(1);
}

static const char *luajitModuleName =
#ifndef _WIN32
        "lib"
#endif
#if ONLY_LUA51
        "lua51"
#else
        "lua51DS"
#endif
#ifdef _WIN32
    ".dll"
#elif defined(__linux__)
    ".so"
#elif defined(__APPLE__)
    ".dylib"
#endif
;
static module_handler_t hluajitModule;

#include "api_listener.hpp"

#if USE_FAKE_API
extern std::unordered_map<std::string_view, void *> lua_fake_apis;

#include <lua.hpp>
void *GetLuaJitAddress(const char *name)
{
    char buf[64];
    snprintf(buf, 64, "fake_%s", name);
        return lua_fake_apis[name];
}
#else
#define GetLuaJitAddress(name) loadlibproc(hluajitModule, name)
#endif
#pragma region Attach

#if USE_LISTENER
static GumInterceptor *interceptor;
#endif

#if !ONLY_LUA51
enum class LUA_EVENT {
  new_state,
  close_state,
  call_lua_gc,
};

void lua_event_notifyer(LUA_EVENT, lua_State *);
static void *lua_newstate_hooker(void *, void *ud) {
    auto L = luaL_newstate();
    lua_event_notifyer(LUA_EVENT::new_state, L);
    spdlog::info("luaL_newstate:{}", (void *) L);
    return L;
}

static void lua_close_hooker(lua_State* L) {
    lua_event_notifyer(LUA_EVENT::close_state, L);
    spdlog::info("lua_close:{}", (void *) L);
    lua_close(L);
}

static int lua_gc_hooker(lua_State* L, int w, int d) {
    lua_event_notifyer(LUA_EVENT::call_lua_gc, L);
    return lua_gc(L, w, d);
}

#if USE_FAKE_API
extern lua_State *map_handler(lua_State *L);
#endif

void lua_setfield_fake(lua_State *L, int idx, const char *k) {
#if USE_FAKE_API
    L = map_handler(L);
#endif
    if (lua_gettop(L) == 0)
        lua_pushnil(L);
    lua_setfield(L, idx, k);
}

#endif

#if USE_LISTENER
GumInvocationListener *listener;
static gboolean PrintCallCb(const GumExportDetails *details,
                            gpointer user_data)
{
    gum_interceptor_attach(interceptor, (void *)details->address, listener, (void *)details->name);
    return true;
}
#endif

static void *get_luajit_address(const std::string_view &name) {
    void *replacer = GetLuaJitAddress(name.data());
    assert(replacer != nullptr);
#if !ONLY_LUA51
    if (name == "lua_newstate"sv) {
        // TODO 2.1 delete this
        replacer = (void *) &lua_newstate_hooker;
    } else if (name == "lua_setfield"sv) {
        replacer = (void *) &lua_setfield_fake;
    } else if (name == "lua_close"sv) {
        replacer = (void*) &lua_close_hooker;
    } else if (name == "lua_gc"sv) {
        replacer = (void*) &lua_gc_hooker;
    }
#endif
    return replacer;
}

static void voidFunc() {
}

static std::map<std::string, std::string> replace_hook = {
#if !ONLY_LUA51
        {"lua_getinfo", "lua_getinfo_game"}
#endif
        };

static void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports) {
    hluajitModule = loadlib(luajitModuleName);
    if (!hluajitModule) {
        spdlog::error("cannot load luajit: {}", luajitModuleName);
        return;
    }

    std::list<uint8_t *> hookeds;
    for (auto &[name, _]: exports) {
        auto offset = signatures.funcs.at(name).offset;
        auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
        auto replacer = (uint8_t *) get_luajit_address(name);
        if (replace_hook.contains(name)) {
            spdlog::info("ReplaceLuaModule hook {} to {}", name, replace_hook[name]);
            auto replacer1 = (uint8_t *) get_luajit_address(replace_hook[name]);
            if (replacer1)
                replacer = replacer1;
        }
        if (!Hook(target, replacer)) {
            spdlog::error("replace {} failed", name);
            break;
        }
        hookeds.emplace_back(target);
        spdlog::info("replace {}: {} to {}", name, (void *) target, (void *) replacer);
    }

    if (hookeds.size() != exports.size()) {
        for (auto target: hookeds) {
            ResetHook(target);
        }
        spdlog::info("reset all hook");
        return;
    }

#if DEBUG_GETSIZE_PATCH
    // In the game code direct read the internal lua vm sturct offset, will crash here
    if (luaRegisterDebugGetsizeSignature.scan(mainPath.c_str())) {
#if DEBUG_GETSIZE_PATCH == 1
    auto code = std::to_array<uint8_t>(
#ifdef _WIN32
        {0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x90}
#else
        {0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00, 0x90}
#endif
        );
        HookWriteCode((uint8_t *) luaRegisterDebugGetsizeSignature.target_address, code.data(), code.size());
#else
        Hook((uint8_t *)luaRegisterDebugGetsizeSignature.target_address, (uint8_t *)&voidFunc);
#endif
    }
#endif

#if REPLACE_IO
    extern void init_luajit_io(module_handler_t hluajitModule);
    init_luajit_io(hluajitModule);
#endif

    extern void init_luajit_jit_opt(module_handler_t hluajitModule);
    init_luajit_jit_opt(hluajitModule);

#if USE_LISTENER
    listener = (GumInvocationListener *)g_object_new(EXAMPLE_TYPE_LISTENER, NULL);
    gum_module_enumerate_exports(target_module_name, PrintCallCb, NULL);
#endif

#define REPALCE_CONST_STRING_BRANCH_DEV 1
#ifndef NDEBUG
#ifdef REPALCE_CONST_STRING_BRANCH_DEV
#ifdef _WIN32
    function_relocation::ModuleSections moduleMain{};
    using namespace std::literals;

    if (function_relocation::get_module_sections(gum_process_get_main_module()->path, moduleMain)) {
        function_relocation::MemorySignature scaner {"00 72 65 6C 65 61 73 65 00", 1};
        auto str = (char*) scaner.scan(moduleMain.rodata.base_address, moduleMain.rodata.size);
        if (str && "release"sv == (str + 1)) {
            GumPageProtection prot;
            if (gum_memory_query_protection(str, &prot) && gum_try_mprotect(str, 4, GUM_PAGE_RW)) {
                gum_memory_write(str, (const guint8*)"dev", 4);
                gum_try_mprotect(str, 4, prot);
            }
        }
    }
#endif
#endif
#endif

}

#pragma endregion Attach

static bool DontStarveInjectorIsClient = false;
static bool server_is_master() {
    return std::string_view{get_cwd()}.contains("DST_Master");
}
#ifndef DISABLE_TRACY_FUTURE
#include <tracy/TracyC.h>
#include <tracy/Tracy.hpp>
#else
#define ___tracy_emit_frame_mark(...) 0
#define ___tracy_alloc_srcloc_name(...) 0
#define ___tracy_emit_zone_begin_alloc(...) 0
#define ___tracy_emit_zone_end(...) 0
typedef uint32_t TracyCZoneCtx;
#define ZoneScopedN(...) 0
#endif
#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <unistd.h>
#include <fstream>
#endif

static uint64_t get_time_ms() {
#ifdef _WIN32
    uint64_t ticks = __rdtsc();
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    return (ticks / freq.QuadPart) * 1000; // 时钟周期转换为毫秒
#elif defined(__APPLE__)
    // macOS (ARM): 使用 mach_absolute_time 获取高精度时间
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t ticks = mach_absolute_time();
    return (ticks * timebase.numer / timebase.denom) / 1e6; // 纳秒转换为毫秒
#elif defined(__linux__)
    // Linux (ARM): 使用 clock_gettime 获取高精度时间
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1e6; // 秒和纳秒转换为毫秒
#else
    #error "not support"
    return 0;
#endif
}
struct Profiler {
    std::list<TracyCZoneCtx> ctx;
    uint64_t start_time;
    int stack;
    lua_State* L;
};
static thread_local Profiler profiler;
extern void (* lua_gc_func)(void *L, int,int);
static int frame_gc_time = 0;
static bool tracy_active = 0;
extern "C" DONTSTARVEINJECTOR_API int DS_LUAJIT_set_frame_gc_time(int ms) {
    return frame_gc_time = std::min(ms,30);
}
static thread_local std::string thread_name;
static void set_thread_name(uint32_t thread_id, const char* name) {
    thread_name = name;
#ifdef _WIN32
    SetThreadDescription(GetCurrentThread(), std::filesystem::path{thread_name}.c_str());
#elif defined(__linux__)
    pthread_setname_np(pthread_self(), thread_name.c_str());
#else
    pthread_setname_np(thread_name.c_str());
#endif
}

static void repalce_set_thread_name() {
#ifdef _WIN32
    function_relocation::MemorySignature set_thread_name_func{"B9 88 13 6D 40", -0x24};
    if (set_thread_name_func.scan(gum_process_get_main_module()->path)) {
        Hook((uint8_t*)set_thread_name_func.target_address, (uint8_t*)&set_thread_name);
    }
#endif
}

static int64_t hook_profiler_push(void* self, const char* zone, const char* source, int line) {
    using namespace std::literals;
    bool is_connected = tracy_active;
    auto& p = profiler;
    if ("Update"sv == zone) {
        if (frame_gc_time) {
            static struct {
                std::atomic_bool vaild;
                std::mutex mtx;
                std::unordered_map<std::thread::id, int> count_map;
            } thread_id_count;
            if (!thread_id_count.vaild.load(memory_order_relaxed)) {
                auto tid = std::this_thread::get_id();
                std::unique_lock<std::mutex> lock(thread_id_count.mtx);
                auto& count = thread_id_count.count_map[tid];
                lock.unlock();
                count++;
                bool except = false;
                if (count >= 600 && thread_id_count.vaild.compare_exchange_strong(except, true, memory_order_relaxed)){
                    set_thread_name(0, "SimUpdateThread");
                    thread_id_count.vaild.store(true, memory_order_relaxed);
                }
            }

            if (thread_name == "SimUpdateThread"sv)
                p.start_time = get_time_ms();
        }
        if (is_connected)
            ___tracy_emit_frame_mark(0);
    }
    p.stack++;
    if (!is_connected) 
        return 0;
    auto v = ___tracy_alloc_srcloc_name(line, source, strlen(source), 0, 0, zone, strlen(zone), 0);
    if (v) {
        auto k = ___tracy_emit_zone_begin_alloc(v, tracy_active);
        p.ctx.emplace_back(k);
    }
    return 0;
}

static int frame_time = 30;
static float *fps_ptr;
static function_relocation::MemorySignature set_notebook_mode{"F3 0F 11 89 D8 01 00 00", -0x3E};
static void set_notebook_mode_config_hook(void*) {}

static function_relocation::MemorySignature set_notebook_mode_config{"80 B9 D4 01 00 00 00", -0x6};
static bool find_set_notebook_mode_imm() {
    if (!DontStarveInjectorIsClient) {
        if (!set_notebook_mode_config.scan(gum_process_get_main_module()->path)) return false;
            //delete this mode
        Hook((uint8_t*)set_notebook_mode_config.target_address, (uint8_t*)&set_notebook_mode_config_hook);
    }
    if (set_notebook_mode.scan(gum_process_get_main_module()->path)) {
        function_relocation::disasm ds{(uint8_t *) set_notebook_mode.target_address, 256};
        int offset = 0;
        int movss[] = {
                1023969417,// 1/30
                1015580809,// 1/60
                1106247680,// 30.0
                1114636288,// 60.0
        };
        void *addrs[4];
        for (auto &&insn: ds) {
            if (insn.id != X86_INS_MOVSS) continue;
            if (insn.detail->x86.operands[0].type != x86_op_type::X86_OP_REG) continue;
            if (insn.detail->x86.operands[1].type != x86_op_type::X86_OP_MEM) continue;
            if (insn.detail->x86.operands[0].reg != x86_reg::X86_REG_XMM0 && insn.detail->x86.operands[0].reg != x86_reg::X86_REG_XMM1)
                return false;

            auto ptr = (int32_t *) function_relocation::read_operand_rip_mem(insn, insn.detail->x86.operands[1]);
            if (movss[offset] != *ptr) return false;
            addrs[offset] = (float *) insn.address;
            offset++;
            if (offset == 4)
                break;
        }
        GumAddressSpec spec{(void *) set_notebook_mode.target_address, INT_MAX/2};
        float *ptr = (float *) gum_memory_allocate_near(&spec, 256, sizeof(void *), GUM_PAGE_RW);
        if (!ptr) return false;
        auto movss_writer = +[](void* addr, float* target){
            // target = addr + 8 + offset
            auto offset = (int64_t)target - (int64_t)addr - 8;
            gum_mprotect(addr, 16, GUM_PAGE_RWX);
            *(((int32_t *) addr) + 1) = (int32_t)offset;
            gum_mprotect(addr, 16, GUM_PAGE_RX);
        };
        for (size_t i = 0; i < 4; i++) {
            movss_writer(addrs[i], ptr + i);
        }
        fps_ptr = ptr;
        auto new_val = (int*)fps_ptr;
        memcpy(new_val, movss, 4 * sizeof(int));
        return true;
    }
    return false;
}


static float* find_luaupdate_imm(function_relocation::MemorySignature& sign) {
    if (sign.scan(gum_process_get_main_module()->path)) {
        if (!sign.only_one) {
            sign.target_address = sign.targets.front();
            for (auto addr : sign.targets)
            {
                if (sign.target_address != addr)
                    return nullptr;
            }
            
        }
        auto insn = function_relocation::disasm::get_insn((uint8_t *) sign.target_address, 8 + 1);
        if (insn->detail->x86.operands[1].type!= x86_op_type::X86_OP_MEM) return nullptr;
        auto  imm = (int32_t*)function_relocation::read_operand_rip_mem(*insn, insn->detail->x86.operands[1]);
        if (0x3D088889 == *imm) {
            return (float*) imm;
        }
    }
    return nullptr;
}
static std::array<float*, 1> luaupdatefps;
static double* getticktimefps;
static function_relocation::MemorySignature luaupdate{"FF 83 C8 00 00 00 F3 0F 10 35", 6};
static function_relocation::MemorySignature getticktime{"00 00 00 20 11 11 A1 3F", 0};
template<typename T>
static void rdata_writer(T* addr, float val){
    gum_mprotect(addr, 4, GUM_PAGE_RW);
    *addr = val;
    gum_mprotect(addr, 4, GUM_PAGE_READ);
};
static bool DS_LUAJIT_get_logic_fps() {
    getticktime.prot_flag = GUM_PAGE_READ;
    if (getticktime.scan(gum_process_get_main_module()->path)) {
        getticktimefps = (double*)getticktime.target_address;
    } else {
        return false;
    }
    //function_relocation::MemorySignature luaupdate1{"48 8D 43 70", 17};
    //function_relocation::MemorySignature luaupdate2{"B8 89 88 88 88", 4, false};
    luaupdatefps[0] = find_luaupdate_imm(luaupdate);
    return luaupdatefps[0];
}

extern "C" DONTSTARVEINJECTOR_API bool DS_LUAJIT_set_target_fps(int fps, int tt) {
#ifndef _WIN32
    return false;
#endif
    
    static auto target_address = [](){
        return find_set_notebook_mode_imm();
    }();
    if (target_address) {
        float val = 1.0f / (float)fps;
        float val2 = (float)fps;
      
        if (tt & 0b01) {
            fps_ptr[1] = val;
            fps_ptr[3] = val2;
            frame_time = (int)std::min(val, 30.0f);
        }

        if (tt & 0b10) {
            static bool init_flag = DS_LUAJIT_get_logic_fps();
            if (init_flag) {
                rdata_writer(getticktimefps, val);
                rdata_writer(luaupdatefps[0], val);
            }
        }
        return true;
    }
    return false;
}

static int64_t hook_profiler_pop(void* self) {
    auto& p = profiler;
    --p.stack;
    if (p.stack < 0) {
        p.stack = 0;
    } else if (p.stack == 0 && p.start_time) {
        p.start_time = 0;
        auto now = get_time_ms();
        auto left_time = std::min<int>(30 - (now - p.start_time), frame_gc_time);
        now += left_time;
        if (p.L) {
            ZoneScopedN("frame gc");
            auto L = p.L;
            p.L = 0;
            do
            {
                lua_gc_func(L, 5, 0);
            } while (get_time_ms() < now);
        }
    }
    if (!tracy_active)
        return 0;
    if (!profiler.ctx.empty()) {
        auto k = p.ctx.back();
        p.ctx.pop_back();
        ___tracy_emit_zone_end(k);
    }
    return 0;
}

void lua_event_notifyer(LUA_EVENT ev, lua_State * L) {
    switch (ev) {
        case LUA_EVENT::new_state:
            profiler.L = 0;
        case LUA_EVENT::close_state:
            profiler.L = 0;
            break;
        case LUA_EVENT::call_lua_gc:
            profiler.L = profiler.start_time ? L : 0;
            break;
    }
}
//#define profiler_lua_gc 0
#ifdef profiler_lua_gc
namespace Gum {
    struct InvocationListener
    {
      virtual ~InvocationListener () {}
  
      virtual void on_enter (GumInvocationContext * context) = 0;
      virtual void on_leave (GumInvocationContext * context) = 0;
    };
    
    typedef struct _GumInvocationListenerProxy GumInvocationListenerProxy;

    class InvocationListenerProxy
    {
    public:
      InvocationListenerProxy (InvocationListener * listener);
      virtual ~InvocationListenerProxy ();
  
      virtual void on_enter (GumInvocationContext * context);
      virtual void on_leave (GumInvocationContext * context);
  
      GumInvocationListenerProxy * cproxy;
      InvocationListener * listener;
    };

    struct InvocationListenerProfiler: InvocationListener {
        virtual ~InvocationListenerProfiler () {}

        virtual void on_enter (GumInvocationContext * context) {
            hook_profiler_push(0, (const char*)gum_invocation_context_get_listener_function_data(context), "", 0);
        };
        virtual void on_leave (GumInvocationContext * context) {
            hook_profiler_pop(0);
        };
    };

    class InvocationListenerProxy;

    typedef struct _GumInvocationListenerProxyClass GumInvocationListenerProxyClass;

    struct _GumInvocationListenerProxy {
        GObject parent;
        InvocationListenerProxy *proxy;
    };

    struct _GumInvocationListenerProxyClass {
        GObjectClass parent_class;
    };

    static GType gum_invocation_listener_proxy_get_type();
    static void gum_invocation_listener_proxy_iface_init(gpointer g_iface, gpointer iface_data);

    InvocationListenerProxy::InvocationListenerProxy(InvocationListener *listener)
        : cproxy(static_cast<GumInvocationListenerProxy *>(g_object_new(gum_invocation_listener_proxy_get_type(), NULL))),
            listener(listener) {
        cproxy->proxy = this;
    }

    InvocationListenerProxy::~InvocationListenerProxy() {
        g_object_unref(cproxy);
        delete listener;
    }

    void InvocationListenerProxy::on_enter(GumInvocationContext *context) {
        listener->on_enter(context);
    }

    void InvocationListenerProxy::on_leave(GumInvocationContext *context) {
        listener->on_leave(context);
    }

    G_DEFINE_TYPE_EXTENDED(GumInvocationListenerProxy,
                            gum_invocation_listener_proxy,
                            G_TYPE_OBJECT,
                            0,
                            G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER,
                                                    gum_invocation_listener_proxy_iface_init))

    static void
    gum_invocation_listener_proxy_init(GumInvocationListenerProxy *self) {
    }

    static void
    gum_invocation_listener_proxy_finalize(GObject *obj) {
        delete reinterpret_cast<GumInvocationListenerProxy *>(obj)->proxy;

        G_OBJECT_CLASS(gum_invocation_listener_proxy_parent_class)->finalize(obj);
    }

    static void
    gum_invocation_listener_proxy_class_init(GumInvocationListenerProxyClass *klass) {
        G_OBJECT_CLASS(klass)->finalize = gum_invocation_listener_proxy_finalize;
    }

    static void
    gum_invocation_listener_proxy_on_enter(GumInvocationListener *listener,
                                            GumInvocationContext *context) {
        reinterpret_cast<GumInvocationListenerProxy *>(listener)->proxy->on_enter(context);
    }

    static void
    gum_invocation_listener_proxy_on_leave(GumInvocationListener *listener,
                                            GumInvocationContext *context) {
        reinterpret_cast<GumInvocationListenerProxy *>(listener)->proxy->on_leave(context);
    }

    static void
    gum_invocation_listener_proxy_iface_init(gpointer g_iface,
                                                gpointer iface_data) {
        GumInvocationListenerInterface *iface =
                static_cast<GumInvocationListenerInterface *>(g_iface);

        iface->on_enter = gum_invocation_listener_proxy_on_enter;
        iface->on_leave = gum_invocation_listener_proxy_on_leave;
    }
}// namespace Gum
#endif

extern "C" DONTSTARVEINJECTOR_API int DS_LUAJIT_replace_profiler_api() {
    static std::atomic_int replaced = 0;
    if (replaced) return replaced;
#ifdef __linux__
    function_relocation::MemorySignature profiler_push { "41 83 84 24 80 01 00 00 01", -0xF6 };
    function_relocation::MemorySignature profiler_pop { "64 48 8B 1C 25 F8 FF FF FF", -0x15 };
#elif defined(__APPLE__)
    function_relocation::MemorySignature profiler_push { "41 83 84 24 80 01 00 00 01", -0xF6 };
    function_relocation::MemorySignature profiler_pop { "64 48 8B 1C 25 F8 FF FF FF", -0x15 };
    return 0; //TODO
#elif defined(_WIN32) 
    function_relocation::MemorySignature profiler_push {"44 8B 9B 88 02 00 00", -0x175};
    function_relocation::MemorySignature profiler_pop {"81 7F 1C 00 3C 00 00", -0x7D};
#endif

    auto path = gum_process_get_main_module()->path;
    if (profiler_pop.scan(path) && profiler_push.scan(path)) {
        Hook((uint8_t*)profiler_push.target_address, (uint8_t*)hook_profiler_push);
        Hook((uint8_t*)profiler_pop.target_address, (uint8_t*)hook_profiler_pop);
#ifdef profiler_lua_gc
        static auto interceptor = gum_interceptor_obtain();
        static Gum::InvocationListenerProxy linstener{new Gum::InvocationListenerProfiler()};
        gum_interceptor_attach(interceptor, (void *) get_luajit_address("lua_gc"), GUM_INVOCATION_LISTENER (linstener.cproxy), (void*)"lua_gc");
#endif
        replaced = 1;
    }
    return replaced;
}

extern "C" DONTSTARVEINJECTOR_API void DS_LUAJIT_enable_tracy(int en) {
    tracy_active = en;
}
extern "C" DONTSTARVEINJECTOR_API const char* DS_LUAJIT_get_mod_version() {
    return MOD_VERSION;
}
extern "C" DONTSTARVEINJECTOR_API int DS_LUAJIT_update(const char* mod_directory, int tt) {
    if (!mod_directory) return 0;
#ifdef _WIN32
    auto mod_dir = std::filesystem::path{mod_directory};
    if (!std::filesystem::exists(mod_dir)) return 0;
    mod_dir = std::filesystem::absolute(mod_dir);
    auto installer = mod_dir / "install.bat";
    if (!std::filesystem::exists(installer)) return 0;
    std::string cmd = std::format("cmd /C \"{}\" {}", installer.string(), tt == 1? "uninstall" : "");
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcess(NULL, (char*)cmd.c_str(), 0, 0, FALSE, CREATE_NEW_CONSOLE, 0, mod_directory, &si, &pi)) {
        WaitForSingleObject( pi.hProcess, INFINITE);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    #endif
return 0;
}  
template<typename Fn>
auto create_defer(Fn&& fn) {
    auto deleter = [cb = std::forward<Fn>(fn)](void *) {
        cb();
    };
    return std::unique_ptr<void, decltype(deleter)>(nullptr, std::move(deleter));
}


static bool check_crash() {
    if (!getenv("SteamClientLaunch")) {
        return true;
    }
#ifndef NDEBUG
    return true;
#endif// !NDEBUG

    auto rootpath = getExePath().parent_path().parent_path();
    auto unsafedatapath = rootpath / "data" / "unsafedata" / "luajit_crash.json";
    if (std::filesystem::exists(unsafedatapath)) {
        auto fp = fopen(unsafedatapath.string().c_str(),  "r+");
        char buf[32] = {};
        auto len = fread(buf, sizeof(char), 16, fp);
        fclose(fp);
        if (len > 0) {
            return false;
        }
    } 
    auto fp = fopen(unsafedatapath.string().c_str(),  "w");
    fwrite("{1}", 1, 3, fp);
    fclose(fp);
    return true;
}

extern "C" DONTSTARVEINJECTOR_API void Inject(bool isClient) {
    DontStarveInjectorIsClient = isClient;
#ifdef _WIN32
    gum_init();
    spdlog::set_default_logger(std::make_shared<spdlog::logger>("", std::make_shared<spdlog::sinks::msvc_sink_st>()));
#endif
#ifdef __linux__
    const auto log_path = std::format("DontStarveInjector_{}.log", isClient ? "client"s : std::format("server_{}", server_is_master()?"master":"caves"));
    spdlog::default_logger()->sinks().push_back(std::make_shared<spdlog::sinks::basic_file_sink_st>(log_path));
#endif
#if USE_LISTENER
    interceptor = gum_interceptor_obtain();
#endif

    spdlog::set_level(spdlog::level::err);
#ifdef DEBUG
    spdlog::set_level(spdlog::level::trace);
#endif

    if (!check_crash()) {
        spdlog::error("skip inject, find crash content");
        return;
    }

    
    if (!function_relocation::init_ctx()) {
        showError("can't init signature");
        return;
    }
    auto defer = create_defer(&function_relocation::deinit_ctx);

    auto lua51 = loadlib(lua51_name);
    if (!lua51) {
        showError("can't load lua51");
        return;
    }
    auto defer1 = create_defer([lua51]() {
        unloadlib(lua51);
    });
    
    auto mainPath = getExePath().string();
    if (luaModuleSignature.scan(mainPath.c_str()) == 0) {
        spdlog::error("can't find luamodule base address");
        return;
    }
    
    auto res = SignatureUpdater::create_or_update(isClient, luaModuleSignature.target_address);
    if (!res) {
        showError(res.error());
        return;
    }
    auto &val = res.value();
    ReplaceLuaModule(mainPath, val.signatures, val.exports);
#if 0
    RedirectOpenGLEntries();
#endif
#ifdef _WIN32
    repalce_set_thread_name();
#endif
}


#ifndef _WIN32
#include <dlfcn.h>
#include "luajit_config.hpp"

int (*origin)(const char* path);
int chdir_hook(const char* path){
    static bool injector = false;
    if ("../data"sv == path && !injector) {
#ifndef NDEBUG
        while (!gum_process_is_debugger_attached())
        {
            std::this_thread::sleep_for(200ms);
        }
#endif
        auto isClientMode = !getExePath().string().contains("dontstarve_dedicated_server_nullrenderer");
        if (!isClientMode) {
            auto config = luajit_config::read_from_file();
            if (config && config->server_disable_luajit) {
                return origin(path);
            }
        }
        Inject(isClientMode);
        spdlog::default_logger_raw()->flush();
        injector = true;
    }
    return origin(path);
}
__attribute__((constructor)) void init() {
    gum_init_embedded();
    auto path = std::filesystem::path(gum_process_get_main_module()->path).filename().string();
    if (!path.contains("dontstarve")) {
        gum_deinit_embedded();
        return;
    }
    auto api = dlsym(RTLD_DEFAULT, "chdir");
    if (!api) {
        gum_deinit_embedded();
        return;
    }
    auto intercetor = gum_interceptor_obtain();
    gum_interceptor_replace_fast(intercetor, api, (void*)&chdir_hook, (void**)&origin);
}
#endif