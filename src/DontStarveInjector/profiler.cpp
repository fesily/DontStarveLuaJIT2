#pragma once

#include <frida-gum.h>

#ifdef _WIN32
#define NOMINMAX 1
#include <windows.h>
#else
#include <signal.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <format>
#include <map>
#include <string>
#include <string_view>
extern "C" {
#include <lj_ctype.h>
#include <lj_debug.h>
#include <lj_frame.h>
#include <lj_gc.h>
#include <lj_obj.h>
#include <lj_state.h>
#include <lj_trace.h>
#include <lua.h>
}
#ifndef DISABLE_TRACY_FUTURE
#include <tracy/TracyLua.hpp>
#endif
#include "config.hpp"
#include "profiler.hpp"
#include <list>
#include <mimalloc-new-delete.h>


namespace luajit {
    using namespace std::literals;
    // GC 类型 (uint8_t 类型，用于 gct 字段)
    const uint8_t TSTR = 4;
    const uint8_t TUPVAL = 5;
    const uint8_t TTHREAD = 6;
    const uint8_t TPROTO = 7;
    const uint8_t TFUNC = 8;
    const uint8_t TTRACE = 9;
    const uint8_t TCDATA = 10;
    const uint8_t TTAB = 11;
    const uint8_t TUDATA = 12;
    // 其他常量
    const uint32_t NO_BCPOS = ~0U;

    // 结构体大小（使用 sizeof 直接计算）
    const size_t sizeof_GCtab = sizeof(GCtab);
    const size_t sizeof_TValue = sizeof(TValue);
    const size_t sizeof_lua_State = sizeof(lua_State);
    const size_t sizeof_GCfunc = sizeof(GCfunc);
    const size_t sizeof_GCupval = sizeof(GCupval);
    const size_t sizeof_GCstr = sizeof(GCstr);
    const size_t sizeof_GCudata = sizeof(GCudata);
    const size_t sizeof_Node = sizeof(Node);
    const size_t sizeof_GCfuncC = sizeof(GCfuncC);
    const size_t sizeof_GCfuncL = sizeof(GCfuncL);
    const size_t sizeof_GCRef = sizeof(GCRef);
    const size_t sizeof_GCproto = sizeof(GCproto);
    const size_t sizeof_GCtrace = sizeof(GCtrace);
    const size_t sizeof_GCcdata = sizeof(GCcdata);
    const size_t sizeof_IRIns = sizeof(IRIns);
    const size_t sizeof_IRRef = sizeof(IRRef);
    const size_t sizeof_SnapShot = sizeof(SnapShot);
    const size_t sizeof_SnapEntry = sizeof(SnapEntry);
    const size_t sizeof_GCcdataVar = sizeof(GCcdataVar);
    const size_t sizeof_BCIns = sizeof(BCIns);
    // 全局变量
    static std::map<void *, std::string> luajit_cfunc_cache;

    // 函数实现
    GCfunc *luajit_frame_func(TValue *f) {
        GCobj *gco = frame_gc(f);
        return &gco->fn;
    }

    global_State *luajit_G(lua_State *L) {
        return reinterpret_cast<global_State *>(L->glref.ptr64);
    }

    GCobj *luajit_gcref(GCRef *r) {
        return gcref(*r);
    }

    size_t luajit_objlen(GCobj *o, uint8_t gct, global_State *g) {
        switch (gct) {
            case TSTR:
                return o->str.len + 1 + sizeof_GCstr;

            case TTAB: {
                GCtab *t = &o->tab;
                uint32_t asize = t->asize;
                uint32_t hmask = t->hmask;
                size_t n = 0;
                if (hmask > 0) {
                    n += sizeof_Node * (hmask + 1);
                }
                if (asize > 0 && t->colo <= 0) {
                    n += sizeof_TValue * asize;
                }
                if (t->colo) {
                    n += (t->colo & 0x7f) * sizeof_TValue + sizeof_GCtab;
                } else {
                    n += sizeof_GCtab;
                }
                return n;
            }

            case TUDATA:
                return o->ud.len + sizeof_GCudata;

            case TPROTO:
                return o->pt.sizept;

            case TTHREAD: {
                lua_State *L = &o->th;
                size_t n = sizeof_lua_State + L->stacksize * sizeof_TValue;
                GCRef *p = &L->openupval;
                while (p->gcptr64 != 0) {
                    GCobj *upval = luajit_gcref(p);
                    if (!upval) break;
                    uint8_t upval_gct = upval->gch.gct;
                    n += luajit_objlen(upval, upval_gct, g);
                    p = &upval->gch.nextgc;
                }
                return n;
            }

            case TFUNC: {
                GCfunc *fn = &o->fn;
                if (isluafunc(fn)) {
                    uint32_t n = fn->l.nupvalues;
                    return sizeof_GCfuncL - sizeof_GCRef + sizeof_GCRef * n;
                } else {
                    uint32_t n = fn->c.nupvalues;
                    return sizeof_GCfuncC - sizeof_TValue + sizeof_TValue * n;
                }
            }

            case TUPVAL:
                return sizeof_GCupval;

            case TTRACE: {
                GCtrace *T = gco2trace(o);
                return ((sizeof_GCtrace + 7) & ~7) +
                       (T->nins - T->nk) * sizeof_IRIns +
                       T->nsnap * sizeof_SnapShot +
                       T->nsnapmap * sizeof_SnapEntry;
            }

            case TCDATA: {
                GCcdata *cd = &o->cd;
                if (cd->marked & 0x80) {// 向量类型
                    GCcdataVar *cdatav = reinterpret_cast<GCcdataVar *>(
                            reinterpret_cast<char *>(cd) - sizeof_GCcdataVar);
                    return cdatav->len + cdatav->extra;
                }
                CTState *cts = reinterpret_cast<CTState *>(g->ctype_state.ptr64);
                uint32_t id = cd->ctypeid;
                CType *ct = &cts->tab[id];
                while ((ct->info >> CTSHIFT_NUM) == CT_ATTRIB) {
                    ct = &cts->tab[ct->info & CTMASK_CID];
                }
                size_t sz = ((ct->info >> CTSHIFT_NUM) <= CT_HASSIZE) ? ct->size : sizeof(void *);
                return sizeof_GCcdata + sz;
            }

            default:
                return 0;
        }
    }

    size_t luajit_jit_state_size(jit_State *J) {
        size_t sizesnapmap = J->sizesnapmap * sizeof_SnapEntry;
        size_t sizesnap = J->sizesnap * sizeof_SnapShot;
        size_t sizeirbuf = (J->irtoplim - J->irbotlim) * sizeof_IRIns;
        size_t sizetrace = J->sizetrace * sizeof_GCRef;
        return sizesnapmap + sizesnap + sizeirbuf + sizetrace;// 忽略 ir_k64_size
    }

    TValue *luajit_index2adr(lua_State *L, int idx) {
        if (idx > 0) {
            TValue *o = L->base + (idx - 1);
            return (o < L->top) ? o : nullptr;
        }
        if (idx != 0 && -idx <= (L->top - L->base)) {
            return L->top + idx;
        }
        return nullptr;
    }

    std::string_view luajit_unbox_gcstr(GCstr *gcs) {
        if (!gcs) return ""sv;
        const char *src = strdata(gcs);
        return {src, gcs->len};
    }

    std::string_view luajit_tostring(lua_State *L, int idx) {
        TValue *o = luajit_index2adr(L, idx);
        if (!o) return "<nil>"sv;
        if (o->it == LJ_TSTR) {
            GCobj *gco = luajit_gcref(&o->gcr);
            return luajit_unbox_gcstr(&gco->str);
        }
        return "<unknown>"sv;
    }

    int luajit_tostringlen(lua_State *L, int idx) {
        TValue *o = luajit_index2adr(L, idx);
        if (!o) return -1;
        if (o->it == LJ_TSTR) {
            GCobj *gco = luajit_gcref(&o->gcr);
            return gco->str.len;
        }
        return -1;
    }

    void *luajit_touserdata(lua_State *L, int idx) {
        TValue *o = luajit_index2adr(L, idx);
        if (!o) return nullptr;
        if (o->it == LJ_TUDATA) {
            GCobj *gco = luajit_gcref(&o->gcr);
            return reinterpret_cast<char *>(&gco->ud) + sizeof_GCudata;
        }
        if (o->it == LJ_TLIGHTUD) {
            return reinterpret_cast<void *>(o->u64 & 0x7fffffffffffULL);
        }
        return nullptr;
    }

    uint32_t luajit_debug_framepc(lua_State *L, const GCtrace *T, GCproto *pt, TValue *nextframe) {
        const BCIns *ins;
        if (!nextframe) {
            void *cf = cframe_raw(L->cframe);
            if (cf == NULL || (char *) cframe_pc(cf) == (char *) cframe_L(cf))
                return NO_BCPOS;
            ins = cframe_pc(cf); /* Only happens during error/hook handling. */
            if (!ins) return NO_BCPOS;
        } else {
            if (frame_islua(nextframe)) {
                ins = frame_pc(nextframe);
            } else if (frame_iscont(nextframe)) {
                ins = frame_contpc(nextframe);
            } else {
                /* Lua function below errfunc/gc/hook: find cframe to get the PC. */
                void *cf = cframe_raw(L->cframe);
                TValue *f = L->base - 1;
                for (;;) {
                    if (cf == NULL)
                        return NO_BCPOS;
                    while (cframe_nres(cf) < 0) {
                        if (f >= restorestack(L, -cframe_nres(cf)))
                            break;
                        cf = cframe_raw(cframe_prev(cf));
                        if (cf == NULL)
                            return NO_BCPOS;
                    }
                    if (f < nextframe)
                        break;
                    if (frame_islua(f)) {
                        f = frame_prevl(f);
                    } else {
                        if (frame_isc(f) || (frame_iscont(f) && frame_iscont_fficb(f)))
                            cf = cframe_raw(cframe_prev(cf));
                        f = frame_prevd(f);
                    }
                }
                ins = cframe_pc(cf);
                if (!ins) return NO_BCPOS;
            }
        }
        BCPos pos = proto_bcpos(pt, ins) - 1;
        if (pos > pt->sizebc) {
            if (bc_isret(bc_op(ins[-1]))) {
                if (!T)
                    T = (GCtrace *) ((char *) (ins - 1) - offsetof(GCtrace, startins));
                pos = proto_bcpos(pt, mref(T->startpc, const BCIns));
            } else {
                pos = NO_BCPOS; /* Punt in case of stack overflow for stitched trace. */
            }
        }
        return pos;
    }

    int luajit_debug_line(GCproto *pt, uint32_t pc) {
        const void *lineinfo = proto_lineinfo(pt);
        if (pc <= pt->sizebc && lineinfo) {
            int first = pt->firstline;
            if (pc == pt->sizebc) return first + pt->numline;
            if (--pc == 0) return first;
            if (pt->numline < 256) {
                return first + reinterpret_cast<const uint8_t *>(lineinfo)[pc];
            } else if (pt->numline < 65536) {
                return first + reinterpret_cast<const uint16_t *>(lineinfo)[pc];
            } else {
                return first + reinterpret_cast<const uint32_t *>(lineinfo)[pc];
            }
        }
        return -1;
    }

    int luajit_debug_frameline(lua_State *L, GCtrace *T, GCproto *pt, TValue *nextframe) {
        uint32_t pc = luajit_debug_framepc(L, T, pt, nextframe);
        if (pc != NO_BCPOS && pc <= pt->sizebc) {
            return luajit_debug_line(pt, pc);
        }
        return -1;
    }

    template<typename... views>
    char *push_trace(char *insert, int line, const views &...source) {
        memcpy(insert, &line, sizeof(int));
        insert += sizeof(int);
        uint16_t len = 0;
        auto _ = {(len += source.size())...};
        memcpy(insert, &len, sizeof(uint16_t));
        insert += sizeof(uint16_t);
        auto __ = {memcpy(insert, source.data(), len)...};
        insert += len;
        len = 0;
        memcpy(insert, &len, sizeof(uint16_t));
        insert += sizeof(uint16_t);
        return insert;
    }
    template<typename... views>
    inline size_t trace_buffer_size(const views &...source) {
        uint16_t len = 0;
        auto _ = {(len += source.size())...};
        return sizeof(int) + sizeof(uint16_t) * 2 + len;
    }

    struct FrameTrace {
        struct FrameData {
            TValue *nextframe = nullptr;
            union {
                GCproto *pt = nullptr;
                GCfunc *fn;
            } val;
            int tt;
        };
        FrameData frames[64];
        uint8_t offset = 0;
        static_assert(ARRAYSIZE(frames) <= 128, "FrameData array size exceeds limit.");
        GCtrace *trace = nullptr;
        void reset() {
            trace = nullptr;
            offset = 0;
            memset(frames, 0, sizeof(frames));
        }

        FrameData *get_next_frame_data() {
            if (offset >= ARRAYSIZE(frames)) {
                return nullptr;
            }
            return &frames[offset++];
        }

        template<typename Fn>
        void for_each_frame(Fn &&fn) {
            for (int i = 0; i < offset; ++i) {
                fn(trace, frames[i]);
            }
        }
    };
    static FrameTrace luajit_frametrace;


    void luajit_debug_dumpstack(lua_State *L, GCtrace *T, int depth, TValue *base, bool simple) {
        int level = 0;
        int dir = 1;
        if (depth < 0) {
            level = -depth;
            depth = -1;
            dir = -1;
        }
        while (level != depth) {
            TValue *bot = tvref(L->stack) + LJ_FR2;
            TValue *frame = base - 1;
            TValue *nextframe = frame;
            int size = 0;
            int tmp_level = level;
            bool found_frame = false;

            for (; frame > bot; nextframe = frame) {
                if (frame_gc(frame) == obj2gco(L))
                    tmp_level++;
                if (tmp_level-- == 0) {
                    size = (int) (nextframe - frame);
                    found_frame = true;
                    break;
                }
                if (frame_islua(frame)) {
                    frame = frame_prevl(frame);
                } else {
                    if (frame_isvarg(frame)) tmp_level++;
                    frame = frame_prevd(frame);
                }
            }

            if (!found_frame) {
                frame = nullptr;
                size = tmp_level;
            }

            if (frame) {
                nextframe = size ? frame + size : nullptr;
                GCfunc *fn = frame_func(frame);
                if (!fn) return;
                if (!gum_memory_is_readable(fn, sizeof(GCfunc))) return;
                auto frame = luajit_frametrace.get_next_frame_data();
                if (!frame) return;
                frame->nextframe = nextframe;
                if (isluafunc(fn)) {
                    GCproto *pt = funcproto(fn);
                    frame->val.pt = pt;
                    frame->tt = LJ_TPROTO;
                } else {
                    frame->val.fn = fn;
                    frame->tt = LJ_TFUNC;
                }
            } else if (dir == 1) {
                break;
            } else {
                level -= size;
            }
            level += dir;
        }
    }

    lua_State *luajit_cur_thread(global_State *g) {
        GCobj *gco = luajit_gcref(&g->cur_L);
        return gco ? &gco->th : nullptr;
    }

    GCtrace *luajit_get_trace(global_State *g, int traceno) {
        jit_State *J = G2J(g);
        return J ? traceref(J, traceno) : nullptr;
    }

    bool luajit_backtrace(lua_State *L, global_State *g, bool simple) {
        luajit_frametrace.reset();
        int vmstate = g->vmstate;
        TValue *base = nullptr;
        if (vmstate >= 0 || (vmstate == -3 && g->jit_base.ptr64)) {
            GCtrace *T = luajit_get_trace(g, vmstate);
            if (T) {
                luajit_frametrace.trace = T;
                if (simple) {
                    GCobj *gco = luajit_gcref(&T->startpt);
                    if (gco) {
                        GCproto *pt = &gco->pt;
                        auto frame = luajit_frametrace.get_next_frame_data();
                        frame->val.pt = pt;
                        frame->tt = LJ_TTRACE;
                    }
                }
            }
            base = reinterpret_cast<TValue *>(g->jit_base.ptr64);
            if (base) {
                luajit_debug_dumpstack(L, T, 30, base, simple);
            }
        } else {
            if (vmstate == -1 && !L->cframe) return 0;
            if (vmstate == -1 || vmstate == -2 || vmstate == -3) {
                base = L->base;
                luajit_debug_dumpstack(L, nullptr, 30, base, simple);
            }
        }
        return luajit_frametrace.offset > 0;
    }

    int luajit_vm_state(global_State *g) {
        return g->vmstate;
    }

    GCstr *luajit_find_gcstr(global_State *g, const std::string &str) {
        size_t len = str.length();
        uint32_t strmask = g->str.mask;
        uint32_t strnum = g->str.num;
        GCRef *strhash = reinterpret_cast<GCRef *>(g->str.tab);
        int n = 0;
        for (uint32_t i = 0; i <= strmask; ++i) {
            GCRef *p = &strhash[i];
            while (p->gcptr64) {
                GCobj *o = luajit_gcref(p);
                if (!o) break;
                if (o->str.len == len && luajit_unbox_gcstr(&o->str) == str) {
                    return &o->str;
                }
                if (++n == strnum) break;
                p = &o->gch.nextgc;
            }
            if (n == strnum) break;
        }
        return nullptr;
    }

    int luajit_bucket_depth(GCRef *p) {
        int n = 0;
        while (p->gcptr64) {
            GCobj *o = luajit_gcref(p);
            if (!o) break;
            n++;
            p = &o->gch.nextgc;
        }
        return n;
    }

    std::string_view get_cfunction_cache(void *cfunc) {
        auto it = luajit_cfunc_cache.find(cfunc);
        std::string_view sym;
        if (it == luajit_cfunc_cache.end()) {
            std::string buf;
            GumDebugSymbolDetails details;
            if (gum_symbol_details_from_address(cfunc, &details)) {
                if (details.line_number != 0) {
                    std::format_to(std::back_inserter(buf), "C:{}!{}:{}", details.module_name, details.symbol_name, details.line_number);
                } else {
                    std::format_to(std::back_inserter(buf), "C:{}!{}", details.module_name, details.symbol_name);
                }
            } else {
                std::format_to(std::back_inserter(buf), "C:{}", reinterpret_cast<uintptr_t>(cfunc));
            }
            sym = buf;
            luajit_cfunc_cache.emplace(cfunc, std::move(buf));
        } else {
            sym = it->second;
        }
        return sym;
    }
}// namespace luajit

void gum_luajit_profiler::update_thread_id(lua_State *target_L, GumThreadId id) {
    L = target_L;
    thread_id = id;
}


static void trace(gum_luajit_profiler *prof) noexcept {
    constexpr auto simple_prof = false;
    constexpr auto use_cfunc_info = false;

    if (prof->isstop) return;
    if (!prof->L) return;
    if (!tracy::GetProfiler().IsConnected()) return;

    auto g = luajit::luajit_G(prof->L);
    if (!g) return;
    auto curL = luajit::luajit_cur_thread(g);
    if (!curL) return;
    if (luajit::luajit_backtrace(curL, g, simple_prof)) {
        auto luajitracer = luajit::luajit_frametrace;
        uint8_t count = luajitracer.offset;
        if (count == 0) return;
        int32_t spaceNeeded = sizeof(count);
        // tracy_frame
        // line uint32_t
        // function_name_len uint16_t
        // function_name char[]
        // source_len uint16_t
        // source char[]
        using namespace std::literals;
        constexpr auto buildin_prefix = "builtin#"sv;
        constexpr auto trace_prefix = "T:"sv;
        luajitracer.for_each_frame(
                [&](GCtrace *trace, const luajit::FrameTrace::FrameData &framedata) {
                    spaceNeeded += sizeof(uint32_t) + sizeof(uint16_t) * 2;
                    switch (framedata.tt) {
                        case LJ_TTRACE:
                            spaceNeeded += trace_prefix.size();
                            [[fallthrough]];
                        case LJ_TPROTO: {
                            auto pt = framedata.val.pt;
                            auto source = proto_chunkname(pt);
                            spaceNeeded += source->len;
                            if (simple_prof) {
                                spaceNeeded += std::formatted_size("{}", pt->firstline);
                            } else {
                                auto line = luajit::luajit_debug_frameline(curL, trace, pt, framedata.nextframe);
                                line = line > 0? line : pt->firstline;
                                spaceNeeded += std::formatted_size("{}", pt->firstline);
                            }
                            spaceNeeded += 1;//:
                            break;
                        }
                        case LJ_TFUNC: {
                            auto fn = framedata.val.fn;
                            if (isffunc(fn)) {
                                spaceNeeded += buildin_prefix.size();
                                spaceNeeded += std::formatted_size("{}", fn->c.ffid);
                            } else {
                                if (use_cfunc_info)
                                    spaceNeeded += luajit::get_cfunction_cache(fn->c.f).size();
                                else 
                                    spaceNeeded += std::formatted_size("{}", (void*)fn->c.f);
                            }
                            break;
                        }
                    }
                });
        auto ptr = (char *) tracy::tracy_malloc(spaceNeeded + 2);
        auto dst = ptr;
        memcpy(dst, &spaceNeeded, 2);
        dst += 2;
        memcpy(dst, &count, 1);
        dst++;
        auto left = spaceNeeded - 1;
        luajitracer.for_each_frame(
            [&](GCtrace *trace, const luajit::FrameTrace::FrameData &framedata) {
                if (left < 0) return;
                switch (framedata.tt) {
                    case LJ_TTRACE:
                    {
                        auto pt = framedata.val.pt;
                        auto source = proto_chunkname(pt);
                        left -= std::format_to_n(dst, left, "T:{}:{}",  std::string_view{strdata(source), source->len}, pt->firstline).size;
                        break;
                    }
                    case LJ_TPROTO: {
                        auto pt = framedata.val.pt;
                        auto source = proto_chunkname(pt);
                        if (simple_prof) {
                            left -= std::format_to_n(dst, left, "{}:{}", std::string_view{strdata(source), source->len}, pt->firstline).size;
                        } else {
                            auto line = luajit::luajit_debug_frameline(curL, trace, pt, framedata.nextframe);
                            line = line > 0? line : pt->firstline;
                            left -= std::format_to_n(dst, left, "{}:{}", std::string_view{strdata(source), source->len}, line).size;
                        }
                        break;
                    }
                    case LJ_TFUNC: {
                        auto fn = framedata.val.fn;
                        if (isffunc(fn)) {
                            left -= std::format_to_n(dst, left, "{}{}", buildin_prefix, fn->c.ffid).size;
                        } else {
                            if (use_cfunc_info) {
                                auto cache = luajit::get_cfunction_cache(fn->c.f);
                                left -= std::format_to_n(dst, left, "{}", cache).size;
                            }
                            else 
                                left -= std::format_to_n(dst, left, "{}", (void*)fn->c.f).size;
                        }
                        break;
                    }
                }
            });
        TracyQueuePrepareC(tracy::QueueType::CallstackAlloc);
        tracy::MemWrite(&item->callstackAllocFat.ptr, (uint64_t) ptr);
        tracy::MemWrite(&item->callstackAllocFat.nativePtr, (uint64_t) tracy::Callstack(30));
        TracyQueueCommitC(callstackAllocFatThread);
    }
}

std::atomic<gum_luajit_profiler *> gum_luajit_profiler::instance = nullptr;
void gum_luajit_profiler::start() {
    gum_luajit_profiler *ptr = nullptr;
    if (!instance.compare_exchange_strong(ptr, this)) {
        return;
    }
    isstop = false;
    intrace = false;
#ifdef _WIN32
    auto th = std::thread([this]() {
        while (!isstop) {
            std::this_thread::sleep_for(interval);
            if (thread_id && L && !isstop && tracy::GetProfiler().IsConnected()) {

                gum_process_modify_thread(thread_id, +[](GumThreadId thread_id, GumCpuContext *cpu_context, gpointer user_data) {
                        auto self = (gum_luajit_profiler *) user_data;
                        bool intrace = false;
                        if (self->intrace.compare_exchange_strong(intrace, true)) {
                            __try {
                                trace(self);
                            }
                            __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? 
                                      EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
                            }
                            self->intrace = false;
                        } }, this, GumModifyThreadFlags::GUM_MODIFY_THREAD_FLAGS_NONE);

                // auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
                // QueueUserAPC2(+[](ULONG_PTR paramer) {
                //     APC_CALLBACK_DATA *pData = (APC_CALLBACK_DATA *) paramer;
                //     auto self = (gum_luajit_profiler *) pData->Parameter;
                //     bool intrace = false;
                //     if (self->intrace.compare_exchange_strong(intrace, true)) {
                //     if (gum_process_get_current_thread_id() != prof->thread_id) return;
                //         trace(self);
                //         self->intrace = false;
                //     }
                // }, hThread, (ULONG_PTR) this, QUEUE_USER_APC_FLAGS(QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC | QUEUE_USER_APC_CALLBACK_DATA_CONTEXT));
                // CloseHandle(hThread);
            }
        }
    });
    th.detach();
#else
    int interval = this->interval.count();
    struct itimerval tm;
    struct sigaction sa;
    tm.it_value.tv_sec = tm.it_interval.tv_sec = interval / 1000;
    tm.it_value.tv_usec = tm.it_interval.tv_usec = (interval % 1000) * 1000;
    setitimer(ITIMER_PROF, &tm, NULL);
#if LJ_TARGET_QNX
    sa.sa_flags = SA_SIGINFO;
#else
    sa.sa_flags = SA_RESTART | SA_SIGINFO;
#endif
    sa.sa_handler = +[](int, siginfo_t *info, void *) {
        instance->trace();
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPROF, &sa, &ps->oldsa);
#endif
}

void gum_luajit_profiler::stop() {
    gum_luajit_profiler *ptr = this;
    instance.compare_exchange_strong(ptr, nullptr);
    this->isstop = true;
#ifdef _WIN32

#else
    struct itimerval tm;
    tm.it_value.tv_sec = tm.it_interval.tv_sec = 0;
    tm.it_value.tv_usec = tm.it_interval.tv_usec = 0;
    setitimer(ITIMER_PROF, &tm, NULL);
    sigaction(SIGPROF, &ps->oldsa, NULL);
#endif
}


DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_enable_profiler(int en) {
    static gum_luajit_profiler profiler;
    if (en) {
        profiler.start();
    } else {
        profiler.stop();
    }
}

void gum_luajit_profiler_update_thread_id(lua_State *target_L, GumThreadId id) {
    if (gum_luajit_profiler::instance) {
        gum_luajit_profiler::instance.load()->update_thread_id(target_L, id);
    }
}
