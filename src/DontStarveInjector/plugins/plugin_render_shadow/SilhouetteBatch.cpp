#include "SilhouetteBatch.hpp"
#include "SilhouetteMath.hpp"
#include "BuildBin.hpp"


#include <spdlog/spdlog.h>
#include "ShadowLog.hpp"

#include <frida-gum.h>


#include <atomic>
#include <cmath>
#include <cstring>
#include <unordered_set>
#include <vector>
#include <string>
#include <cstdio>



#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif


namespace ds::shadow {
namespace {

std::atomic<int> g_on{0};
std::atomic<int> g_healthy{0};
std::unordered_set<const void *> g_set;

constexpr uint32_t kVertBudget = 256000;

// CPU world XZ + UV. No GPU vb, no per-run matrix.
struct Run {
    uint32_t tex;
    uint32_t start;
    uint32_t count;
};
struct GpuRun {
    uint32_t vb;
    uint32_t tex;
    uint32_t fx;
    uint32_t vd;
    uint32_t start;
    uint32_t count;
    float m[16];
};

std::vector<SilVert> g_cpu;
std::vector<Run> g_runs;
std::vector<GpuRun> g_gpu;
uint32_t g_effect = 0;
uint32_t g_vd = 0;
bool g_budget = false;
void *g_game = nullptr;
uint32_t g_sil_fx = 0;
uint32_t g_sil_vd = 0;
struct DebugStamp {
    float x;
    float z;
};
std::vector<DebugStamp> g_stamps;
uint32_t g_debug_tex = 0;
uint32_t g_debug_fx = 0;
uint32_t g_debug_vd = 0;
uint32_t g_anim_pass_fx = 0;
uint32_t g_anim_pass_vd = 0;
bool g_did_twin = false;
uint32_t g_twin_fx = 0;
bool g_ground_poke = false;



uint32_t g_pf_fn = 0;
uint32_t g_pf_uv = 0;
uint32_t g_pf_frame = 0;
uint32_t g_pf_elems = 0;
uint32_t g_pf_added = 0;
uint32_t g_pack_ents = 0;




using LoadShader_fn = uint32_t(__fastcall *)(void *effect_mgr, const char *path, bool log_error,
                                             bool do_fallback, uint32_t extra);
LoadShader_fn load_shader = nullptr;


using GetAnimFrame_fn = void *(__fastcall *)(void *anim, uint32_t play_mode, float time);
using CalcScale_fn = float *(__fastcall *)(void *tdc, float *dest, const float *world,
                                           const float *scale);
using MatMul_fn = float *(__fastcall *)(float *dest, const float *a, const float *b);
using GetDsList_fn = void *(__fastcall *)(void *entity_manager);
using SetEffect_fn = void(__fastcall *)(void *renderer, uint32_t handle);
using SetVd_fn = void(__fastcall *)(void *renderer, uint32_t handle);
using SetTex_fn = void(__fastcall *)(void *renderer, uint32_t slot, uint32_t handle);
using SetVb_fn = void(__fastcall *)(void *renderer, uint32_t handle);
using SetUniform_fn = void(__fastcall *)(void *renderer, int slot, const void *data);
using PopUniform_fn = void(__fastcall *)(void *renderer, int slot);
using GlDrawArrays_fn = void(__stdcall *)(uint32_t mode, int first, int count);
SetUniform_fn set_uniform = nullptr;
PopUniform_fn pop_uniform = nullptr;
GlDrawArrays_fn gl_draw_arrays = nullptr;
void **gl_draw_iat = nullptr;

const int32_t *g_prim_table = nullptr;
using ConvertMat_fn = float *(__fastcall *)(float *dest, const float *src);
ConvertMat_fn convert_mat = nullptr;


using Draw_fn = void(__fastcall *)(void *renderer, int start, int prim);
using AnimDraw_fn = void(__fastcall *)(void *renderer, const float *matrix, int start, int count,
                                       int prim);
using GetVertDesc_fn = void *(__fastcall *)(void *cache, uint32_t handle);
using CreateVB_fn = uint32_t(__fastcall *)(void *renderer, uint32_t type, int vert_count,
                                           uint16_t fmt, void *verts, uint8_t unk);
using ReleaseVb_fn = void(__fastcall *)(void *res_mgr, uint32_t handle);

GetAnimFrame_fn get_anim_frame = nullptr;
AnimDraw_fn anim_draw = nullptr;

CalcScale_fn calc_scale = nullptr;
MatMul_fn mat_mul = nullptr;
GetDsList_fn get_ds_list = nullptr;
SetEffect_fn set_effect = nullptr;
SetVd_fn set_vd = nullptr;
SetTex_fn set_tex = nullptr;
SetVb_fn set_vb = nullptr;
Draw_fn draw = nullptr;
using HwBind_fn = void(__fastcall *)(void *fx, void *constants, uint8_t *renderer_plus_0x10);
HwBind_fn hw_bind = nullptr;

#ifdef _WIN32
using GlEnable_fn = void(__stdcall *)(unsigned);
using GlDisable_fn = void(__stdcall *)(unsigned);
using GlStencilFunc_fn = void(__stdcall *)(unsigned, int, unsigned);
using GlStencilOp_fn = void(__stdcall *)(unsigned, unsigned, unsigned);
using GlStencilMask_fn = void(__stdcall *)(unsigned);
using GlGetIntegerv_fn = void(__stdcall *)(unsigned, int *);
using WglGetProc_fn = void *(__stdcall *)(const char *);
using GlGenRbo_fn = void(__stdcall *)(int, unsigned *);
using GlDelRbo_fn = void(__stdcall *)(int, const unsigned *);
using GlBindRbo_fn = void(__stdcall *)(unsigned, unsigned);
using GlRboStorage_fn = void(__stdcall *)(unsigned, unsigned, int, int);
using GlFboRbo_fn = void(__stdcall *)(unsigned, unsigned, unsigned, unsigned);
using GlCheckFbo_fn = unsigned(__stdcall *)(unsigned);
using GlGetFboAttach_fn = void(__stdcall *)(unsigned, unsigned, unsigned, int *);
using GlClear_fn = void(__stdcall *)(unsigned);
using GlClearStencil_fn = void(__stdcall *)(int);

GlEnable_fn gl_enable = nullptr;
GlDisable_fn gl_disable = nullptr;
GlStencilFunc_fn gl_stencil_func = nullptr;
GlStencilOp_fn gl_stencil_op = nullptr;
GlStencilMask_fn gl_stencil_mask = nullptr;
GlGetIntegerv_fn gl_get_integerv = nullptr;
GlGenRbo_fn gl_gen_rbo = nullptr;
GlDelRbo_fn gl_del_rbo = nullptr;
GlBindRbo_fn gl_bind_rbo = nullptr;
GlRboStorage_fn gl_rbo_storage = nullptr;
GlFboRbo_fn gl_fbo_rbo = nullptr;
GlCheckFbo_fn gl_check_fbo = nullptr;
GlGetFboAttach_fn gl_get_fbo_attach = nullptr;
GlClear_fn gl_clear = nullptr;
GlClearStencil_fn gl_clear_stencil = nullptr;

unsigned g_sil_rbo = 0;
int g_sil_rbo_w = 0;
int g_sil_rbo_h = 0;
bool g_sil_rbo_on = false;
constexpr unsigned kGlStencilTest = 0x0B90u;
constexpr unsigned kGlEqual = 0x0202u;
constexpr unsigned kGlKeep = 0x1E00u;
constexpr unsigned kGlIncr = 0x1E02u;
constexpr unsigned kGlStencilBits = 0x0D57u;
constexpr unsigned kGlViewport = 0x0BA2u;
constexpr unsigned kGlFramebuffer = 0x8D40u;
constexpr unsigned kGlRenderbuffer = 0x8D41u;
constexpr unsigned kGlStencilAttach = 0x8D20u;
constexpr unsigned kGlStencilIndex8 = 0x8D48u;
constexpr unsigned kGlFboComplete = 0x8CD5u;
constexpr unsigned kGlFboAttachType = 0x8CD0u;
constexpr unsigned kGlStencilBufferBit = 0x00000400u;


void *SilGlProc(HMODULE gl, WglGetProc_fn wgl, const char *name) {
    if (wgl != nullptr) {
        if (void *p = wgl(name)) {
            return p;
        }
    }
    return reinterpret_cast<void *>(::GetProcAddress(gl, name));
}

bool BindSilGl() {
    if (gl_enable != nullptr) {
        return gl_stencil_func != nullptr && gl_stencil_op != nullptr;
    }
    HMODULE gl = ::GetModuleHandleA("opengl32.dll");
    if (gl == nullptr) {
        return false;
    }
    auto wgl = reinterpret_cast<WglGetProc_fn>(::GetProcAddress(gl, "wglGetProcAddress"));
    gl_enable = reinterpret_cast<GlEnable_fn>(SilGlProc(gl, wgl, "glEnable"));
    gl_disable = reinterpret_cast<GlDisable_fn>(SilGlProc(gl, wgl, "glDisable"));
    gl_stencil_func = reinterpret_cast<GlStencilFunc_fn>(SilGlProc(gl, wgl, "glStencilFunc"));
    gl_stencil_op = reinterpret_cast<GlStencilOp_fn>(SilGlProc(gl, wgl, "glStencilOp"));
    gl_stencil_mask = reinterpret_cast<GlStencilMask_fn>(SilGlProc(gl, wgl, "glStencilMask"));
    gl_get_integerv = reinterpret_cast<GlGetIntegerv_fn>(SilGlProc(gl, wgl, "glGetIntegerv"));
    gl_gen_rbo = reinterpret_cast<GlGenRbo_fn>(SilGlProc(gl, wgl, "glGenRenderbuffers"));
    if (gl_gen_rbo == nullptr) {
        gl_gen_rbo = reinterpret_cast<GlGenRbo_fn>(SilGlProc(gl, wgl, "glGenRenderbuffersEXT"));
    }
    gl_del_rbo = reinterpret_cast<GlDelRbo_fn>(SilGlProc(gl, wgl, "glDeleteRenderbuffers"));
    if (gl_del_rbo == nullptr) {
        gl_del_rbo = reinterpret_cast<GlDelRbo_fn>(SilGlProc(gl, wgl, "glDeleteRenderbuffersEXT"));
    }
    gl_bind_rbo = reinterpret_cast<GlBindRbo_fn>(SilGlProc(gl, wgl, "glBindRenderbuffer"));
    if (gl_bind_rbo == nullptr) {
        gl_bind_rbo = reinterpret_cast<GlBindRbo_fn>(SilGlProc(gl, wgl, "glBindRenderbufferEXT"));
    }
    gl_rbo_storage = reinterpret_cast<GlRboStorage_fn>(SilGlProc(gl, wgl, "glRenderbufferStorage"));
    if (gl_rbo_storage == nullptr) {
        gl_rbo_storage = reinterpret_cast<GlRboStorage_fn>(SilGlProc(gl, wgl, "glRenderbufferStorageEXT"));
    }
    gl_fbo_rbo = reinterpret_cast<GlFboRbo_fn>(SilGlProc(gl, wgl, "glFramebufferRenderbuffer"));
    if (gl_fbo_rbo == nullptr) {
        gl_fbo_rbo = reinterpret_cast<GlFboRbo_fn>(SilGlProc(gl, wgl, "glFramebufferRenderbufferEXT"));
    }
    gl_check_fbo = reinterpret_cast<GlCheckFbo_fn>(SilGlProc(gl, wgl, "glCheckFramebufferStatus"));
    if (gl_check_fbo == nullptr) {
        gl_check_fbo = reinterpret_cast<GlCheckFbo_fn>(SilGlProc(gl, wgl, "glCheckFramebufferStatusEXT"));
    }
    gl_get_fbo_attach =
        reinterpret_cast<GlGetFboAttach_fn>(SilGlProc(gl, wgl, "glGetFramebufferAttachmentParameteriv"));
    if (gl_get_fbo_attach == nullptr) {
        gl_get_fbo_attach = reinterpret_cast<GlGetFboAttach_fn>(
            SilGlProc(gl, wgl, "glGetFramebufferAttachmentParameterivEXT"));
    }
    gl_clear = reinterpret_cast<GlClear_fn>(SilGlProc(gl, wgl, "glClear"));
    gl_clear_stencil = reinterpret_cast<GlClearStencil_fn>(SilGlProc(gl, wgl, "glClearStencil"));

    return gl_enable != nullptr && gl_disable != nullptr && gl_stencil_func != nullptr &&
           gl_stencil_op != nullptr && gl_stencil_mask != nullptr && gl_get_integerv != nullptr;
}

bool AttachTempStencil() {
    g_sil_rbo_on = false;
    static uint32_t nwhy = 0;
    const bool chatter = nwhy < 3;
    ++nwhy;
    if (gl_get_integerv == nullptr || gl_gen_rbo == nullptr || gl_fbo_rbo == nullptr ||
        gl_check_fbo == nullptr || gl_rbo_storage == nullptr || gl_bind_rbo == nullptr) {
        if (chatter) {
            SHADOW_TRACE("[render.shadow] stencil skip procs gen={} fbo={} chk={} stor={} bind={}",
                         gl_gen_rbo != nullptr, gl_fbo_rbo != nullptr, gl_check_fbo != nullptr,
                         gl_rbo_storage != nullptr, gl_bind_rbo != nullptr);
        }
        return false;
    }
    int fbo = -1;
    gl_get_integerv(0x8CA6u, &fbo);
    int atype = -1;
    if (gl_get_fbo_attach != nullptr) {
        gl_get_fbo_attach(kGlFramebuffer, kGlStencilAttach, kGlFboAttachType, &atype);
    }
    int vp[4] = {};
    gl_get_integerv(kGlViewport, vp);
    if (chatter) {
        SHADOW_TRACE("[render.shadow] stencil try fbo={} atype={} vp={}x{}", fbo, atype, vp[2],
                     vp[3]);
    }
    if (atype > 0) {
        return false;
    }
    const int w = vp[2];
    const int h = vp[3];
    if (w <= 0 || h <= 0) {
        return false;
    }

    if (g_sil_rbo == 0 || g_sil_rbo_w != w || g_sil_rbo_h != h) {
        if (g_sil_rbo != 0 && gl_del_rbo != nullptr) {
            gl_del_rbo(1, &g_sil_rbo);
            g_sil_rbo = 0;
        }
        gl_gen_rbo(1, &g_sil_rbo);
        if (g_sil_rbo == 0) {
            return false;
        }
        gl_bind_rbo(kGlRenderbuffer, g_sil_rbo);
        gl_rbo_storage(kGlRenderbuffer, kGlStencilIndex8, w, h);
        gl_bind_rbo(kGlRenderbuffer, 0);
        g_sil_rbo_w = w;
        g_sil_rbo_h = h;
    }
    gl_fbo_rbo(kGlFramebuffer, kGlStencilAttach, kGlRenderbuffer, g_sil_rbo);
    if (gl_check_fbo(kGlFramebuffer) != kGlFboComplete) {
        gl_fbo_rbo(kGlFramebuffer, kGlStencilAttach, kGlRenderbuffer, 0);
        return false;
    }
    if (gl_clear_stencil != nullptr) {
        gl_clear_stencil(0);
    }
    if (gl_clear != nullptr) {
        gl_clear(kGlStencilBufferBit);
    }
    g_sil_rbo_on = true;
    return true;
}


void DetachTempStencil() {
    if (!g_sil_rbo_on || gl_fbo_rbo == nullptr) {
        g_sil_rbo_on = false;
        return;
    }
    gl_fbo_rbo(kGlFramebuffer, kGlStencilAttach, kGlRenderbuffer, 0);
    g_sil_rbo_on = false;
}

using GlBindFbo_fn = void(__stdcall *)(unsigned, unsigned);
using GlGenFbo_fn = void(__stdcall *)(int, unsigned *);
using GlDelFbo_fn = void(__stdcall *)(int, const unsigned *);
using GlFboTex_fn = void(__stdcall *)(unsigned, unsigned, unsigned, unsigned, int);
using GlGenTex_fn = void(__stdcall *)(int, unsigned *);
using GlDelTex_fn = void(__stdcall *)(int, const unsigned *);
using GlBindTex_fn = void(__stdcall *)(unsigned, unsigned);
using GlTexImage2D_fn = void(__stdcall *)(unsigned, int, int, int, int, int, unsigned, unsigned,
                                         const void *);
using GlTexParam_fn = void(__stdcall *)(unsigned, unsigned, int);
using GlCreateShader_fn = unsigned(__stdcall *)(unsigned);
using GlShaderSource_fn = void(__stdcall *)(unsigned, int, const char *const *, const int *);
using GlCompileShader_fn = void(__stdcall *)(unsigned);
using GlGetShaderiv_fn = void(__stdcall *)(unsigned, unsigned, int *);
using GlGetShaderInfoLog_fn = void(__stdcall *)(unsigned, int, int *, char *);
using GlCreateProgram_fn = unsigned(__stdcall *)();
using GlAttachShader_fn = void(__stdcall *)(unsigned, unsigned);
using GlLinkProgram_fn = void(__stdcall *)(unsigned);
using GlGetProgramiv_fn = void(__stdcall *)(unsigned, unsigned, int *);
using GlUseProgram_fn = void(__stdcall *)(unsigned);
using GlGetUniform_fn = int(__stdcall *)(unsigned, const char *);
using GlUniform1f_fn = void(__stdcall *)(int, float);
using GlUniform1i_fn = void(__stdcall *)(int, int);
using GlDeleteShader_fn = void(__stdcall *)(unsigned);
using GlDeleteProgram_fn = void(__stdcall *)(unsigned);
using GlGenBuf_fn = void(__stdcall *)(int, unsigned *);
using GlBindBuf_fn = void(__stdcall *)(unsigned, unsigned);
using GlBufData_fn = void(__stdcall *)(unsigned, intptr_t, const void *, unsigned);

using GlVertexAttrib_fn = void(__stdcall *)(unsigned, int, unsigned, unsigned char, int,
                                           const void *);
using GlEnableVA_fn = void(__stdcall *)(unsigned);
using GlBlendFunc_fn = void(__stdcall *)(unsigned, unsigned);
using GlClearColor_fn = void(__stdcall *)(float, float, float, float);
using GlIsEnabled_fn = unsigned char(__stdcall *)(unsigned);
using GlViewport_fn = void(__stdcall *)(int, int, int, int);
using GlGetError_fn = unsigned(__stdcall *)();
GlBindFbo_fn gl_bind_fbo = nullptr;
GlGenFbo_fn gl_gen_fbo = nullptr;
GlDelFbo_fn gl_del_fbo = nullptr;
GlFboTex_fn gl_fbo_tex = nullptr;
GlGenTex_fn gl_gen_tex = nullptr;
GlDelTex_fn gl_del_tex = nullptr;
GlBindTex_fn gl_bind_tex = nullptr;
GlTexImage2D_fn gl_tex_image = nullptr;
GlTexParam_fn gl_tex_param = nullptr;
GlCreateShader_fn gl_create_shader = nullptr;
GlShaderSource_fn gl_shader_source = nullptr;
GlCompileShader_fn gl_compile_shader = nullptr;
GlGetShaderiv_fn gl_get_shaderiv = nullptr;
GlGetShaderInfoLog_fn gl_get_shader_log = nullptr;
GlCreateProgram_fn gl_create_program = nullptr;
GlAttachShader_fn gl_attach_shader = nullptr;
GlLinkProgram_fn gl_link_program = nullptr;
GlGetProgramiv_fn gl_get_programiv = nullptr;
GlUseProgram_fn gl_use_program = nullptr;
GlGetUniform_fn gl_get_uniform = nullptr;
GlUniform1f_fn gl_uniform1f = nullptr;
GlUniform1i_fn gl_uniform1i = nullptr;
GlDeleteShader_fn gl_delete_shader = nullptr;
GlDeleteProgram_fn gl_delete_program = nullptr;
GlGenBuf_fn gl_gen_buf = nullptr;
GlBindBuf_fn gl_bind_buf = nullptr;
GlBufData_fn gl_buf_data = nullptr;
GlVertexAttrib_fn gl_vertex_attrib = nullptr;
GlEnableVA_fn gl_enable_va = nullptr;
GlBlendFunc_fn gl_blend_func = nullptr;
GlClearColor_fn gl_clear_color = nullptr;
GlIsEnabled_fn gl_is_enabled = nullptr;
GlViewport_fn gl_viewport = nullptr;
GlDrawArrays_fn gl_draw_cov = nullptr;
GlGetError_fn gl_get_error = nullptr;

unsigned g_cov_fbo = 0;
unsigned g_cov_tex = 0;
unsigned g_blit_prog = 0;
unsigned g_blit_vbo = 0;
int g_cov_w = 0;
int g_cov_h = 0;
int g_blit_u_mask = -1;
int g_blit_u_alpha = -1;
constexpr unsigned kGlFboBinding = 0x8CA6u;
constexpr unsigned kGlColorAttach0 = 0x8CE0u;
constexpr unsigned kGlColorBufferBit = 0x4000u;
constexpr unsigned kGlTexture2D = 0x0DE1u;
constexpr unsigned kGlRgba = 0x1908u;
constexpr unsigned kGlRgba8 = 0x8058u;
constexpr unsigned kGlTexMaxLevel = 0x813Du;
constexpr unsigned kGlUnsignedByte = 0x1401u;
constexpr unsigned kGlNearest = 0x2600u;
constexpr unsigned kGlClampToEdge = 0x812Fu;
constexpr unsigned kGlTexMin = 0x2801u;
constexpr unsigned kGlTexMag = 0x2800u;
constexpr unsigned kGlTexWrapS = 0x2802u;
constexpr unsigned kGlTexWrapT = 0x2803u;
constexpr unsigned kGlArrayBuf = 0x8892u;
constexpr unsigned kGlStaticDraw = 0x88E4u;
constexpr unsigned kGlTriStrip = 0x0005u;
constexpr unsigned kGlFloat = 0x1406u;
constexpr unsigned kGlVertShader = 0x8B31u;
constexpr unsigned kGlFragShader = 0x8B30u;
constexpr unsigned kGlCompileStatus = 0x8B81u;
constexpr unsigned kGlLinkStatus = 0x8B82u;
constexpr unsigned kGlBlend = 0x0BE2u;
constexpr unsigned kGlDepthTest = 0x0B71u;
constexpr unsigned kGlSrcAlpha = 0x0302u;
constexpr unsigned kGlOneMinusSrcAlpha = 0x0303u;

void *SilGlProcExt(HMODULE gl, WglGetProc_fn wgl, const char *name, const char *ext) {
    void *p = SilGlProc(gl, wgl, name);
    if (p == nullptr && ext != nullptr) {
        p = SilGlProc(gl, wgl, ext);
    }
    return p;
}

bool BindCoverageGl() {
    static bool resolved = false;
    static bool ok = false;
    if (resolved) {
        return ok;
    }
    HMODULE gles = ::GetModuleHandleA("ds_GLESv2.dll");
    const char *mod = "ds_GLESv2.dll";
    if (gles == nullptr) {
        gles = ::GetModuleHandleA("libGLESv2.dll");
        mod = "libGLESv2.dll";
    }
    if (gles == nullptr) {
        return false;
    }
    resolved = true;
    auto gp = [gles](const char *name) -> void * {
        return reinterpret_cast<void *>(::GetProcAddress(gles, name));
    };
    gl_bind_fbo = reinterpret_cast<GlBindFbo_fn>(gp("glBindFramebuffer"));
    gl_gen_fbo = reinterpret_cast<GlGenFbo_fn>(gp("glGenFramebuffers"));
    gl_del_fbo = reinterpret_cast<GlDelFbo_fn>(gp("glDeleteFramebuffers"));
    gl_fbo_tex = reinterpret_cast<GlFboTex_fn>(gp("glFramebufferTexture2D"));
    gl_check_fbo = reinterpret_cast<GlCheckFbo_fn>(gp("glCheckFramebufferStatus"));
    gl_gen_tex = reinterpret_cast<GlGenTex_fn>(gp("glGenTextures"));
    gl_del_tex = reinterpret_cast<GlDelTex_fn>(gp("glDeleteTextures"));
    gl_bind_tex = reinterpret_cast<GlBindTex_fn>(gp("glBindTexture"));
    gl_tex_image = reinterpret_cast<GlTexImage2D_fn>(gp("glTexImage2D"));
    gl_tex_param = reinterpret_cast<GlTexParam_fn>(gp("glTexParameteri"));
    gl_create_shader = reinterpret_cast<GlCreateShader_fn>(gp("glCreateShader"));
    gl_shader_source = reinterpret_cast<GlShaderSource_fn>(gp("glShaderSource"));
    gl_compile_shader = reinterpret_cast<GlCompileShader_fn>(gp("glCompileShader"));
    gl_get_shaderiv = reinterpret_cast<GlGetShaderiv_fn>(gp("glGetShaderiv"));
    gl_get_shader_log = reinterpret_cast<GlGetShaderInfoLog_fn>(gp("glGetShaderInfoLog"));
    gl_create_program = reinterpret_cast<GlCreateProgram_fn>(gp("glCreateProgram"));
    gl_attach_shader = reinterpret_cast<GlAttachShader_fn>(gp("glAttachShader"));
    gl_link_program = reinterpret_cast<GlLinkProgram_fn>(gp("glLinkProgram"));
    gl_get_programiv = reinterpret_cast<GlGetProgramiv_fn>(gp("glGetProgramiv"));
    gl_use_program = reinterpret_cast<GlUseProgram_fn>(gp("glUseProgram"));
    gl_get_uniform = reinterpret_cast<GlGetUniform_fn>(gp("glGetUniformLocation"));
    gl_uniform1f = reinterpret_cast<GlUniform1f_fn>(gp("glUniform1f"));
    gl_uniform1i = reinterpret_cast<GlUniform1i_fn>(gp("glUniform1i"));
    gl_delete_shader = reinterpret_cast<GlDeleteShader_fn>(gp("glDeleteShader"));
    gl_delete_program = reinterpret_cast<GlDeleteProgram_fn>(gp("glDeleteProgram"));
    gl_gen_buf = reinterpret_cast<GlGenBuf_fn>(gp("glGenBuffers"));
    gl_bind_buf = reinterpret_cast<GlBindBuf_fn>(gp("glBindBuffer"));
    gl_buf_data = reinterpret_cast<GlBufData_fn>(gp("glBufferData"));
    gl_vertex_attrib = reinterpret_cast<GlVertexAttrib_fn>(gp("glVertexAttribPointer"));
    gl_enable_va = reinterpret_cast<GlEnableVA_fn>(gp("glEnableVertexAttribArray"));
    gl_blend_func = reinterpret_cast<GlBlendFunc_fn>(gp("glBlendFunc"));
    gl_clear_color = reinterpret_cast<GlClearColor_fn>(gp("glClearColor"));
    gl_is_enabled = reinterpret_cast<GlIsEnabled_fn>(gp("glIsEnabled"));
    gl_viewport = reinterpret_cast<GlViewport_fn>(gp("glViewport"));
    gl_draw_cov = reinterpret_cast<GlDrawArrays_fn>(gp("glDrawArrays"));
    gl_clear = reinterpret_cast<GlClear_fn>(gp("glClear"));
    gl_get_integerv = reinterpret_cast<GlGetIntegerv_fn>(gp("glGetIntegerv"));
    gl_get_error = reinterpret_cast<GlGetError_fn>(gp("glGetError"));
    gl_enable = reinterpret_cast<GlEnable_fn>(gp("glEnable"));
    gl_disable = reinterpret_cast<GlDisable_fn>(gp("glDisable"));
    ok = gl_bind_fbo != nullptr && gl_gen_fbo != nullptr && gl_fbo_tex != nullptr &&
         gl_check_fbo != nullptr && gl_gen_tex != nullptr && gl_tex_image != nullptr &&
         gl_create_shader != nullptr && gl_use_program != nullptr && gl_draw_cov != nullptr &&
         gl_clear != nullptr && gl_get_integerv != nullptr && gl_viewport != nullptr;
    char gles_path[MAX_PATH]{};
    (void)::GetModuleFileNameA(gles, gles_path, MAX_PATH);
    SHADOW_TRACE("[render.shadow] coverage gles={} ok={} path={}", mod, ok ? 1 : 0, gles_path);
    return ok;
}

unsigned CompileGlShader(unsigned type, const char *src) {
    const unsigned sh = gl_create_shader(type);
    gl_shader_source(sh, 1, &src, nullptr);
    gl_compile_shader(sh);
    int ok = 0;
    gl_get_shaderiv(sh, kGlCompileStatus, &ok);
    if (ok == 0) {
        char log[256]{};
        if (gl_get_shader_log != nullptr) {
            gl_get_shader_log(sh, 255, nullptr, log);
        }
        spdlog::error("[render.shadow] shader compile: {}", log);
        gl_delete_shader(sh);
        return 0;
    }
    return sh;
}

bool EnsureBlitProg() {
    if (g_blit_prog != 0) {
        return true;
    }
    static const char *kVs =
        "#version 100\n"
        "attribute vec2 POS;\n"
        "varying vec2 UV;\n"
        "void main(){\n"
        "  gl_Position=vec4(POS,0.0,1.0);\n"
        "  UV=POS*0.5+0.5;\n"
        "}\n";
    static const char *kPs =
        "#version 100\n"
        "precision mediump float;\n"
        "uniform sampler2D MASK;\n"
        "uniform float ALPHA;\n"
        "varying vec2 UV;\n"
        "void main(){\n"
        "  float m=texture2D(MASK,UV).a;\n"
        "  if(m<1.0/255.0) discard;\n"
        "  gl_FragColor=vec4(0.0,0.0,0.0,ALPHA);\n"
        "}\n";
    const unsigned vs = CompileGlShader(kGlVertShader, kVs);
    const unsigned ps = CompileGlShader(kGlFragShader, kPs);
    if (vs == 0 || ps == 0) {
        return false;
    }
    g_blit_prog = gl_create_program();
    gl_attach_shader(g_blit_prog, vs);
    gl_attach_shader(g_blit_prog, ps);
    gl_link_program(g_blit_prog);
    gl_delete_shader(vs);
    gl_delete_shader(ps);
    int ok = 0;
    gl_get_programiv(g_blit_prog, kGlLinkStatus, &ok);
    if (ok == 0) {
        spdlog::error("[render.shadow] blit link failed");
        gl_delete_program(g_blit_prog);
        g_blit_prog = 0;
        return false;
    }
    g_blit_u_mask = gl_get_uniform(g_blit_prog, "MASK");
    g_blit_u_alpha = gl_get_uniform(g_blit_prog, "ALPHA");
    if (g_blit_vbo == 0 && gl_gen_buf != nullptr) {
        gl_gen_buf(1, &g_blit_vbo);
        const float quad[8] = {-1.f, -1.f, 1.f, -1.f, -1.f, 1.f, 1.f, 1.f};
        gl_bind_buf(kGlArrayBuf, g_blit_vbo);
        gl_buf_data(kGlArrayBuf, static_cast<intptr_t>(sizeof(quad)), quad, kGlStaticDraw);
        gl_bind_buf(kGlArrayBuf, 0);
    }
    return g_blit_vbo != 0;
}


bool EnsureCoverageRt(int w, int h) {
    static bool dead = false;
    if (dead || w <= 0 || h <= 0) {
        return false;
    }
    if (g_cov_fbo != 0 && g_cov_w == w && g_cov_h == h) {
        return true;
    }
    if (g_cov_tex != 0 && gl_del_tex != nullptr) {
        gl_del_tex(1, &g_cov_tex);
        g_cov_tex = 0;
    }
    if (g_cov_fbo != 0 && gl_del_fbo != nullptr) {
        gl_del_fbo(1, &g_cov_fbo);
        g_cov_fbo = 0;
    }
    if (gl_get_error != nullptr) {
        while (gl_get_error() != 0) {
        }
    }
    gl_gen_tex(1, &g_cov_tex);
    gl_bind_tex(kGlTexture2D, g_cov_tex);
    gl_tex_image(kGlTexture2D, 0, static_cast<int>(kGlRgba8), w, h, 0, kGlRgba, kGlUnsignedByte,
                 nullptr);
    gl_tex_param(kGlTexture2D, kGlTexMin, static_cast<int>(kGlNearest));
    gl_tex_param(kGlTexture2D, kGlTexMag, static_cast<int>(kGlNearest));
    gl_tex_param(kGlTexture2D, kGlTexWrapS, static_cast<int>(kGlClampToEdge));
    gl_tex_param(kGlTexture2D, kGlTexWrapT, static_cast<int>(kGlClampToEdge));
    gl_tex_param(kGlTexture2D, kGlTexMaxLevel, 0);
    gl_bind_tex(kGlTexture2D, 0);
    gl_gen_fbo(1, &g_cov_fbo);
    gl_bind_fbo(kGlFramebuffer, g_cov_fbo);
    gl_fbo_tex(kGlFramebuffer, kGlColorAttach0, kGlTexture2D, g_cov_tex, 0);
    const unsigned status = gl_check_fbo != nullptr ? gl_check_fbo(kGlFramebuffer) : 0;
    const unsigned err = gl_get_error != nullptr ? gl_get_error() : 0;
    gl_bind_fbo(kGlFramebuffer, 0);
    const bool ok = status == kGlFboComplete && g_cov_tex != 0 && g_cov_fbo != 0;
    SHADOW_TRACE("[render.shadow] coverage rt tex={:#x} fbo={:#x} st={:#x} err={:#x} {}x{}",
                 g_cov_tex, g_cov_fbo, status, err, w, h);
    if (!ok) {
        dead = true;
        return false;
    }
    g_cov_w = w;
    g_cov_h = h;
    return true;
}

bool BeginCoverageRt(int w, int h) {
    if (!EnsureCoverageRt(w, h) || !EnsureBlitProg() || gl_bind_fbo == nullptr) {
        return false;
    }
    gl_bind_fbo(kGlFramebuffer, g_cov_fbo);
    if (gl_viewport != nullptr) {
        gl_viewport(0, 0, w, h);
    }
    if (gl_clear_color != nullptr) {
        gl_clear_color(0.f, 0.f, 0.f, 0.f);
    }
    gl_clear(kGlColorBufferBit);
    if (gl_disable != nullptr) {
        gl_disable(kGlDepthTest);
        gl_disable(kGlBlend);
    }
    return true;
}
void BlitCoverageRt(float alpha, int prev_fbo, const int vp[4]) {
    if (gl_bind_fbo != nullptr) {
        gl_bind_fbo(kGlFramebuffer, static_cast<unsigned>(prev_fbo));
    }
    if (gl_viewport != nullptr && vp != nullptr) {
        gl_viewport(vp[0], vp[1], vp[2], vp[3]);
    }
    if (!(alpha > 0.f) || g_blit_prog == 0 || g_cov_tex == 0) {
        return;
    }
    if (alpha > 1.f) {
        alpha = 1.f;
    }
    gl_use_program(g_blit_prog);
    if (g_blit_u_mask >= 0) {
        gl_uniform1i(g_blit_u_mask, 0);
    }
    if (g_blit_u_alpha >= 0) {
        gl_uniform1f(g_blit_u_alpha, alpha);
    }
    gl_bind_tex(kGlTexture2D, g_cov_tex);
    if (gl_enable != nullptr) {
        gl_enable(kGlBlend);
    }
    if (gl_blend_func != nullptr) {
        gl_blend_func(kGlSrcAlpha, kGlOneMinusSrcAlpha);
    }
    if (gl_disable != nullptr) {
        gl_disable(kGlDepthTest);
    }
    gl_bind_buf(kGlArrayBuf, g_blit_vbo);
    gl_enable_va(0);
    gl_vertex_attrib(0, 2, kGlFloat, 0, 0, nullptr);
    gl_draw_cov(kGlTriStrip, 0, 4);

    gl_bind_buf(kGlArrayBuf, 0);
    gl_use_program(0);
    gl_bind_tex(kGlTexture2D, 0);
}

#endif


using Bvs_fn = void *(__fastcall *)(void *renderer);
Bvs_fn bind_vs = nullptr;

GetVertDesc_fn get_vert_desc = nullptr;
CreateVB_fn create_vb = nullptr;
ReleaseVb_fn release_vb = nullptr;
#ifdef _WIN32
void ProbeStep(const char *msg) {
    SHADOW_TRACE("[render.shadow] {}", msg);
    if (auto log = spdlog::default_logger()) {
        log->flush();
    }
    FILE *f = nullptr;
    if (fopen_s(&f, "C:\\Users\\fesil\\DontStarveLuaJIT2\\Mod\\flush_probe.txt", "a") == 0 &&
        f != nullptr) {
        std::fputs(msg, f);
        std::fputc('\n', f);
        std::fflush(f);
        std::fclose(f);
    }
}
void DumpSlots(void *r, const char *tag) {
    if (r == nullptr) {
        ProbeStep("slots null");
        return;
    }
    auto *p = static_cast<uint8_t *>(r);
    char line[256];
    std::snprintf(line, sizeof(line),
                  "slots %s last_vb=%#x vb=%#x cvd=%#x vd=%#x ib=%#x fx=%#x", tag,
                  *reinterpret_cast<uint32_t *>(p + 0x10),
                  *reinterpret_cast<uint32_t *>(p + 0x14),
                  *reinterpret_cast<uint32_t *>(p + 0x18),
                  *reinterpret_cast<uint32_t *>(p + 0x1C),
                  *reinterpret_cast<uint32_t *>(p + 0x20),
                  *reinterpret_cast<uint32_t *>(p + 0x2C));
    ProbeStep(line);
}

uint32_t TryCreateVB(void *r, uint32_t type, int n, uint16_t stride, void *data) {
    __try {
        return create_vb(r, type, n, stride, data, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xDEAD0001u;
    }
}
int TrySetTex(void *r, uint32_t slot, uint32_t tex) {
    __try {
        set_tex(r, slot, tex);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}
int TrySetVb(void *r, uint32_t vb) {
    __try {
        set_vb(r, vb);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}
int TryDraw(void *r, int start, int prim) {
    __try {
        draw(r, start, prim);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<int>(GetExceptionCode());
    }
}

using GetRes_fn = void *(__fastcall *)(void *mgr, uint32_t handle);
void DumpVbObj(void *renderer, uint32_t handle, const char *tag) {
    char line[256];
    if (draw == nullptr || renderer == nullptr) {
        ProbeStep("vbobj no draw");
        return;
    }
    auto get = reinterpret_cast<GetRes_fn>(reinterpret_cast<uint8_t *>(draw) - 0x3B0);
    void *mgr = *reinterpret_cast<void **>(static_cast<uint8_t *>(renderer) + 0x1A8);
    if (mgr == nullptr) {
        ProbeStep("vbobj no mgr");
        return;
    }
    void *obj = get(mgr, handle);
    if (obj == nullptr) {
        std::snprintf(line, sizeof(line), "vbobj %s h=%#x obj=null", tag, handle);
        ProbeStep(line);
        return;
    }
    auto *p = static_cast<uint8_t *>(obj);
    std::snprintf(line, sizeof(line),
                  "vbobj %s h=%#x obj=%p +8=%u +c=%u +10=%#x +14=%#x", tag, handle, obj,
                  *reinterpret_cast<uint32_t *>(p + 8), *reinterpret_cast<uint32_t *>(p + 0xC),
                  *reinterpret_cast<uint32_t *>(p + 0x10),
                  *reinterpret_cast<uint32_t *>(p + 0x14));
    ProbeStep(line);
}
using UploadVb_fn = void(__fastcall *)(void *hwbuf, void *data);
void *GetVbObj(void *renderer, uint32_t handle) {
    if (draw == nullptr || renderer == nullptr) {
        return nullptr;
    }
    auto get = reinterpret_cast<GetRes_fn>(reinterpret_cast<uint8_t *>(draw) - 0x3B0);
    void *mgr = *reinterpret_cast<void **>(static_cast<uint8_t *>(renderer) + 0x1A8);
    if (mgr == nullptr) {
        return nullptr;
    }
    return get(mgr, handle);
}
int TryUploadVb(void *obj, void *data) {
    if (obj == nullptr) {
        return -1;
    }
    auto **vt = *reinterpret_cast<void ***>(obj);
    if (vt == nullptr || vt[1] == nullptr) {
        return -2;
    }
    auto up = reinterpret_cast<UploadVb_fn>(vt[1]);
    __try {
        up(obj, data);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<int>(GetExceptionCode());
    }
}
int EnsureVbUploaded(void *renderer, uint32_t handle, void *data, uint32_t *gl_name) {
    void *obj = GetVbObj(renderer, handle);
    if (obj == nullptr) {
        return -1;
    }
    auto *p = static_cast<uint8_t *>(obj);
    const int up = TryUploadVb(obj, data);
    const uint32_t n = *reinterpret_cast<uint32_t *>(p + 0x10);
    if (gl_name != nullptr) {
        *gl_name = n;
    }
    return up;
}
int TryBindFx(void *renderer, uint32_t fx) {
    if (draw == nullptr || renderer == nullptr) {
        return -1;
    }
    auto get = reinterpret_cast<GetRes_fn>(reinterpret_cast<uint8_t *>(draw) - 0x3B0);
    void *mgr = *reinterpret_cast<void **>(static_cast<uint8_t *>(renderer) + 0x1B8);
    if (mgr == nullptr) {
        return -2;
    }
    void *obj = get(mgr, fx);
    if (obj == nullptr) {
        return -3;
    }
    auto **vt = *reinterpret_cast<void ***>(obj);
    if (vt == nullptr || vt[2] == nullptr) {
        return -4;
    }
    using BindFx_fn = void(__fastcall *)(void *effect, void *unk188, void *renderer_plus_10);
    auto bind = reinterpret_cast<BindFx_fn>(vt[2]);
    void *unk188 = *reinterpret_cast<void **>(static_cast<uint8_t *>(renderer) + 0x188);
    __try {
        bind(obj, unk188, static_cast<uint8_t *>(renderer) + 0x10);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<int>(GetExceptionCode());
    }

}




float *CsSlotDest(void *renderer, int slot) {
    if (renderer == nullptr || slot < 0 || !ReadableUserPtr(renderer, 0x194)) {
        return nullptr;
    }
    auto *r = static_cast<uint8_t *>(renderer);
    auto *cs = *reinterpret_cast<uint8_t **>(r + 0x188);
    if (!ReadableUserPtr(cs, 0x8390)) {
        return nullptr;
    }
    auto *table = *reinterpret_cast<uint8_t **>(cs + 0x8388);
    if (!ReadableUserPtr(table, static_cast<size_t>(slot + 1) * 144u)) {
        return nullptr;
    }
    auto *rec = table + static_cast<size_t>(slot) * 144u;
    const uint32_t n = *reinterpret_cast<uint32_t *>(rec + 0x88);
    if (n == 0) {
        return nullptr;
    }
    auto *entry = rec + 8 + static_cast<size_t>(n - 1u) * 16u;
    auto *dest = *reinterpret_cast<float **>(entry + 8);
    if (!ReadableUserPtr(dest, 64)) {
        return nullptr;
    }
    return dest;
}

bool Mat4AllFinite(const float *m) {
    for (int i = 0; i < 16; ++i) {
        if (!std::isfinite(m[i])) {
            return false;
        }
    }
    return true;
}

bool Mat4NearZero(const float *m) {
    for (int i = 0; i < 16; ++i) {
        if (std::fabs(m[i]) > 1e-6f) {
            return false;
        }
    }
    return true;
}

bool Mat4NearIdent(const float *m) {
    for (int i = 0; i < 16; ++i) {
        const float want = (i % 5 == 0) ? 1.f : 0.f;
        if (std::fabs(m[i] - want) > 1e-4f) {
            return false;
        }
    }
    return true;
}

bool LooksLikeProj(const float *m) {
    return std::fabs(m[11] + 1.f) < 0.15f ||
           (std::fabs(m[15]) < 1e-3f && std::fabs(m[14]) > 1e-3f);
}

bool LooksLikeView(const float *m) {

    if (m == nullptr || !Mat4AllFinite(m) || Mat4NearZero(m) || Mat4NearIdent(m)) {
        return false;
    }
    if (std::fabs(m[15] - 1.f) > 0.05f) {
        return false;
    }
    for (int c = 0; c < 3; ++c) {
        const float x = m[c * 4 + 0];
        const float y = m[c * 4 + 1];
        const float z = m[c * 4 + 2];
        const float len = std::sqrt(x * x + y * y + z * z);
        if (len < 0.4f || len > 2.5f) {
            return false;
        }
    }
    return true;
}

bool IsWorldScaleView(const float *m) {
    if (!LooksLikeView(m) || LooksLikeProj(m)) {
        return false;
    }
    const float tcol = std::fabs(m[12]) + std::fabs(m[13]) + std::fabs(m[14]);
    const float trow = std::fabs(m[3]) + std::fabs(m[7]) + std::fabs(m[11]);
    return tcol > 80.f || trow > 80.f;
}

bool IsIsoWorldView(const float *m) {
    return IsWorldScaleView(m) && std::fabs(std::fabs(m[0]) - 0.707f) < 0.15f;
}





int g_grab_v_off = -1;
float g_saved_p[16]{};
float g_saved_v[16]{};
bool g_have_saved_p = false;
bool g_have_saved_v = false;
float g_cs_v[16]{};
bool g_have_cs_v = false;
float g_world_p[16]{};
float g_world_v[16]{};
bool g_have_world_p = false;
bool g_have_world_v = false;
float g_anim_w[16]{};
bool g_have_anim_w = false;
float g_anim_p[16]{};
float g_anim_v[16]{};
bool g_have_anim_pv = false;


void ToGlMat(float o[16], const float *i);

void ConsiderWorldView(const float *m) {
    if (m == nullptr || !IsWorldScaleView(m)) {
        return;
    }
    float gl[16];
    const float tcol = std::fabs(m[12]) + std::fabs(m[13]) + std::fabs(m[14]);
    if (tcol > 80.f) {
        std::memcpy(gl, m, 64);
    } else {
        ToGlMat(gl, m);
    }
    if (!IsIsoWorldView(gl) && g_have_world_v && IsIsoWorldView(g_world_v)) {
        return;
    }
    std::memcpy(g_world_v, gl, 64);
    g_have_world_v = true;
}







constexpr size_t kGetMatrixTableOff = 0x778;
constexpr size_t kLayerCountOff = 0x868;
constexpr size_t kLayerStackOff = 0x86C;

int CurrentRenderLayer(void *renderer) {
    if (renderer == nullptr || !ReadableUserPtr(renderer, kLayerStackOff + 32)) {
        return -1;
    }
    auto *r = static_cast<uint8_t *>(renderer);
    const int n = *reinterpret_cast<int *>(r + kLayerCountOff);
    if (n <= 0 || n > 8) {
        return -1;
    }
    return *reinterpret_cast<int *>(r + kLayerStackOff + static_cast<size_t>(n - 1) * 4u);
}

float *GetMatrixSlot(void *renderer, int layer, int type) {
    if (renderer == nullptr || layer < 0 || layer > 8 || (type != 0 && type != 1) ||
        !ReadableUserPtr(renderer, kGetMatrixTableOff + 18 * 8)) {
        return nullptr;
    }
    auto *table = reinterpret_cast<float **>(static_cast<uint8_t *>(renderer) + kGetMatrixTableOff);
    float *m = table[layer * 2 + type];
    if (!ReadableUserPtr(m, 64) || !Mat4AllFinite(m)) {
        return nullptr;
    }
    return m;
}

float *GetMatrixByType(void *renderer, int type) {
    return GetMatrixSlot(renderer, CurrentRenderLayer(renderer), type);
}

float *FindViewMatrix(void *renderer) {
    for (int layer = 0; layer <= 8; ++layer) {
        for (int t = 0; t < 2; ++t) {
            float *m = GetMatrixSlot(renderer, layer, t);
            if (m != nullptr && IsWorldScaleView(m)) {

                g_grab_v_off = layer * 10 + t;
                return m;
            }
        }
    }
    return nullptr;
}


void ToGlMat(float o[16], const float *i) {
    if (convert_mat != nullptr) {
        convert_mat(o, i);
        return;
    }
    o[0] = i[0];
    o[1] = i[4];
    o[2] = i[8];
    o[3] = i[12];
    o[4] = i[1];
    o[5] = i[5];
    o[6] = i[9];
    o[7] = i[13];
    o[8] = i[2];
    o[9] = i[6];
    o[10] = i[10];
    o[11] = i[14];
    o[12] = i[3];
    o[13] = i[7];
    o[14] = i[11];
    o[15] = i[15];
}

int GrabCameraPV(void *renderer, float p[16], float v[16]) {
    if (renderer == nullptr || !ReadableUserPtr(renderer, 0xA00)) {
        return -1;
    }
    g_grab_v_off = CurrentRenderLayer(renderer);
    bool have_p = false;
    bool have_v = false;
    if (g_have_anim_pv && IsIsoWorldView(g_anim_v)) {
        std::memcpy(p, g_anim_p, 64);
        std::memcpy(v, g_anim_v, 64);
        have_p = true;
        have_v = true;
        g_grab_v_off = 401;
    } else if (g_have_world_p && g_have_world_v && IsIsoWorldView(g_world_v)) {
        std::memcpy(p, g_world_p, 64);
        std::memcpy(v, g_world_v, 64);
        have_p = true;
        have_v = Mat4AllFinite(v) && !Mat4NearIdent(v);
        g_grab_v_off = 301;
    }

    if (!have_p) {
        float *cs6 = CsSlotDest(renderer, 6);
        float *mp = GetMatrixByType(renderer, 1);
        if (cs6 != nullptr && LooksLikeProj(cs6)) {
            std::memcpy(p, cs6, 64);
            have_p = true;
        } else if (mp != nullptr && LooksLikeProj(mp)) {
            ToGlMat(p, mp);
            have_p = true;
        } else if (g_have_saved_p) {
            std::memcpy(p, g_saved_p, 64);
            have_p = true;
        }
    }
    if (!have_v) {
        float *cs_v = nullptr;
        for (int s = 0; s <= 8; ++s) {
            float *cs = CsSlotDest(renderer, s);
            if (cs != nullptr && IsIsoWorldView(cs)) {
                cs_v = cs;
                g_grab_v_off = 100 + s;
                break;
            }
        }
        if (cs_v != nullptr) {
            std::memcpy(v, cs_v, 64);
            have_v = Mat4AllFinite(v) && !Mat4NearIdent(v);
        } else if (g_have_world_v && IsWorldScaleView(g_world_v)) {
            std::memcpy(v, g_world_v, 64);
            g_grab_v_off = 302;
            have_v = true;
        } else {
            float *live_v = FindViewMatrix(renderer);
            if (live_v != nullptr) {
                ToGlMat(v, live_v);
                have_v = Mat4AllFinite(v) && !Mat4NearIdent(v);
            } else if (g_have_saved_v) {
                ToGlMat(v, g_saved_v);
                have_v = true;
            }
        }
    }
    if (!have_p) {
        return -4;
    }
    if (!have_v) {
        return -5;
    }
    return 1;
}


void LogClip(const float p[16], const float v[16], float x, float y, float z) {
    const float pos[4] = {x, y, z, 1.f};
    float eye[4]{};
    float clip[4]{};
    for (int r = 0; r < 4; ++r) {
        eye[r] = v[r] * pos[0] + v[r + 4] * pos[1] + v[r + 8] * pos[2] + v[r + 12] * pos[3];
    }
    for (int r = 0; r < 4; ++r) {
        clip[r] = p[r] * eye[0] + p[r + 4] * eye[1] + p[r + 8] * eye[2] + p[r + 12] * eye[3];
    }
    const float w = clip[3] != 0.f ? clip[3] : 1.f;
    char line[192];
    std::snprintf(line, sizeof(line), "clip xyz=%.1f,%.1f,%.1f ndc=%.3f,%.3f,%.3f w=%.3f", x, y, z,
                  clip[0] / w, clip[1] / w, clip[2] / w, w);
    ProbeStep(line);
}
void LogClipTag(const char *tag, const float p[16], const float v[16], float x, float y,
                float z, bool row) {
    const float pos[4] = {x, y, z, 1.f};
    float eye[4]{};
    float clip[4]{};
    if (row) {
        for (int r = 0; r < 4; ++r) {
            eye[r] = v[r * 4 + 0] * pos[0] + v[r * 4 + 1] * pos[1] + v[r * 4 + 2] * pos[2] +
                     v[r * 4 + 3] * pos[3];
        }
        for (int r = 0; r < 4; ++r) {
            clip[r] = p[r * 4 + 0] * eye[0] + p[r * 4 + 1] * eye[1] + p[r * 4 + 2] * eye[2] +
                      p[r * 4 + 3] * eye[3];
        }
    } else {
        for (int r = 0; r < 4; ++r) {
            eye[r] = v[r] * pos[0] + v[r + 4] * pos[1] + v[r + 8] * pos[2] + v[r + 12] * pos[3];
        }
        for (int r = 0; r < 4; ++r) {
            clip[r] = p[r] * eye[0] + p[r + 4] * eye[1] + p[r + 8] * eye[2] + p[r + 12] * eye[3];
        }
    }
    const float w = clip[3] != 0.f ? clip[3] : 1.f;
    char line[224];
    std::snprintf(line, sizeof(line), "clip %s xyz=%.1f,%.1f,%.1f ndc=%.3f,%.3f,%.3f w=%.3f", tag, x,
                  y, z, clip[0] / w, clip[1] / w, clip[2] / w, w);
    ProbeStep(line);
}

void LogAnimWAndSweep(const float p[16], const float v[16], float ox, float oz) {
    LogClipTag("xz0", p, v, ox, 0.f, oz, false);
    LogClipTag("xy0", p, v, ox, oz, 0.f, false);
    LogClipTag("zx0", p, v, oz, 0.f, ox, false);
    LogClipTag("xnz", p, v, ox, 0.f, -oz, false);
    LogClipTag("nxz", p, v, -ox, 0.f, oz, false);
    LogClipTag("row-xz0", p, v, ox, 0.f, oz, true);
    if (g_have_anim_w) {
        const float tx = g_anim_w[3];
        const float ty = g_anim_w[7];
        const float tz = g_anim_w[11];
        const float rx = g_anim_w[12];
        const float ry = g_anim_w[13];
        const float rz = g_anim_w[14];
        char line[224];
        std::snprintf(line, sizeof(line),
                      "animw col=%.2f,%.2f,%.2f row=%.2f,%.2f,%.2f d0=%.3f d5=%.3f d10=%.3f", tx,
                      ty, tz, rx, ry, rz, g_anim_w[0], g_anim_w[5], g_anim_w[10]);
        ProbeStep(line);
        LogClipTag("wcol", p, v, tx, ty, tz, false);
        LogClipTag("wrow", p, v, rx, ry, rz, false);
    } else {
        ProbeStep("animw missing");
    }
}






uint32_t FxGlProgram(void *renderer, uint32_t fx) {
    if (renderer == nullptr || fx == 0 || fx == 0xFFFFFFFFu || get_vert_desc == nullptr) {
        return 0;
    }
    void *mgr = *reinterpret_cast<void **>(static_cast<uint8_t *>(renderer) + 0x1B8);
    if (mgr == nullptr) {
        return 0;
    }
    void *hw = get_vert_desc(mgr, fx);
    if (!ReadableUserPtr(hw, 0xF0)) {
        return 0;
    }
    return *reinterpret_cast<uint32_t *>(static_cast<uint8_t *>(hw) + 0xEC);
}


void *TryBvs(void *r) {
    __try {
        return bind_vs(r);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return reinterpret_cast<void *>(static_cast<uintptr_t>(GetExceptionCode()));
    }
}

int TryReleaseVb(void *rm, uint32_t vb) {
    __try {
        release_vb(rm, vb);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}
#endif

#ifdef _WIN32
constexpr uint32_t kLoadShaderRva = 0x3e9f00;

bool BindSilLoadFns() noexcept {
    GumModule *main = gum_process_get_main_module();
    if (main == nullptr) {
        load_shader = nullptr;
        return false;
    }
    const GumMemoryRange *range = gum_module_get_range(main);
    if (range == nullptr) {
        load_shader = nullptr;
        return false;
    }
    auto *base = reinterpret_cast<uint8_t *>(range->base_address);
    static const uint8_t kPrologue[] = {0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55,
                                        0x41, 0x56, 0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00};
    if (base == nullptr || kLoadShaderRva + sizeof(kPrologue) > range->size) {
        load_shader = nullptr;
        return false;
    }
    auto *ls = base + kLoadShaderRva;
    if (std::memcmp(ls, kPrologue, sizeof(kPrologue)) != 0) {
        spdlog::warn("[render.shadow] LoadShader prologue miss base={:#x}",
                     reinterpret_cast<uintptr_t>(base));
        load_shader = nullptr;
        return false;
    }
    load_shader = reinterpret_cast<LoadShader_fn>(ls);
    return true;
}

std::string SilKshAbsolutePath() {
    HMODULE self = nullptr;
    if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCWSTR>(&SilKshAbsolutePath), &self) ||
        self == nullptr) {
        return {};
    }
    char buf[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameA(self, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return {};
    }
    std::string p(buf, n);
    const auto slash = p.find_last_of("\\/");
    if (slash == std::string::npos) {
        return {};
    }
    p.resize(slash);
    p += "\\shaders\\sil.ksh";
    return p;
}


bool LoadSilFromRendererImpl(void *game_renderer) noexcept {

    if (g_sil_fx != 0 && g_sil_vd != 0) {
        return true;
    }
    if (!BindSilLoadFns() || load_shader == nullptr) {
        return false;
    }
    auto *renderer = static_cast<uint8_t *>(game_renderer);
    if (!ReadableUserPtr(renderer, 0x1C0)) {
        return false;
    }
    void *fx_mgr = *reinterpret_cast<void **>(renderer + 0x1B8);
    void *vd_mgr = *reinterpret_cast<void **>(renderer + 0x1A0);
    if (!ReadableUserPtr(fx_mgr, 0x60) || !ReadableUserPtr(vd_mgr, 0x60)) {
        return false;
    }

    const std::string path = SilKshAbsolutePath();
    if (path.empty()) {
        return false;
    }
    if (::GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        spdlog::error("[render.shadow] sil.ksh missing at {}", path);
        return false;
    }
    const uint32_t prev_fx =
        *reinterpret_cast<uint32_t *>(renderer + kRendererEffectHandleOff);
    const uint32_t fx = load_shader(fx_mgr, path.c_str(), true, false, 0);
    if (prev_fx != 0 && prev_fx != 0xFFFFFFFFu) {
        WriteRendererEffectHandle(game_renderer, prev_fx);
    }
    if (fx == 0 || fx == 0xFFFFFFFFu) {
        spdlog::error("[render.shadow] LoadShader failed path={}", path);
        g_sil_fx = 0;
        return false;
    }
    g_sil_fx = fx;
    if (!ReadableUserPtr(g_game, 0x78)) {
        spdlog::warn("[render.shadow] sil vd steal: no cGame");
        return false;
    }
    auto *anim_mgr = *reinterpret_cast<void **>(static_cast<uint8_t *>(g_game) + 0x70);
    if (!ReadableUserPtr(anim_mgr, 0x134)) {
        spdlog::warn("[render.shadow] sil vd steal: no AnimManager");
        return false;
    }
    const uint32_t vd =
        *reinterpret_cast<uint32_t *>(static_cast<uint8_t *>(anim_mgr) + 0x130);
    if (vd == 0 || vd == 0xFFFFFFFFu) {
        spdlog::warn("[render.shadow] sil vd steal: AnimManager+0x130 empty");
        return false;
    }
    g_sil_fx = fx;
    g_sil_vd = vd;
    SHADOW_TRACE("[render.shadow] sil.ksh fx={:#x} vd={:#x} path={}", fx, vd, path);
    return true;
}
#endif


void *Rel32Target(const uint8_t *call) {
    if (call == nullptr || call[0] != 0xE8) {
        return nullptr;
    }
    int32_t rel = 0;
    std::memcpy(&rel, call + 1, sizeof(rel));
    return const_cast<uint8_t *>(call + 5 + rel);
}
void *Rel32Jmp(const uint8_t *jmp) {
    if (jmp == nullptr || jmp[0] != 0xE9) {
        return nullptr;
    }
    int32_t rel = 0;
    std::memcpy(&rel, jmp + 1, sizeof(rel));
    return const_cast<uint8_t *>(jmp + 5 + rel);
}

void *RipRel(const uint8_t *insn, size_t len) {
    if (insn == nullptr || len < 5) {
        return nullptr;
    }
    int32_t rel = 0;
    std::memcpy(&rel, insn + len - 4, sizeof(rel));
    return const_cast<uint8_t *>(insn + len + rel);
}


float HalfToFloat(uint16_t h) noexcept {
    uint32_t bits = 0;
    if ((h & 0x7c00u) != 0) {
        bits = static_cast<uint32_t>((h & 0x7fffu) + 0x1c000u) * 0x2000u;
    }
    bits |= static_cast<uint32_t>(h & 0x8000u) << 16;
    float f = 0.f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

void ElemAffine(const uint8_t *elem, float m[16]) noexcept {
    const auto h = [elem](size_t off) {
        uint16_t v = 0;
        std::memcpy(&v, elem + off, sizeof(v));
        return HalfToFloat(v);
    };
    m[0] = h(0x24);
    m[1] = h(0x28);
    m[2] = 0.f;
    m[3] = h(0x2c);
    m[4] = h(0x26);
    m[5] = h(0x2a);
    m[6] = 0.f;
    m[7] = h(0x2e);
    m[8] = 0.f;
    m[9] = 0.f;
    m[10] = 1.f;
    m[11] = 0.f;
    m[12] = 0.f;
    m[13] = 0.f;
    m[14] = 0.f;
    m[15] = 1.f;
}

void MulMat(float dest[16], const float a[16], const float b[16]) noexcept {
    if (mat_mul != nullptr) {
        mat_mul(dest, a, b);
        return;
    }
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            dest[r * 4 + c] = a[r * 4 + 0] * b[0 * 4 + c] + a[r * 4 + 1] * b[1 * 4 + c] +
                              a[r * 4 + 2] * b[2 * 4 + c] + a[r * 4 + 3] * b[3 * 4 + c];
        }
    }
}


bool HiddenLayer(const uint8_t *tdc, uint32_t layer_hash) noexcept {
    const uint32_t *begin = nullptr;
    const uint32_t *end = nullptr;
    std::memcpy(&begin, tdc + 0x148, sizeof(begin));
    std::memcpy(&end, tdc + 0x150, sizeof(end));
    if (begin == nullptr || end == nullptr || end <= begin) {
        return false;
    }
    const auto bytes = static_cast<size_t>(reinterpret_cast<const uint8_t *>(end) -
                                           reinterpret_cast<const uint8_t *>(begin));
    if ((bytes & 0xF) != 0 || bytes > 0x10000) {
        return false;
    }
    // Binary search, 16B entries, hash at +0 (FUN_1400eff60).
    const uint32_t *lo = begin;
    const uint32_t *hi = end;
    while (lo < hi) {
        const auto n = static_cast<size_t>(hi - lo) / 4;
        const uint32_t *mid = lo + (n / 2) * 4;
        if (*mid < layer_hash) {
            lo = mid + 4;
        } else {
            hi = mid;
        }
    }
    return lo != end && *lo == layer_hash;
}

void *GetBuildFrame(const uint8_t *build, uint32_t symbol_hash, uint32_t frame_index) noexcept {
    if (build == nullptr) {
        return nullptr;
    }
    auto *syms = *reinterpret_cast<uint8_t **>(const_cast<uint8_t *>(build) + 0x70);
    const uint32_t nsym = *reinterpret_cast<const uint32_t *>(build + 0xA0);
    if (syms == nullptr || nsym == 0 || nsym > 0x10000) {
        return nullptr;
    }
    uint32_t lo = 0;
    uint32_t hi = nsym;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2;
        auto *ent = syms + static_cast<size_t>(mid) * 0x20u;
        const uint32_t h = *reinterpret_cast<uint32_t *>(ent);
        if (h < symbol_hash) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo >= nsym) {
        return nullptr;
    }
    auto *ent = syms + static_cast<size_t>(lo) * 0x20u;
    if (*reinterpret_cast<uint32_t *>(ent) != symbol_hash) {
        return nullptr;
    }
    auto *frames = *reinterpret_cast<uint8_t **>(ent + 0x10);
    const uint32_t nfr = *reinterpret_cast<uint32_t *>(ent + 0x18);
    if (frames == nullptr || nfr == 0 || nfr > 0x10000) {
        return nullptr;
    }
    for (uint32_t i = 0; i < nfr; ++i) {
        auto *fr = frames + static_cast<size_t>(i) * 0x34u;
        const uint32_t start = *reinterpret_cast<uint32_t *>(fr + 0x00);
        const uint32_t count = *reinterpret_cast<uint32_t *>(fr + 0x04);
        if (start <= frame_index && frame_index < start + count) {
            return fr;
        }
    }
    return nullptr;
}


void *DsListFromTdc(void *tdc) noexcept {
    if (tdc == nullptr || get_ds_list == nullptr || !ReadableUserPtr(tdc, 16)) {
        return nullptr;
    }
    auto *anim_node = *reinterpret_cast<uint8_t **>(static_cast<uint8_t *>(tdc) + 0x08);
    if (!ReadableUserPtr(anim_node, 0x80)) {
        return nullptr;
    }
    auto *game = *reinterpret_cast<uint8_t **>(anim_node + 0x78);
    if (!ReadableUserPtr(game, 0x30)) {
        return nullptr;
    }
    auto *sim = *reinterpret_cast<uint8_t **>(game + 0x28);
    if (!ReadableUserPtr(sim, 0xA8)) {
        return nullptr;
    }
    auto *emgr = *reinterpret_cast<void **>(sim + 0xA0);
    if (!ReadableUserPtr(emgr, 8)) {
        return nullptr;
    }
    return get_ds_list(emgr);
}



void AppendRun(uint32_t tex, uint32_t start, uint32_t count) {
    if (count == 0) {
        return;
    }
    g_runs.push_back(Run{tex, start, count});
}


} // namespace
void NoteCameraSlot(void *renderer, int slot, const float *m) noexcept {
    if (m == nullptr || !Mat4AllFinite(m) || Mat4NearZero(m) || Mat4NearIdent(m)) {
        return;
    }
    int pass = -1;
    if (renderer != nullptr && ReadableUserPtr(renderer, 0x934)) {
        pass = *reinterpret_cast<int *>(static_cast<uint8_t *>(renderer) + 0x930);
    }
    static uint32_t nnote = 0;
    if (LooksLikeProj(m) && (pass == 1 || !g_have_world_p)) {
        std::memcpy(g_saved_p, m, 64);
        g_have_saved_p = true;
        if (LooksLikeProj(m)) {
            std::memcpy(g_world_p, m, 64);
            g_have_world_p = true;
        }
    }
    ConsiderWorldView(m);
    if (IsWorldScaleView(m)) {
        std::memcpy(g_saved_v, m, 64);
        g_have_saved_v = true;
    }
    if (nnote < 8) {
        ++nnote;
        SHADOW_TRACE("[render.shadow] camslot n={} slot={} pass={} wp={} wv={} "
                     "m0={:.3f} m12={:.3f} m13={:.3f} m14={:.3f} m15={:.3f}",
                     nnote, slot, pass, g_have_world_p ? 1 : 0, g_have_world_v ? 1 : 0, m[0],
                     m[12], m[13], m[14], m[15]);
    }
}

void NoteAnimWorld(const float *engine_m) noexcept {
    if (engine_m == nullptr || !Mat4AllFinite(engine_m)) {
        return;
    }
    std::memcpy(g_anim_w, engine_m, 64);
    g_have_anim_w = true;
    g_have_anim_w = true;
}

void NoteAnimCamera(void *renderer) noexcept {
    if (renderer == nullptr) {
        return;
    }
    float *pv = GetMatrixByType(renderer, 1);
    float *vv = GetMatrixByType(renderer, 0);
    if (pv != nullptr && LooksLikeProj(pv)) {
        const float tcol = std::fabs(pv[12]) + std::fabs(pv[13]) + std::fabs(pv[14]);
        if (std::fabs(pv[11] + 1.f) < 0.15f && tcol < 1.f) {
            ToGlMat(g_anim_p, pv);
        } else {
            std::memcpy(g_anim_p, pv, 64);
        }
    }
    if (vv != nullptr && LooksLikeView(vv)) {
        const float tcol = std::fabs(vv[12]) + std::fabs(vv[13]) + std::fabs(vv[14]);
        if (tcol > 80.f) {
            std::memcpy(g_anim_v, vv, 64);
        } else {
            ToGlMat(g_anim_v, vv);
        }
        if (IsIsoWorldView(g_anim_v) || IsWorldScaleView(g_anim_v)) {
            g_have_anim_pv = Mat4AllFinite(g_anim_p) && LooksLikeProj(g_anim_p);
            ConsiderWorldView(g_anim_v);
        }
    }
}

bool HaveAnimCamera() noexcept { return g_have_anim_pv; }



void SnapshotCameraCs(void *renderer) noexcept {
    if (renderer == nullptr || !ReadableUserPtr(renderer, 0xA00)) {
        return;
    }
    int pass = -1;
    if (ReadableUserPtr(renderer, 0x934)) {
        pass = *reinterpret_cast<int *>(static_cast<uint8_t *>(renderer) + 0x930);
    }
    static uint32_t nsnap = 0;
    const bool chatter = nsnap < 8;
    ++nsnap;
    float *cs6 = CsSlotDest(renderer, 6);
    float *cs5 = CsSlotDest(renderer, 5);
    if (cs6 != nullptr && LooksLikeProj(cs6) && (pass == 1 || !g_have_world_p)) {
        std::memcpy(g_world_p, cs6, 64);
        g_have_world_p = true;
    }
    if (cs5 != nullptr) {
        ConsiderWorldView(cs5);
    }
    if (cs5 != nullptr && LooksLikeView(cs5) && !LooksLikeProj(cs5)) {
        std::memcpy(g_cs_v, cs5, 64);
        g_have_cs_v = true;
    }
    float *found = FindViewMatrix(renderer);
    if (found != nullptr) {
        ConsiderWorldView(found);
        std::memcpy(g_saved_v, found, 64);
        g_have_saved_v = true;
    }
    if (chatter) {
        SHADOW_TRACE("[render.shadow] dcrsnap n={} pass={} wp={} wv={} v0={:.3f} v12={:.1f} v14={:.1f}",
                     nsnap, pass, g_have_world_p ? 1 : 0, g_have_world_v ? 1 : 0,
                     g_have_world_v ? g_world_v[0] : 0.f,
                     g_have_world_v ? g_world_v[12] : 0.f,
                     g_have_world_v ? g_world_v[14] : 0.f);
    }
}





bool LoadSilFromRenderer(void *game_renderer) noexcept {
#ifdef _WIN32
    return LoadSilFromRendererImpl(game_renderer);
#else
    (void)game_renderer;
    return false;
#endif
}


bool ReadableUserPtr(const void *p, size_t bytes) noexcept {
    const auto u = reinterpret_cast<uintptr_t>(p);
    if (p == nullptr || (u & 0x7u) != 0 || u < 0x10000u || (u >> 47) != 0) {
        return false;
    }
    if (bytes == 0 || u + bytes < u) {
        return false;
    }
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT) {
        return false;
    }
    const DWORD prot = mbi.Protect & 0xffu;
    if (prot == 0 || prot == PAGE_NOACCESS || prot == PAGE_EXECUTE) {
        return false;
    }
    const auto base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    if (u + bytes > base + mbi.RegionSize) {
        return false;
    }
#endif
    return true;
}


void SetSilhouetteEnabled(bool on) noexcept { g_on.store(on ? 1 : 0, std::memory_order_release); }
bool IsSilhouetteEnabled() noexcept { return g_on.load(std::memory_order_acquire) != 0; }
bool IsSilhouetteHealthy() noexcept { return g_healthy.load(std::memory_order_acquire) != 0; }
void SetSilhouetteHealthy(bool ok) noexcept {
    g_healthy.store(ok ? 1 : 0, std::memory_order_release);
}
bool MarkSilhouetted(void *entity) {
    if (entity == nullptr) {
        return false;
    }
    g_set.insert(entity);
    return true;
}
bool IsSilhouetted(const void *entity) noexcept {
    return entity != nullptr && g_set.find(entity) != g_set.end();
}
void ClearSilhouetted() noexcept { g_set.clear(); }
size_t SilhouettedCount() noexcept { return g_set.size(); }
size_t BatchVertCount() noexcept {
    size_t n = g_cpu.size();
    for (const auto &gr : g_gpu) {
        n += gr.count;
    }
    return n;
}

size_t BatchRunCount() noexcept { return g_runs.size(); }
uint32_t BatchEffectHandle() noexcept { return g_effect; }
uint32_t BatchVertDescHandle() noexcept { return g_vd; }


bool BindSilhouetteHelpers(uintptr_t anim_dcr, uintptr_t shadow_dcr, uintptr_t generate_vb) {
    auto *sd = reinterpret_cast<const uint8_t *>(shadow_dcr);
    auto *gv = reinterpret_cast<const uint8_t *>(generate_vb);

    if (anim_dcr != 0) {
        auto *ad = reinterpret_cast<const uint8_t *>(anim_dcr);
        get_anim_frame = reinterpret_cast<GetAnimFrame_fn>(Rel32Target(ad + 0x37));
        calc_scale = reinterpret_cast<CalcScale_fn>(Rel32Target(ad + 0xA4));
        mat_mul = reinterpret_cast<MatMul_fn>(Rel32Target(ad + 0xF9));
    }

    set_effect = reinterpret_cast<SetEffect_fn>(Rel32Target(sd + 0x28));
    set_vd = reinterpret_cast<SetVd_fn>(Rel32Target(sd + 0x33));
    set_tex = reinterpret_cast<SetTex_fn>(Rel32Target(sd + 0x41));
    set_vb = reinterpret_cast<SetVb_fn>(Rel32Target(sd + 0x55));
    draw = reinterpret_cast<Draw_fn>(Rel32Target(sd + 0x63));
    release_vb = reinterpret_cast<ReleaseVb_fn>(Rel32Target(sd + 0x7F));
    get_ds_list = reinterpret_cast<GetDsList_fn>(Rel32Target(sd + 0x9D));

    get_vert_desc = reinterpret_cast<GetVertDesc_fn>(Rel32Target(gv + 0x32));
    create_vb = reinterpret_cast<CreateVB_fn>(Rel32Target(gv + 0x1A9));
    (void)BindSilLoadFns();

    return set_tex != nullptr && set_vd != nullptr && set_vb != nullptr && create_vb != nullptr &&
           get_ds_list != nullptr && get_vert_desc != nullptr && draw != nullptr;

}

bool CanBindAnimKsh() noexcept {
    return set_effect != nullptr && set_vd != nullptr && set_tex != nullptr;
}

void BindGetAnimFrame(uintptr_t fn) noexcept {
    if (fn != 0) {
        get_anim_frame = reinterpret_cast<GetAnimFrame_fn>(fn);
    }
}

void BindHwEffectBind(uintptr_t fn) noexcept {
    hw_bind = (fn != 0) ? reinterpret_cast<HwBind_fn>(fn) : nullptr;
}

bool BindProgramPinned() noexcept { return hw_bind != nullptr; }


void BindAnimDraw(uintptr_t fn) noexcept {
    anim_draw = (fn != 0) ? reinterpret_cast<AnimDraw_fn>(fn) : nullptr;
}



uintptr_t SetUniformAddress() noexcept {
    return reinterpret_cast<uintptr_t>(set_uniform);
}
uintptr_t GlDrawArraysAddress() noexcept {
    return reinterpret_cast<uintptr_t>(gl_draw_arrays);
}
void **GlDrawArraysIat() noexcept { return gl_draw_iat; }

uint32_t HwEffectGlProgram(void *renderer) noexcept {
    if (renderer == nullptr || !ReadableUserPtr(renderer, 0x1C0) || get_vert_desc == nullptr) {
        return 0;
    }
    auto *r = static_cast<uint8_t *>(renderer);
    const uint32_t fx = *reinterpret_cast<uint32_t *>(r + kRendererEffectHandleOff);
    void *mgr = *reinterpret_cast<void **>(r + 0x1B8);
    if (fx == 0 || fx == 0xFFFFFFFFu || mgr == nullptr) {
        return 0;
    }
    void *hw = get_vert_desc(mgr, fx);
    if (!ReadableUserPtr(hw, 0xF0)) {
        return 0;
    }
    return *reinterpret_cast<uint32_t *>(static_cast<uint8_t *>(hw) + 0xEC);
}



void SetGroundPoke(bool on) noexcept { g_ground_poke = on; }

bool IsGroundPoke() noexcept { return g_ground_poke; }

void BumpSlot7Stamp(void *game_renderer) noexcept {
    if (game_renderer == nullptr || !ReadableUserPtr(game_renderer, 0x934)) {
        return;
    }
    auto *r = static_cast<uint8_t *>(game_renderer);
    auto *cs = *reinterpret_cast<uint8_t **>(r + 0x188);
    if (!ReadableUserPtr(cs, 16)) {
        return;
    }
    const uint32_t idx = *reinterpret_cast<uint32_t *>(cs);
    if (idx < 16) {
        return;
    }
    auto *dest = reinterpret_cast<float *>(cs + 8 + static_cast<size_t>(idx - 16u) * 4u);
    const auto du = reinterpret_cast<uintptr_t>(dest);
    if (dest == nullptr || (du & 3u) != 0 || du < 0x10000u) {
        return;
    }
    ++*reinterpret_cast<uint32_t *>(dest + 16);
}



static void Transpose16(float o[16], const float i[16]) noexcept {
    o[0] = i[0];
    o[1] = i[4];
    o[2] = i[8];
    o[3] = i[12];
    o[4] = i[1];
    o[5] = i[5];
    o[6] = i[9];
    o[7] = i[13];
    o[8] = i[2];
    o[9] = i[6];
    o[10] = i[10];
    o[11] = i[14];
    o[12] = i[3];
    o[13] = i[7];
    o[14] = i[11];
    o[15] = i[15];
}

void PokeFlattenSlot7(void *, const float *) noexcept {}

void SilhouetteDepthWrite(bool) noexcept {}









void NoteGameAnimManager(void *game) noexcept {
    if (!ReadableUserPtr(game, 0x78)) {
        return;
    }
    g_game = game;
}

void *ActiveGameRenderer() noexcept {
    if (g_game == nullptr || !ReadableUserPtr(g_game, 0x50)) {
        return nullptr;
    }
    return *reinterpret_cast<void **>(static_cast<uint8_t *>(g_game) + 0x48);
}


void NoteAnimPassHandles(void *renderer) noexcept {
    if (g_anim_pass_fx != 0 || renderer == nullptr || !ReadableUserPtr(renderer, 0x1C0)) {
        return;
    }
    auto *r = static_cast<uint8_t *>(renderer);
    if (*reinterpret_cast<int *>(r + 0x930) != 2) {
        return;
    }
    const uint32_t fx = *reinterpret_cast<uint32_t *>(r + kRendererEffectHandleOff);
    if (fx == 0 || fx == 0xFFFFFFFFu || fx == g_sil_fx) {
        return;
    }
    void *mgr = *reinterpret_cast<void **>(r + 0x1B8);
    if (get_vert_desc != nullptr && mgr != nullptr) {
        void *hw = get_vert_desc(mgr, fx);
        if (!ReadableUserPtr(hw, 0xC0)) {
            return;
        }
        if (*reinterpret_cast<void **>(static_cast<uint8_t *>(hw) + 0xB8) == nullptr) {
            return;
        }
    }
    const uint32_t vd = *reinterpret_cast<uint32_t *>(r + kRendererVertDescHandleOff);
    g_anim_pass_fx = fx;
    if (vd != 0 && vd != 0xFFFFFFFFu) {
        g_anim_pass_vd = vd;
    }
}



bool LoadSilShader() noexcept {
    if (g_sil_fx != 0 && g_sil_vd != 0) {
        return true;
    }
#ifdef _WIN32
    if (g_game == nullptr || !ReadableUserPtr(g_game, 0x50)) {
        return false;
    }
    auto *renderer = *reinterpret_cast<void **>(static_cast<uint8_t *>(g_game) + 0x48);
    return LoadSilFromRendererImpl(renderer);

#else
    return false;
#endif
}

uint32_t SilEffectHandle() noexcept { return g_sil_fx; }
uint32_t SilVertDescHandle() noexcept { return g_sil_vd; }


void *EntityFromTdcViaDsList(void *tdc) noexcept {
    if (tdc == nullptr) {
        return nullptr;
    }
    auto *want_node = *reinterpret_cast<uint8_t **>(static_cast<uint8_t *>(tdc) + 0x08);
    if (want_node == nullptr) {
        return nullptr;
    }
    auto *list = DsListFromTdc(tdc);
    if (list == nullptr) {
        return nullptr;
    }
    auto *begin = *reinterpret_cast<uint8_t **>(static_cast<uint8_t *>(list) + 0x08);
    auto *end = *reinterpret_cast<uint8_t **>(static_cast<uint8_t *>(list) + 0x10);
    if (begin == nullptr || end == nullptr || end < begin) {
        return nullptr;
    }
    const auto bytes = static_cast<size_t>(end - begin);
    if (bytes > 0x100000u || (bytes % sizeof(void *)) != 0) {
        return nullptr;
    }
    for (auto *it = begin; it < end; it += sizeof(void *)) {
        auto *comp = *reinterpret_cast<uint8_t **>(it);
        if (comp == nullptr || comp[0x28] == 0) {
            continue;
        }
        auto *entity = *reinterpret_cast<uint8_t **>(comp + 0x18);
        if (entity == nullptr || entity[0x1B4] != 0) {
            continue;
        }
        auto *anim_state = *reinterpret_cast<uint8_t **>(entity + 0x1D0);
        if (anim_state == nullptr) {
            continue;
        }
        auto *node = *reinterpret_cast<uint8_t **>(anim_state + 0xF0);
        if (node == want_node) {
            return entity;
        }
    }
    return nullptr;
}

static uint8_t *TdcFromNode(uint8_t *node) noexcept {
    if (!ReadableUserPtr(node, 16)) {
        return nullptr;
    }
    auto *inner = *reinterpret_cast<uint8_t **>(node + 8);
    if (ReadableUserPtr(inner, 0xC0)) {
        auto *sanim = *reinterpret_cast<void **>(inner + 0xB0);
        auto *sbuild = *reinterpret_cast<void **>(inner + 0xB8);
        if (ReadableUserPtr(sanim) && ReadableUserPtr(sbuild)) {
            return inner;
        }
    }
    if (ReadableUserPtr(node, 0xC0)) {
        auto *sanim = *reinterpret_cast<void **>(node + 0xB0);
        auto *sbuild = *reinterpret_cast<void **>(node + 0xB8);
        if (ReadableUserPtr(sanim) && ReadableUserPtr(sbuild)) {
            return node;
        }
    }
    return nullptr;
}

bool PackEntityAnim(void *entity, const SunSample &sample) {
    if (entity == nullptr || !ReadableUserPtr(entity, 0x280)) {
        return false;
    }


    auto *eb = static_cast<uint8_t *>(entity);
    uint8_t *tdc = nullptr;
    size_t hit_off = 0;
    const size_t try_off[] = {0x170, 0x1D0, 0x1C8, 0x1D8, 0x1C0, 0x1E0};

    for (size_t off : try_off) {
        auto *as = *reinterpret_cast<uint8_t **>(eb + off);
        if (!ReadableUserPtr(as, 0xF8)) {
            continue;
        }
        auto *node = *reinterpret_cast<uint8_t **>(as + 0xF0);
        tdc = TdcFromNode(node);
        if (tdc != nullptr) {
            hit_off = off;
            break;
        }
        tdc = TdcFromNode(as);
        if (tdc != nullptr) {
            hit_off = off;
            break;
        }
    }
    if (tdc == nullptr) {
        for (size_t off = 0x100; off < 0x280 && tdc == nullptr; off += 8) {
            auto *p = *reinterpret_cast<uint8_t **>(eb + off);
            tdc = TdcFromNode(p);
            if (tdc != nullptr) {
                hit_off = off;
            }
        }
    }
    static uint32_t nscan = 0;
    if (tdc == nullptr) {
        if (nscan < 6) {
            ++nscan;
            SHADOW_TRACE("[render.shadow] pack-entity miss e={:p}", entity);
        }
        return false;
    }
    const bool ok = PackFromTdc(tdc, entity, sample);
    if (ok) {
        ++g_pack_ents;
    }
    if (nscan < 6) {
        ++nscan;
        SHADOW_TRACE("[render.shadow] pack-entity off={:#x} ok={} tdc={:p}", hit_off, ok ? 1 : 0,
                     static_cast<void *>(tdc));
    }

    return ok;

}


void ResetPackedGpu() noexcept { g_gpu.clear(); }



void BeginSilhouetteFrame() noexcept {
    g_cpu.clear();
    g_runs.clear();
    g_gpu.clear();
    g_stamps.clear();


    g_effect = 0;
    g_vd = 0;
    g_did_twin = false;
    g_twin_fx = 0;

    g_budget = false;
    g_pf_fn = 0;
    g_pf_uv = 0;
    g_pf_frame = 0;
    g_pf_elems = 0;
    g_pf_added = 0;
    g_pack_ents = 0;

    g_anim_pass_fx = 0;
    g_anim_pass_vd = 0;
}


void PackFailCounts(uint32_t *no_fn, uint32_t *no_uv, uint32_t *no_frame, uint32_t *no_elems,
                    uint32_t *no_added) noexcept {
    if (no_fn) {
        *no_fn = g_pf_fn;
    }
    if (no_uv) {
        *no_uv = g_pf_uv;
    }
    if (no_frame) {
        *no_frame = g_pf_frame;
    }
    if (no_elems) {
        *no_elems = g_pf_elems;
    }
    if (no_added) {
        *no_added = g_pf_added;
    }
}


void NoteDebugCaster(void *entity, float x, float z) noexcept {
    (void)entity;
    if (!std::isfinite(x) || !std::isfinite(z)) {
        return;
    }
    g_stamps.push_back(DebugStamp{x, z});
}

void NoteDebugTex(uint32_t tex) noexcept {
    if (tex != 0 && tex != 0xFFFFFFFFu) {
        g_debug_tex = tex;
    }
}

void NoteDebugSplat(uint32_t fx, uint32_t vd) noexcept {
    if (fx != 0 && fx != 0xFFFFFFFFu) {
        g_debug_fx = fx;
    }
    if (vd != 0 && vd != 0xFFFFFFFFu) {
        if (g_debug_vd == 0) {
            SHADOW_TRACE("[render.shadow] splat handles fx={:#x} vd={:#x}", fx, vd);
        }
        g_debug_vd = vd;
    }
}

void NoteShadowTdc(void *tdc) noexcept {
    if (tdc == nullptr || !ReadableUserPtr(tdc, 0x10)) {
        return;
    }
    auto *tb = static_cast<uint8_t *>(tdc);
    void *owner = *reinterpret_cast<void **>(tb + 8);
    static bool dumped = false;
    if (!dumped && ReadableUserPtr(owner, 0xE0)) {
        dumped = true;
        auto *sr = static_cast<uint8_t *>(owner);
        char hex[8 * 9 + 1];
        SHADOW_TRACE("[render.shadow] tdc={:p} owner={:p}", tdc, owner);
        for (size_t row = 0x90; row < 0xE0; row += 16) {
            int n = 0;
            for (size_t i = 0; i < 16; i += 4) {
                const uint32_t w = *reinterpret_cast<uint32_t *>(sr + row + i);
                n += std::snprintf(hex + n, sizeof(hex) - static_cast<size_t>(n), " %08x", w);
            }
            SHADOW_TRACE("[render.shadow] sr+{:02x}:{}", row, hex);
        }
        const uint32_t vd = *reinterpret_cast<uint32_t *>(sr + 0xD4);
        const uint32_t fx = *reinterpret_cast<uint32_t *>(sr + 0xD8);
        SHADOW_TRACE("[render.shadow] shadow-sr +d4 vd={:#x} +d8 fx={:#x}", vd, fx);
        (void)vd;
        (void)fx;

    }
}


void NoteRendererAfterShadow(void *renderer) noexcept {
    if (renderer == nullptr || !ReadableUserPtr(renderer, 0x40)) {
        return;
    }
    auto *r = static_cast<uint8_t *>(renderer);
    // Win64 Renderer: +0x10 last VB, +0x14 VB, +0x18 cached VD, +0x1C VD, +0x20 IB, +0x2C effect.
    const uint32_t last_vb = *reinterpret_cast<uint32_t *>(r + 0x10);
    const uint32_t vb = *reinterpret_cast<uint32_t *>(r + 0x14);
    const uint32_t cvd = *reinterpret_cast<uint32_t *>(r + 0x18);
    const uint32_t vd = *reinterpret_cast<uint32_t *>(r + 0x1C);
    const uint32_t ib = *reinterpret_cast<uint32_t *>(r + 0x20);
    const uint32_t fx = *reinterpret_cast<uint32_t *>(r + 0x2C);
    if (g_debug_vd != 0) {
        return;
    }
    SHADOW_TRACE("[render.shadow] after-shadow last_vb={:#x} vb={:#x} cvd={:#x} vd={:#x} ib={:#x} "
                 "fx={:#x}",
                 last_vb, vb, cvd, vd, ib, fx);
    if (vd != 0 && vd != 0xFFFFFFFFu && vd < 0x10000u) {
        g_debug_vd = vd;
    }
    if (fx != 0 && fx != 0xFFFFFFFFu && fx < 0x10000u) {
        g_debug_fx = fx;
    }
}






bool SilhouetteBudgetHit() noexcept { return g_budget; }

// FUN_1400eff60 param_6 = TDC+0x160. Flag 0x10 → sBuild* @ override+0x58.
// Dest symbol hash @ obj+0x64 (AnimNode::sSymbolOverrides).
uint8_t *ResolveOverrideBuild(uint8_t *tdc, uint8_t *elem, uint8_t *default_build, bool *skip,
                              uint32_t *sym_out) noexcept {
    *skip = false;
    if (tdc == nullptr || elem == nullptr) {
        return default_build;
    }
    auto map_size = [](uint8_t *m) -> uint64_t {
        return m != nullptr ? *reinterpret_cast<uint64_t *>(m + 0x10) : 0;
    };
    uint8_t *map = tdc + 0x160;
    auto *anim_node = *reinterpret_cast<uint8_t **>(tdc + 8);
    const uint64_t tdc_sz = map_size(map);
    uint64_t an160 = 0, an118 = 0;
    if (ReadableUserPtr(anim_node, 0x180)) {
        an160 = map_size(anim_node + 0x160);
        an118 = map_size(anim_node + 0x118);
    }
    static uint32_t nmap = 0;
    if (nmap < 8 && tdc_sz != 0) {
        ++nmap;
        auto *hdr = *reinterpret_cast<uint8_t **>(map + 0x08);
        uint8_t *root = hdr != nullptr ? *reinterpret_cast<uint8_t **>(hdr + 0x08) : nullptr;
        uint32_t k18 = 0, k20 = 0, k24 = 0;
        if (root != nullptr && ReadableUserPtr(root, 0x30)) {
            std::memcpy(&k18, root + 0x18, 4);
            std::memcpy(&k20, root + 0x20, 4);
            std::memcpy(&k24, root + 0x24, 4);
        }
        SHADOW_TRACE("[render.shadow] ovmap tdc={:#x} an160={:#x} an118={:#x} elem={:#x} "
                     "k18={:#x} k20={:#x} k24={:#x} root={}",
                     tdc_sz, an160, an118, *reinterpret_cast<uint32_t *>(elem + 0x10), k18, k20,
                     k24, static_cast<const void *>(root));
    }
    if (map_size(map) == 0) {
        return default_build;
    }
    auto *header = *reinterpret_cast<uint8_t **>(map + 0x08);
    if (header == nullptr) {
        return default_build;
    }
    const uint32_t key = *reinterpret_cast<uint32_t *>(elem + 0x10);
    auto *node = *reinterpret_cast<uint8_t **>(header + 0x08);
    auto *cand = header;
    int guard = 0;
    while (node != nullptr && node != header && guard++ < 4096) {
        const uint32_t nk = MsvcMapKey(node);
        if (nk < key) {
            node = *reinterpret_cast<uint8_t **>(node + 0x10);
        } else {
            cand = node;
            node = *reinterpret_cast<uint8_t **>(node);
        }
    }
    if (cand == nullptr || cand == header) {
        return default_build;
    }
    if (key < MsvcMapKey(cand)) {
        return default_build;
    }
    const auto ov = ReadSymbolOverride(MsvcMapValue(cand));
    *skip = ov.skip;
    if (ov.skip) {
        return default_build;
    }
    if (sym_out != nullptr && ov.symbol != 0) {
        *sym_out = ov.symbol;
    }
    static uint32_t nov = 0;
    if (ov.build != nullptr && ov.build != default_build && nov < 12) {
        ++nov;
        const uint8_t *obj = MsvcMapValue(cand);
        uint32_t w[32]{};
        if (obj != nullptr) {
            std::memcpy(w, obj, sizeof(w));
        }
        SHADOW_TRACE(
            "[render.shadow] ov key={:#x} fl={:02x} "
            "{:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} "
            "{:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} "
            "{:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} "
            "{:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
            key, obj != nullptr ? obj[0] : 0, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8],
            w[9], w[10], w[11], w[12], w[13], w[14], w[15], w[16], w[17], w[18], w[19], w[20], w[21],
            w[22], w[23], w[24], w[25], w[26], w[27], w[28], w[29], w[30], w[31]);
    }
    return ov.build != nullptr ? ov.build : default_build;
}

bool PackFromTdc(void *tdc, void *entity, const SunSample &sample) {
    auto fail = [](const char *why) {
        static uint32_t n = 0;
        if (n < 12) {
            ++n;
            SHADOW_TRACE("[render.shadow] packfail why={}", why);
        }
    };
    if (tdc == nullptr || !sample.visible || sample.alpha < 1e-3f || IsSilhouetted(entity)) {
        fail(tdc == nullptr ? "null-tdc" : !sample.visible ? "invisible"
                                         : sample.alpha < 1e-3f ? "alpha"
                                                                : "already");
        return false;
    }
    SunSample samp = sample;
    if (g_budget) {
        fail("budget");
        return false;
    }
    auto *tb = static_cast<uint8_t *>(tdc);
    auto *eb = static_cast<uint8_t *>(entity);

    auto *sanim = *reinterpret_cast<void **>(tb + 0xB0);
    auto *sbuild = *reinterpret_cast<uint8_t **>(tb + 0xB8);
    if (sanim == nullptr || sbuild == nullptr || get_anim_frame == nullptr) {
        ++g_pf_fn;
        fail("no-fn");
        return false;
    }
    const uint32_t play = *reinterpret_cast<uint32_t *>(tb + 0xC0);
    const float time = *reinterpret_cast<float *>(tb + 0xC4);
    auto *sframe = static_cast<uint8_t *>(get_anim_frame(sanim, play, time));
    if (sframe == nullptr) {
        ++g_pf_frame;
        fail("no-frame");
        return false;
    }
    auto *elems = *reinterpret_cast<uint8_t **>(sframe + 0x18);
    const uint32_t nelem = *reinterpret_cast<uint32_t *>(sframe + 0x20);
    if (elems == nullptr || nelem == 0 || nelem > 0x4000) {
        ++g_pf_elems;
        fail("no-elems");
        return false;
    }



    const float *wm = reinterpret_cast<const float *>(tb + 0x18);
    float tdc_wx = wm[3];
    float tdc_wz = wm[11];
    if (!std::isfinite(tdc_wx) || !std::isfinite(tdc_wz)) {
        tdc_wx = 0.f;
        tdc_wz = 0.f;
    }
    float pass[16];
    if (calc_scale != nullptr) {
        calc_scale(tdc, pass, reinterpret_cast<float *>(tb + 0x18),
                   reinterpret_cast<float *>(tb + 0x58));
    } else {
        std::memcpy(pass, tb + 0x18, sizeof(pass));
    }
    // Billboard orientation is discarded; only the sprite→world size is kept.
    float world_scale = std::hypot(pass[1], pass[5]);
    world_scale = std::hypot(world_scale, pass[9]);
    if (!std::isfinite(world_scale) || world_scale < 1e-4f || world_scale > 8.f) {
        world_scale = 1.f;
    }
    static uint32_t nscale = 0;
    if (nscale < 4) {
        ++nscale;
        SHADOW_TRACE("[render.shadow] stamp scale={:.4f} origin={:.1f},{:.1f} len={:.2f} a={:.2f}",
                     world_scale, tdc_wx, tdc_wz, samp.length_scale, samp.alpha);
    }





    if (entity == nullptr) {
        entity = EntityFromTdcViaDsList(tdc);
        eb = static_cast<uint8_t *>(entity);
    }

    const float origin_x = tdc_wx;
    const float origin_z = tdc_wz;



    const size_t gpu_before = g_gpu.size();
    uint32_t added = 0;
    uint32_t nkept = 0;
    for (uint32_t i = 0; i < nelem; ++i) {
        auto *elem = elems + static_cast<size_t>(i) * 0x30u;
        const uint32_t layer_hash = *reinterpret_cast<uint32_t *>(elem);
        if (HiddenLayer(tb, layer_hash)) {
            continue;
        }
        bool skip_elem = false;
        const uint32_t orig_sym = *reinterpret_cast<uint32_t *>(elem + 0x10);
        uint32_t dest_sym = orig_sym;
        auto *build = ResolveOverrideBuild(tb, elem, sbuild, &skip_elem, &dest_sym);
        if (skip_elem || build == nullptr || !ReadableUserPtr(build, 0x88)) {
            continue;
        }
        auto *ebegin = *reinterpret_cast<uint32_t **>(build + 0x58);
        auto *eend = *reinterpret_cast<uint32_t **>(build + 0x60);
        if (ebegin == nullptr || eend == nullptr || ebegin >= eend) {
            continue;
        }
        const uint32_t etex = *ebegin;
        const uint32_t gpu_vb = *reinterpret_cast<uint32_t *>(build + 0x80);
        const uint32_t gpu_vb2 = *reinterpret_cast<uint32_t *>(build + 0x84);
        if (gpu_vb == 0 || gpu_vb == 0xFFFFFFFFu) {
            continue;
        }
        const uint32_t fr_i = *reinterpret_cast<uint32_t *>(elem + 0x20);
        auto *sbsf = static_cast<uint8_t *>(GetBuildFrame(build, dest_sym, fr_i));
        if (sbsf == nullptr && dest_sym != orig_sym) {
            sbsf = static_cast<uint8_t *>(GetBuildFrame(build, orig_sym, fr_i));
        }
        if (sbsf == nullptr && build != sbuild) {
            sbsf = static_cast<uint8_t *>(GetBuildFrame(sbuild, orig_sym, fr_i));
        }
        if (sbsf == nullptr) {
            continue;
        }
        const uint32_t vstart = *reinterpret_cast<uint32_t *>(sbsf + 0x08);
        const uint32_t vcount = *reinterpret_cast<uint32_t *>(sbsf + 0x0C);
        if (vcount < 3) {
            continue;
        }
        if (g_gpu.size() + 1 > 4096) {
            g_gpu.resize(gpu_before);
            g_budget = true;
            return false;
        }
        float aff[16];
        float elem_final[16];
        float shadow_w[16];
        ElemAffine(elem, aff);
        MulMat(elem_final, pass, aff);
        const bool pass_world = std::fabs(elem_final[3]) + std::fabs(elem_final[11]) > 1.f;
        ComposeShadowW(elem_final, samp.yaw_rad, samp.length_scale,
                       pass_world ? 0.f : origin_x, pass_world ? 0.f : origin_z, shadow_w);
        StashShadowAlpha(shadow_w, samp.alpha);





        GpuRun gr{};
        gr.vb = gpu_vb;
        gr.tex = etex;
        gr.start = vstart;
        gr.count = vcount;
        std::memcpy(gr.m, shadow_w, sizeof(gr.m));
        g_gpu.push_back(gr);
        added += vcount;
        ++nkept;
        const uint32_t vstart2 = *reinterpret_cast<uint32_t *>(sbsf + 0x10);
        const uint32_t vcount2 = *reinterpret_cast<uint32_t *>(sbsf + 0x14);
        if (gpu_vb2 != 0 && gpu_vb2 != 0xFFFFFFFFu && vcount2 >= 3) {
            gr.vb = gpu_vb2;
            gr.start = vstart2;
            gr.count = vcount2;
            g_gpu.push_back(gr);
            added += vcount2;
        }
    }

    static uint32_t next = 0;
    if (added > 0 && next < 8) {
        ++next;
        SHADOW_TRACE("[render.shadow] packext n={} nelem={} kept={} verts={} len={:.2f}",
                     next, nelem, nkept, added, samp.length_scale);
    }
    if (added == 0) {
        ++g_pf_added;
        fail("empty");
        return false;
    }
    MarkSilhouetted(entity);
    return true;





}

bool CallOriginalAnimDraw(void *, const float *, int, int, int) noexcept { return false; }


void FlushGpuNow(void *) {}





const float *FlattenMatrixIfPacked(void *game_renderer) {
    if (g_did_twin || game_renderer == nullptr || g_gpu.empty() || !IsSilhouetteEnabled() ||
        !ReadableUserPtr(game_renderer, 0x30)) {
        return nullptr;
    }
    auto *r = static_cast<uint8_t *>(game_renderer);
    const uint32_t vb = *reinterpret_cast<uint32_t *>(r + 0x14);
    const uint32_t fx = *reinterpret_cast<uint32_t *>(r + 0x2C);
    if (vb == 0 || vb == 0xFFFFFFFFu || fx == 0 || fx == 0xFFFFFFFFu) {
        return nullptr;
    }
    for (const auto &gr : g_gpu) {
        if (gr.vb == vb && gr.vd == fx) {
            return gr.m;
        }
    }
    return nullptr;
}












void FlushSilhouettes(void *game_renderer) {
    static uint32_t nflush = 0;
    ++nflush;
    const bool chatter = nflush <= 8 || (nflush % 60u) == 0;
    if (!IsSilhouetteEnabled() || !IsSilhouetteHealthy() || !BindProgramPinned()) {
        g_cpu.clear();
        g_runs.clear();
        return;
    }
    if (game_renderer == nullptr) {
        SetSilhouetteHealthy(false);
        g_cpu.clear();
        g_runs.clear();
        return;
    }
    auto *renderer = static_cast<uint8_t *>(game_renderer);
    if (!ReadableUserPtr(renderer, 0x934) ||
        *reinterpret_cast<int *>(renderer + 0x930) != 2) {
        return;
    }
    if ((g_sil_fx == 0 || g_sil_vd == 0) && !LoadSilShader()) {
        SetSilhouetteHealthy(false);
        g_cpu.clear();
        g_runs.clear();
        return;
    }
    if (g_sil_fx == 0 || g_sil_vd == 0 || anim_draw == nullptr || set_vb == nullptr ||
        set_tex == nullptr || set_effect == nullptr || set_vd == nullptr) {
        SetSilhouetteHealthy(false);
        g_gpu.clear();
        return;
    }


    // sd+0x28 writes renderer+0x1C (vert-desc). sd+0x33 writes +0x2C (effect).
    // Bind copies +0x2C → +0x28 and glUseProgram; it does not rewrite fx+0xB8.
    void *src_before = nullptr;
    if (hw_bind != nullptr && get_vert_desc != nullptr && ReadableUserPtr(renderer, 0x1C0)) {
        void *emgr = *reinterpret_cast<void **>(renderer + 0x1B8);
        const uint32_t bound = *reinterpret_cast<uint32_t *>(renderer + 0x28);
        if (void *prev = (emgr != nullptr && bound != 0) ? get_vert_desc(emgr, bound) : nullptr) {
            if (ReadableUserPtr(prev, 0xC0)) {
                src_before = *reinterpret_cast<void **>(static_cast<uint8_t *>(prev) + 0xB8);
            }
        }
    }

    set_effect(game_renderer, g_sil_vd);
    set_vd(game_renderer, g_sil_fx);

    static bool bind_proven = false;
    if (hw_bind != nullptr && get_vert_desc != nullptr && ReadableUserPtr(renderer, 0x1C0)) {
        void *emgr = *reinterpret_cast<void **>(renderer + 0x1B8);
        void *fx = get_vert_desc(emgr, g_sil_fx);
        void *cs = *reinterpret_cast<void **>(renderer + 0x188);
        hw_bind(fx, cs, renderer + 0x10);
        void *src_after = nullptr;
        if (fx != nullptr && ReadableUserPtr(fx, 0xC0)) {
            src_after = *reinterpret_cast<void **>(static_cast<uint8_t *>(fx) + 0xB8);
        }
        const uint32_t bound_after = *reinterpret_cast<uint32_t *>(renderer + 0x28);
        if (!bind_proven) {
            if (!BindProgramUpdatesSrcData(src_before, src_after) ||
                !BindCopiedDesiredHandle(bound_after, g_sil_fx)) {
                spdlog::error("[render.shadow] BindProgram did not commit sil fx "
                              "src_before={} src_after={} bound={:#x} want={:#x}",
                              src_before, src_after, bound_after, g_sil_fx);
                SetSilhouetteHealthy(false);
                g_cpu.clear();
                g_runs.clear();
                return;
            }
            bind_proven = true;
        } else if (src_after == nullptr ||
                   !BindCopiedDesiredHandle(bound_after, g_sil_fx)) {
            SetSilhouetteHealthy(false);
            g_cpu.clear();
            g_runs.clear();
            return;
        }
    }

    int n_ok = 0;
    int n_fail = 0;
    uint32_t nverts = 0;
#ifdef _WIN32
    int vp[4] = {};
    int prev_fbo = 0;
    bool cov = false;
    const bool gl_ok = BindCoverageGl();
    if (gl_ok && gl_get_integerv != nullptr) {
        gl_get_integerv(kGlViewport, vp);
        gl_get_integerv(kGlFboBinding, &prev_fbo);
    }
    if (vp[2] <= 0 || vp[3] <= 0) {
        if (HWND hw = ::FindWindowW(nullptr, L"Don't Starve Together")) {
            RECT rc{};
            if (::GetClientRect(hw, &rc) && rc.right > 0 && rc.bottom > 0) {
                vp[2] = rc.right;
                vp[3] = rc.bottom;
            }
        }
    }
    if (gl_ok && vp[2] > 0 && vp[3] > 0) {
        __try {
            cov = BeginCoverageRt(vp[2], vp[3]);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            cov = false;
            spdlog::error("[render.shadow] coverage begin crash");
        }
    }
    static uint32_t ncov = 0;
    if (ncov < 4) {
        ++ncov;
        SHADOW_TRACE("[render.shadow] coverage gl={} on={} fbo={:#x} tex={:#x} {}x{} prev={}",
                     gl_ok ? 1 : 0, cov ? 1 : 0, g_cov_fbo, g_cov_tex, vp[2], vp[3], prev_fbo);
    }
#endif


    for (const auto &gr : g_gpu) {
        if (gr.vb == 0 || gr.vb == 0xFFFFFFFFu || gr.count < 3) {
            ++n_fail;
            continue;
        }
        if (gr.tex != 0) {
            set_tex(game_renderer, 0, gr.tex);
        }
        set_vb(game_renderer, gr.vb);
        float m[16];
        std::memcpy(m, gr.m, sizeof(m));
#ifdef _WIN32
        if (cov) {
            m[14] = 1.f;
        }
#endif
        static uint32_t nw = 0;
        if (nw < 4) {
            ++nw;
            SHADOW_TRACE("[render.shadow] gpuW n={} vb={:#x} start={} count={} t={:.1f},{:.1f},{:.1f}",
                         nw, gr.vb, gr.start, gr.count, m[3], m[7], m[11]);
        }
        __try {
            anim_draw(game_renderer, m, static_cast<int>(gr.start), static_cast<int>(gr.count), 6);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ++n_fail;
            continue;
        }
        nverts += gr.count;
        ++n_ok;
    }
#ifdef _WIN32
    if (cov) {
        __try {
            BlitCoverageRt(LoadPublished().alpha, prev_fbo, vp);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            spdlog::error("[render.shadow] coverage blit crash");
        }
    }
#endif
    if (chatter) {
#ifdef _WIN32
        SHADOW_TRACE("[render.shadow] flush gpu n={} ok={} fail={} verts={} runs={} cov={} {}x{}",
                     nflush, n_ok, n_fail, nverts, static_cast<unsigned>(g_gpu.size()), cov ? 1 : 0,
                     vp[2], vp[3]);
#else
        SHADOW_TRACE("[render.shadow] flush gpu n={} ok={} fail={} verts={} runs={}", nflush, n_ok,
                     n_fail, nverts, static_cast<unsigned>(g_gpu.size()));
#endif
    }

    g_gpu.clear();
    g_cpu.clear();
    g_runs.clear();
}











} // namespace ds::shadow
