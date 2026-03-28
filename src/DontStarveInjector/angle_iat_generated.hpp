#pragma once

#ifdef _WIN32

#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <Windows.h>

#include <cstring>

namespace angle_iat_generated {

inline FARPROC ResolveViaEglProcAddress(const char *name) {
    if (!name) {
        return nullptr;
    }
    return reinterpret_cast<FARPROC>(eglGetProcAddress(name));
}

inline FARPROC ResolveStaticEglSymbol(const char *name) {
    if (!name) {
        return nullptr;
    }
    if (strcmp(name, "eglChooseConfig") == 0) return reinterpret_cast<FARPROC>(eglChooseConfig);
    if (strcmp(name, "eglCreateContext") == 0) return reinterpret_cast<FARPROC>(eglCreateContext);
    if (strcmp(name, "eglCreateWindowSurface") == 0) return reinterpret_cast<FARPROC>(eglCreateWindowSurface);
    if (strcmp(name, "eglGetConfigAttrib") == 0) return reinterpret_cast<FARPROC>(eglGetConfigAttrib);
    if (strcmp(name, "eglGetConfigs") == 0) return reinterpret_cast<FARPROC>(eglGetConfigs);
    if (strcmp(name, "eglGetDisplay") == 0) return reinterpret_cast<FARPROC>(eglGetDisplay);
    if (strcmp(name, "eglGetError") == 0) return reinterpret_cast<FARPROC>(eglGetError);
    if (strcmp(name, "eglGetProcAddress") == 0) return reinterpret_cast<FARPROC>(eglGetProcAddress);
    if (strcmp(name, "eglInitialize") == 0) return reinterpret_cast<FARPROC>(eglInitialize);
    if (strcmp(name, "eglMakeCurrent") == 0) return reinterpret_cast<FARPROC>(eglMakeCurrent);
    if (strcmp(name, "eglSwapBuffers") == 0) return reinterpret_cast<FARPROC>(eglSwapBuffers);
    if (strcmp(name, "eglSwapInterval") == 0) return reinterpret_cast<FARPROC>(eglSwapInterval);
    return ResolveViaEglProcAddress(name);
}

inline FARPROC ResolveStaticGlesSymbol(const char *name) {
    if (!name) {
        return nullptr;
    }
    auto from_egl = ResolveViaEglProcAddress(name);
    if (from_egl) {
        return from_egl;
    }
    if (strcmp(name, "glActiveTexture") == 0) return reinterpret_cast<FARPROC>(glActiveTexture);
    if (strcmp(name, "glAttachShader") == 0) return reinterpret_cast<FARPROC>(glAttachShader);
    if (strcmp(name, "glBindAttribLocation") == 0) return reinterpret_cast<FARPROC>(glBindAttribLocation);
    if (strcmp(name, "glBindBuffer") == 0) return reinterpret_cast<FARPROC>(glBindBuffer);
    if (strcmp(name, "glBindFramebuffer") == 0) return reinterpret_cast<FARPROC>(glBindFramebuffer);
    if (strcmp(name, "glBindRenderbuffer") == 0) return reinterpret_cast<FARPROC>(glBindRenderbuffer);
    if (strcmp(name, "glBindTexture") == 0) return reinterpret_cast<FARPROC>(glBindTexture);
    if (strcmp(name, "glBlendEquation") == 0) return reinterpret_cast<FARPROC>(glBlendEquation);
    if (strcmp(name, "glBlendFunc") == 0) return reinterpret_cast<FARPROC>(glBlendFunc);
    if (strcmp(name, "glBufferData") == 0) return reinterpret_cast<FARPROC>(glBufferData);
    if (strcmp(name, "glCheckFramebufferStatus") == 0) return reinterpret_cast<FARPROC>(glCheckFramebufferStatus);
    if (strcmp(name, "glClear") == 0) return reinterpret_cast<FARPROC>(glClear);
    if (strcmp(name, "glClearColor") == 0) return reinterpret_cast<FARPROC>(glClearColor);
    if (strcmp(name, "glClearStencil") == 0) return reinterpret_cast<FARPROC>(glClearStencil);
    if (strcmp(name, "glColorMask") == 0) return reinterpret_cast<FARPROC>(glColorMask);
    if (strcmp(name, "glCompileShader") == 0) return reinterpret_cast<FARPROC>(glCompileShader);
    if (strcmp(name, "glCompressedTexImage2D") == 0) return reinterpret_cast<FARPROC>(glCompressedTexImage2D);
    if (strcmp(name, "glCreateProgram") == 0) return reinterpret_cast<FARPROC>(glCreateProgram);
    if (strcmp(name, "glCreateShader") == 0) return reinterpret_cast<FARPROC>(glCreateShader);
    if (strcmp(name, "glCullFace") == 0) return reinterpret_cast<FARPROC>(glCullFace);
    if (strcmp(name, "glDeleteBuffers") == 0) return reinterpret_cast<FARPROC>(glDeleteBuffers);
    if (strcmp(name, "glDeleteFramebuffers") == 0) return reinterpret_cast<FARPROC>(glDeleteFramebuffers);
    if (strcmp(name, "glDeleteProgram") == 0) return reinterpret_cast<FARPROC>(glDeleteProgram);
    if (strcmp(name, "glDeleteRenderbuffers") == 0) return reinterpret_cast<FARPROC>(glDeleteRenderbuffers);
    if (strcmp(name, "glDeleteShader") == 0) return reinterpret_cast<FARPROC>(glDeleteShader);
    if (strcmp(name, "glDeleteTextures") == 0) return reinterpret_cast<FARPROC>(glDeleteTextures);
    if (strcmp(name, "glDepthFunc") == 0) return reinterpret_cast<FARPROC>(glDepthFunc);
    if (strcmp(name, "glDepthMask") == 0) return reinterpret_cast<FARPROC>(glDepthMask);
    if (strcmp(name, "glDisable") == 0) return reinterpret_cast<FARPROC>(glDisable);
    if (strcmp(name, "glDisableVertexAttribArray") == 0) return reinterpret_cast<FARPROC>(glDisableVertexAttribArray);
    if (strcmp(name, "glDrawArrays") == 0) return reinterpret_cast<FARPROC>(glDrawArrays);
    if (strcmp(name, "glEnable") == 0) return reinterpret_cast<FARPROC>(glEnable);
    if (strcmp(name, "glEnableVertexAttribArray") == 0) return reinterpret_cast<FARPROC>(glEnableVertexAttribArray);
    if (strcmp(name, "glFinish") == 0) return reinterpret_cast<FARPROC>(glFinish);
    if (strcmp(name, "glFramebufferRenderbuffer") == 0) return reinterpret_cast<FARPROC>(glFramebufferRenderbuffer);
    if (strcmp(name, "glFramebufferTexture2D") == 0) return reinterpret_cast<FARPROC>(glFramebufferTexture2D);
    if (strcmp(name, "glFrontFace") == 0) return reinterpret_cast<FARPROC>(glFrontFace);
    if (strcmp(name, "glGenBuffers") == 0) return reinterpret_cast<FARPROC>(glGenBuffers);
    if (strcmp(name, "glGenFramebuffers") == 0) return reinterpret_cast<FARPROC>(glGenFramebuffers);
    if (strcmp(name, "glGenRenderbuffers") == 0) return reinterpret_cast<FARPROC>(glGenRenderbuffers);
    if (strcmp(name, "glGenTextures") == 0) return reinterpret_cast<FARPROC>(glGenTextures);
    if (strcmp(name, "glGetActiveAttrib") == 0) return reinterpret_cast<FARPROC>(glGetActiveAttrib);
    if (strcmp(name, "glGetAttribLocation") == 0) return reinterpret_cast<FARPROC>(glGetAttribLocation);
    if (strcmp(name, "glGetError") == 0) return reinterpret_cast<FARPROC>(glGetError);
    if (strcmp(name, "glGetIntegerv") == 0) return reinterpret_cast<FARPROC>(glGetIntegerv);
    if (strcmp(name, "glGetProgramInfoLog") == 0) return reinterpret_cast<FARPROC>(glGetProgramInfoLog);
    if (strcmp(name, "glGetProgramiv") == 0) return reinterpret_cast<FARPROC>(glGetProgramiv);
    if (strcmp(name, "glGetShaderInfoLog") == 0) return reinterpret_cast<FARPROC>(glGetShaderInfoLog);
    if (strcmp(name, "glGetShaderiv") == 0) return reinterpret_cast<FARPROC>(glGetShaderiv);
    if (strcmp(name, "glGetString") == 0) return reinterpret_cast<FARPROC>(glGetString);
    if (strcmp(name, "glGetUniformLocation") == 0) return reinterpret_cast<FARPROC>(glGetUniformLocation);
    if (strcmp(name, "glLinkProgram") == 0) return reinterpret_cast<FARPROC>(glLinkProgram);
    if (strcmp(name, "glPixelStorei") == 0) return reinterpret_cast<FARPROC>(glPixelStorei);
    if (strcmp(name, "glPolygonOffset") == 0) return reinterpret_cast<FARPROC>(glPolygonOffset);
    if (strcmp(name, "glRenderbufferStorage") == 0) return reinterpret_cast<FARPROC>(glRenderbufferStorage);
    if (strcmp(name, "glScissor") == 0) return reinterpret_cast<FARPROC>(glScissor);
    if (strcmp(name, "glShaderSource") == 0) return reinterpret_cast<FARPROC>(glShaderSource);
    if (strcmp(name, "glStencilFunc") == 0) return reinterpret_cast<FARPROC>(glStencilFunc);
    if (strcmp(name, "glStencilMask") == 0) return reinterpret_cast<FARPROC>(glStencilMask);
    if (strcmp(name, "glStencilOp") == 0) return reinterpret_cast<FARPROC>(glStencilOp);
    if (strcmp(name, "glTexImage2D") == 0) return reinterpret_cast<FARPROC>(glTexImage2D);
    if (strcmp(name, "glTexParameteri") == 0) return reinterpret_cast<FARPROC>(glTexParameteri);
    if (strcmp(name, "glUniform1f") == 0) return reinterpret_cast<FARPROC>(glUniform1f);
    if (strcmp(name, "glUniform1fv") == 0) return reinterpret_cast<FARPROC>(glUniform1fv);
    if (strcmp(name, "glUniform1i") == 0) return reinterpret_cast<FARPROC>(glUniform1i);
    if (strcmp(name, "glUniform2fv") == 0) return reinterpret_cast<FARPROC>(glUniform2fv);
    if (strcmp(name, "glUniform3fv") == 0) return reinterpret_cast<FARPROC>(glUniform3fv);
    if (strcmp(name, "glUniform4fv") == 0) return reinterpret_cast<FARPROC>(glUniform4fv);
    if (strcmp(name, "glUniformMatrix2fv") == 0) return reinterpret_cast<FARPROC>(glUniformMatrix2fv);
    if (strcmp(name, "glUniformMatrix3fv") == 0) return reinterpret_cast<FARPROC>(glUniformMatrix3fv);
    if (strcmp(name, "glUniformMatrix4fv") == 0) return reinterpret_cast<FARPROC>(glUniformMatrix4fv);
    if (strcmp(name, "glUseProgram") == 0) return reinterpret_cast<FARPROC>(glUseProgram);
    if (strcmp(name, "glVertexAttribPointer") == 0) return reinterpret_cast<FARPROC>(glVertexAttribPointer);
    if (strcmp(name, "glViewport") == 0) return reinterpret_cast<FARPROC>(glViewport);
    return nullptr;
}

} // namespace angle_iat_generated

#endif
