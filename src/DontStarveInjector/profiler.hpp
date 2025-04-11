#pragma once
#ifndef DONTSTARVEINJECTOR_PROFILER_HPP
#define DONTSTARVEINJECTOR_PROFILER_HPP
#include <lua.hpp>
#include <frida-gum.h>
#include <atomic>
#include <chrono>
struct gum_luajit_profiler {
    void update_thread_id(lua_State *target_L, GumThreadId id);

    void start();

    void stop();

    static std::atomic<gum_luajit_profiler *> instance;
    bool isstop = false;
    std::atomic_bool intrace = false;
    GumThreadId thread_id;
    lua_State *L;
    std::chrono::milliseconds interval = std::chrono::milliseconds(20);
};

#endif