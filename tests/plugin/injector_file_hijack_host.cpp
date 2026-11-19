// tests/plugin/injector_file_hijack_host.cpp
//
// Host for the injector's C-function hook service (game/CfunctionHook.hpp) and the file hijack
// policy built on it (game/InjectorFileHijack.cpp).
//
// The VM under test is loaded at runtime by absolute path (dlopen / LoadLibraryA) and every
// lua_* entry point is resolved from that handle, so one binary drives any LuaJIT build and
// nothing links against the VM. The hook service and the policy are the
// production TUs, so what runs here is the shipped code, not a copy of it.
//
// Env: DS_HIJACK_VM=<lua51DS library>  DS_HIJACK_FRAMEWORK=<GameLuaInjectFramework.lua>
//
// Teeth: before the C entry hook, GameLuaInjectFramework.lua replaced the global `require` with
// a Lua closure (what="Lua", nups=3, extra frame). Re-introducing that fails the disguise
// checks, and so does anything that leaves a patch record in the Lua registry.
#include "game/CfunctionHook.hpp"
#include "game/InjectorFileHijack.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

#ifdef _WIN32
using module_handle = HMODULE;
module_handle open_module(const char *path) { return LoadLibraryA(path); }
void *module_symbol(module_handle handle, const char *name) {
    return reinterpret_cast<void *>(GetProcAddress(handle, name));
}
#else
using module_handle = void *;
module_handle open_module(const char *path) { return dlopen(path, RTLD_NOW | RTLD_LOCAL); }
void *module_symbol(module_handle handle, const char *name) { return dlsym(handle, name); }
#endif

struct Vm {
    module_handle handle{};
    LuaApis api{};
    lua_State *L{};

    explicit Vm(const char *path) {
        if (path != nullptr) {
            handle = open_module(path);
        }
        if (handle == nullptr) {
            return;
        }
#define DS_LUA_ENTRY(name) api._##name = reinterpret_cast<decltype(&name)>(module_symbol(handle, #name))
        DS_LUA_ENTRY(luaL_newstate);
        DS_LUA_ENTRY(lua_close);
        DS_LUA_ENTRY(luaL_openlibs);
        DS_LUA_ENTRY(luaL_loadfile);
        DS_LUA_ENTRY(luaL_loadstring);
        DS_LUA_ENTRY(lua_pcall);
        DS_LUA_ENTRY(lua_gettop);
        DS_LUA_ENTRY(lua_settop);
        DS_LUA_ENTRY(lua_pushvalue);
        DS_LUA_ENTRY(lua_replace);
        DS_LUA_ENTRY(lua_type);
        DS_LUA_ENTRY(lua_iscfunction);
        DS_LUA_ENTRY(lua_tocfunction);
        DS_LUA_ENTRY(lua_toboolean);
        DS_LUA_ENTRY(lua_tolstring);
        DS_LUA_ENTRY(lua_topointer);
        DS_LUA_ENTRY(lua_getfield);
        DS_LUA_ENTRY(lua_setfield);
        DS_LUA_ENTRY(lua_rawget);
        DS_LUA_ENTRY(lua_pushnil);
        DS_LUA_ENTRY(lua_createtable);
        DS_LUA_ENTRY(lua_pushcclosure);
        DS_LUA_ENTRY(lua_getstack);
        DS_LUA_ENTRY(lua_getinfo);
#undef DS_LUA_ENTRY
        // A missing entry would otherwise be a null call in the middle of a test case.
        if (api._luaL_newstate == nullptr || api._luaL_openlibs == nullptr ||
            api._luaL_loadfile == nullptr || api._luaL_loadstring == nullptr ||
            api._lua_pcall == nullptr || api._lua_pushcclosure == nullptr ||
            api._lua_getinfo == nullptr || api._lua_getstack == nullptr ||
            api._lua_topointer == nullptr) {
            return;
        }
        L = api._luaL_newstate();
        if (L != nullptr) {
            api._luaL_openlibs(L);
        }
    }

    // The VM deliberately outlives the process's hooks: a hooked closure keeps pointing at our
    // thunk, so unloading the module would leave that pointer dangling.
    Vm(const Vm &) = delete;
    Vm &operator=(const Vm &) = delete;
};

// The service belongs to a VM context; the slot table is class-wide, so one instance is enough.
ds::core_vm::detail::CfunctionHook g_hooks{};

Vm &shared_vm() {
    static Vm *vm = [] {
        auto *created = new Vm(std::getenv("DS_HIJACK_VM"));
        return created;
    }();
    return *vm;
}

// log stub the framework chunk expects as its first vararg
int noop_log(lua_State *) { return 0; }

void push_log_stub(LuaApis &api, lua_State *L) {
    api._lua_createtable(L, 0, 3);
    api._lua_pushcclosure(L, noop_log, 0);
    api._lua_setfield(L, -2, "info");
    api._lua_pushcclosure(L, noop_log, 0);
    api._lua_setfield(L, -2, "warn");
    api._lua_pushcclosure(L, noop_log, 0);
    api._lua_setfield(L, -2, "error");
}

// Runs `code`; on failure returns the Lua error text, else "".
std::string run_lua(LuaApis &api, lua_State *L, const char *code) {
    if (api._luaL_dostring(L, code) != 0) {
        const char *err = api._lua_tostring(L, -1);
        std::string message = err ? err : "?";
        api._lua_pop(L, 1);
        return message;
    }
    return {};
}

// A C function with no observable behaviour: only the policy decides what a call does.
int echo_cfunction(lua_State *) { return 0; }

// Lifecycle fixture: the body is observable, so "reverted" differs from "unhooked by bookkeeping
// but still redirected" (the latter drops the call instead of running the implementation).
int g_lifecycle_body_calls = 0;
int lifecycle_cfunction(lua_State *) {
    g_lifecycle_body_calls++;
    return 0;
}

// Distinct implementations, one per slot: more than the old fixed hook table held, and the
// require/kleiloadlua asymmetry (one shared policy, different addresses) in the same fixture.
#define DS_ECHO_FN(n) int echo_cfunction_##n(lua_State *) { return 0; }
DS_ECHO_FN(0) DS_ECHO_FN(1) DS_ECHO_FN(2) DS_ECHO_FN(3) DS_ECHO_FN(4) DS_ECHO_FN(5) DS_ECHO_FN(6)
DS_ECHO_FN(7) DS_ECHO_FN(8) DS_ECHO_FN(9) DS_ECHO_FN(10) DS_ECHO_FN(11)
#undef DS_ECHO_FN

constexpr lua_CFunction kDistinctEchoes[] = {
    &echo_cfunction_0, &echo_cfunction_1,  &echo_cfunction_2,  &echo_cfunction_3,
    &echo_cfunction_4, &echo_cfunction_5,  &echo_cfunction_6,  &echo_cfunction_7,
    &echo_cfunction_8, &echo_cfunction_9,  &echo_cfunction_10, &echo_cfunction_11,
};

struct CallLog {
    int calls{0};
    void *last_userdata{nullptr};
    lua_CFunction last_original{nullptr};
};

int logging_policy(LuaApis &, lua_State *L, lua_CFunction original, void *userdata) {
    auto *log = static_cast<CallLog *>(userdata);
    log->calls++;
    log->last_userdata = userdata;
    log->last_original = original;
    return original(L);
}

const char *kFileHijackAssertions = R"LUA(
local function fail(fmt, ...)
    error(string.format(fmt, ...), 0)
end

-- 1. Disguise: the Lua-visible object must stay the stock C function.
if not rawequal(require, __require_before) then
    fail("require was replaced")
end
local info = debug.getinfo(require)
local up = debug.getinfo(require, "u")
local nups = up and up.nups or info.nups
if info.what ~= "C" then
    fail("require what=%s", tostring(info.what))
end
if nups ~= 0 then
    fail("require nups=%s", tostring(nups))
end

-- 2. No patch record anywhere in the registry (the jit.patch_cfunction style leak).
for _, v in pairs(debug.getregistry()) do
    if type(v) == "table" then
        for k2, v2 in pairs(v) do
            if type(v2) == "table" and rawget(v2, "policy") ~= nil then
                fail("registry leak at %s", tostring(k2))
            end
        end
    end
end

-- 3. Relocation: require("hijack_a") loads hijack_b, and the afterload registered for the
--    effective name sees that module exactly once.
GameLuaInjector.relocation_file("hijack_a", "hijack_b")
local calls, seen = 0, nil
GameLuaInjector.inject_module_text("hijack_b", function(m)
    calls = calls + 1
    seen = m
end)
local m = require("hijack_a")
if not m or m.name ~= "b" then
    fail("relocation loaded %s", tostring(m and m.name))
end
if seen ~= m then
    fail("afterload did not receive the module")
end
if calls ~= 1 then
    fail("afterload ran %d times", calls)
end
require("hijack_a")
if calls ~= 1 then
    fail("afterload is not one-shot (%d)", calls)
end

-- 4. The injector is keyed by the effective name, not by the caller's name.
local wrong = 0
GameLuaInjector.inject_module_text("hijack_a", function()
    wrong = wrong + 1
end)
if wrong ~= 0 then
    fail("afterload keyed by the pre-relocation name ran")
end

-- 5. An afterload error must not escape into require (the framework xpcalls it).
GameLuaInjector.inject_module_text("hijack_c", function()
    error("boom")
end)
local ok, err = pcall(require, "hijack_c")
if not ok then
    fail("afterload error escaped: %s", tostring(err))
end
if type(err) ~= "table" or err.name ~= "c" then
    fail("require lost its result")
end

-- 6. Nested loads go through the policy too (a module requiring another module).
local inner_calls, inner_seen = 0, nil
GameLuaInjector.inject_module_text("hijack_nest_inner", function(m)
    inner_calls = inner_calls + 1
    inner_seen = m
end)
local nest = require("hijack_nest")
if type(nest) ~= "table" or nest.name ~= "nest" then
    fail("nested module load broke")
end
if inner_calls ~= 1 then
    fail("nested afterload ran %d times", inner_calls)
end
if not inner_seen or inner_seen.name ~= "nest_inner" then
    fail("nested afterload did not see the inner module")
end

-- 7. Modules without injectors still load normally.
if require("hijack_plain").name ~= "plain" then
    fail("plain require broke")
end

return "ok"
)LUA";

} // namespace

TEST_CASE("C-function hook is per implementation and leaves the Lua object stock") {
    Vm &vm = shared_vm();
    REQUIRE(vm.L != nullptr);
    LuaApis &api = vm.api;
    lua_State *L = vm.L;
    auto &hooks = g_hooks;

    // Two objects backed by the same C implementation (distinct upvalues), plus a Lua function
    // that must be refused.
    api._lua_pushnil(L);
    api._lua_pushcclosure(L, echo_cfunction, 1);
    api._lua_setglobal(L, "echo_a");
    api._lua_pushnil(L);
    api._lua_pushcclosure(L, echo_cfunction, 1);
    api._lua_setglobal(L, "echo_b");
    REQUIRE(run_lua(api, L, "keep_a, keep_b = echo_a, echo_b; function lua_only() end").empty());

    static CallLog log;
    log = CallLog{};
    static CallLog other;
    other = CallLog{};
    REQUIRE(hooks.hook_global(api, L, "echo_a", &logging_policy, &log));
    // A second closure of the same implementation is a separate object: it gets its own slot.
    REQUIRE(hooks.hook_global(api, L, "echo_b", &logging_policy, &log));
    // Same implementation, different policy: refused -- the policy belongs to the implementation
    // (a state-specific branch belongs inside the policy, which receives the running state).
    REQUIRE_FALSE(hooks.hook_global(api, L, "echo_b", &logging_policy, &other));
    // Same closure twice is refused, and a Lua function is not hookable at all.
    REQUIRE(hooks.hook_count() == 2);
    REQUIRE_FALSE(hooks.hook_global(api, L, "echo_a", &logging_policy, &log));
    REQUIRE_FALSE(hooks.hook_global(api, L, "lua_only", &logging_policy, &log));

    const std::string failure = run_lua(api, L, R"LUA(
local function fail(fmt, ...) error(string.format(fmt, ...), 0) end

-- Objects stay stock: identity, metadata, upvalues, registry.
for _, pair in ipairs({ { "echo_a", keep_a }, { "echo_b", keep_b } }) do
    local name, before = pair[1], pair[2]
    local now = _G[name]
    if not rawequal(now, before) then fail("%s was replaced", name) end
    local info = debug.getinfo(now)
    local up = debug.getinfo(now, "u")
    local nups = up and up.nups or info.nups
    if info.what ~= "C" then fail("%s what=%s", name, tostring(info.what)) end
    if nups ~= 1 then fail("%s nups=%s", name, tostring(nups)) end
end
for _, v in pairs(debug.getregistry()) do
    if type(v) == "table" then
        for k2, v2 in pairs(v) do
            if type(v2) == "table" and rawget(v2, "policy") ~= nil then
                fail("registry leak at %s", tostring(k2))
            end
        end
    end
end

-- One policy per implementation: both objects dispatch to it.
echo_a()
echo_b()
echo_a()
return "ok"
)LUA");
    if (!failure.empty()) {
        MESSAGE(failure);
    }
    REQUIRE(failure.empty());
    REQUIRE(log.calls == 3);
    REQUIRE(log.last_userdata == &log);
    REQUIRE(other.calls == 0);
    // The policy gets the stock implementation pointer that was in the closure before the hook.
    REQUIRE(log.last_original == &echo_cfunction);
}

TEST_CASE("each hook gets its own dedicated thunk with its own original") {
    Vm &vm = shared_vm();
    REQUIRE(vm.L != nullptr);
    LuaApis &api = vm.api;
    lua_State *L = vm.L;
    auto &hooks = g_hooks;

    // One shared policy over many implementations: every slot must hand the policy its own
    // original, which a shared dispatcher would have to reconstruct at call time.
    constexpr size_t count = sizeof(kDistinctEchoes) / sizeof(kDistinctEchoes[0]);
    static std::array<CallLog, count> logs{};
    logs = {};
    for (size_t i = 0; i < count; i++) {
        const std::string name = "scale_echo_" + std::to_string(i);
        api._lua_pushcclosure(L, kDistinctEchoes[i], 0);
        api._lua_setglobal(L, name.c_str());
        REQUIRE(hooks.hook_global(api, L, name.c_str(), &logging_policy, &logs[i]));
    }

    std::string calls;
    for (size_t i = 0; i < count; i++) {
        calls += "scale_echo_" + std::to_string(i) + "()\n";
    }
    const std::string failure = run_lua(api, L, calls.c_str());
    if (!failure.empty()) {
        MESSAGE(failure);
    }
    REQUIRE(failure.empty());
    for (size_t i = 0; i < count; i++) {
        INFO("hook " << i);
        REQUIRE(logs[i].calls == 1);
        REQUIRE(logs[i].last_userdata == &logs[i]);
        REQUIRE(logs[i].last_original != nullptr);
    }
    // Every slot kept its own implementation: a shared "first original" would collapse these.
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            REQUIRE(logs[i].last_original != logs[j].last_original);
        }
    }
}

TEST_CASE("injector file hijack: relocation + one-shot afterload on a stock require") {
    Vm &vm = shared_vm();
    REQUIRE(vm.L != nullptr);
    LuaApis &api = vm.api;
    lua_State *L = vm.L;
    auto &hooks = g_hooks;

    // Capture the stock `require` object, then hook its implementation.
    api._lua_getglobal(L, "require");
    REQUIRE(api._lua_iscfunction(L, -1) != 0);
    api._lua_pushvalue(L, -1);
    api._lua_setglobal(L, "__require_before");
    api._lua_pop(L, 1);
    REQUIRE(hooks.hook_global(api, L, "require", &ds::core_vm::detail::file_hijack_policy,
                              nullptr));

    // Load the framework chunk exactly like the injector does: (spdlog table, native_getenv).
    const char *framework_path = std::getenv("DS_HIJACK_FRAMEWORK");
    REQUIRE(framework_path != nullptr);
    REQUIRE(api._luaL_loadfile(L, framework_path) == 0);
    push_log_stub(api, L);
    api._lua_pushnil(L);
    REQUIRE(api._lua_pcall(L, 2, 0, 0) == 0);
    api._lua_getglobal(L, GameLuaInjectorName);
    REQUIRE(api._lua_istable(L, -1) != 0);
    api._lua_pop(L, 1);

    // Module tree for the relocation/injector cases.
    const auto dir = std::filesystem::temp_directory_path() / "ds_injector_file_hijack";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const auto write_module = [&](const char *name, const char *body) {
        std::ofstream out(dir / (std::string{name} + ".lua"), std::ios::binary);
        out << body;
    };
    write_module("hijack_a", "return { name = \"a\" }\n");
    write_module("hijack_b", "return { name = \"b\" }\n");
    write_module("hijack_c", "return { name = \"c\" }\n");
    write_module("hijack_plain", "return { name = \"plain\" }\n");
    // A module that loads another module: the policy must also run for nested loads.
    write_module("hijack_nest", "return { name = \"nest\", inner = require(\"hijack_nest_inner\") }\n");
    write_module("hijack_nest_inner", "return { name = \"nest_inner\" }\n");

    const std::string package_path =
        "package.path = [[" + dir.generic_string() + "/?.lua;]] .. package.path";
    REQUIRE(run_lua(api, L, package_path.c_str()).empty());

    const std::string failure = run_lua(api, L, kFileHijackAssertions);
    std::filesystem::remove_all(dir);
    if (!failure.empty()) {
        MESSAGE(failure);
    }
    REQUIRE(failure.empty());
}

TEST_CASE("hook lifecycle: clear reverts the implementation and a new state hooks again") {
    Vm &vm = shared_vm();
    REQUIRE(vm.L != nullptr);
    LuaApis &api = vm.api;
    auto &hooks = g_hooks;

    static CallLog log;
    log = CallLog{};
    g_lifecycle_body_calls = 0;

    lua_State *s1 = api._luaL_newstate();
    REQUIRE(s1 != nullptr);
    api._luaL_openlibs(s1);
    api._lua_pushcclosure(s1, &lifecycle_cfunction, 0);
    api._lua_setglobal(s1, "life_20");

    REQUIRE(hooks.hook_global(api, s1, "life_20", &logging_policy, &log));
    REQUIRE(run_lua(api, s1, "life_20()").empty());
    REQUIRE(log.calls == 1);
    REQUIRE(g_lifecycle_body_calls == 1);
    // Nothing about the state is remembered: the next state's install is idempotent, not refused.
    api._lua_close(s1);
    lua_State *s2 = api._luaL_newstate();
    REQUIRE(s2 != nullptr);
    api._luaL_openlibs(s2);
    api._lua_pushcclosure(s2, &lifecycle_cfunction, 0);
    api._lua_setglobal(s2, "life_20");
    REQUIRE(hooks.hook_global(api, s2, "life_20", &logging_policy, &log));
    REQUIRE(run_lua(api, s2, "life_20()").empty());
    REQUIRE(log.calls == 2);
    REQUIRE(g_lifecycle_body_calls == 2);

    // clear() is what ResetApis does: every entry is reverted and forgotten.
    hooks.clear();
    REQUIRE(hooks.hook_count() == 0);

    lua_State *s3 = api._luaL_newstate();
    REQUIRE(s3 != nullptr);
    api._luaL_openlibs(s3);
    api._lua_pushcclosure(s3, &lifecycle_cfunction, 0);
    api._lua_setglobal(s3, "life_20");
    REQUIRE(run_lua(api, s3, "life_20()").empty());
    REQUIRE(log.calls == 2);              // policy is gone
    REQUIRE(g_lifecycle_body_calls == 3);  // ... and the stock implementation still runs
    // A cleared address can be hooked again: clear() restored the entry bytes.
    REQUIRE(hooks.hook_global(api, s3, "life_20", &logging_policy, &log));
    REQUIRE(run_lua(api, s3, "life_20()").empty());
    REQUIRE(log.calls == 3);
    REQUIRE(g_lifecycle_body_calls == 4);
    api._lua_close(s3);
}
