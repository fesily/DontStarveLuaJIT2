option(ENABLE_FAKE_API "check inejctor hook lua func" OFF)
option(ENABLE_ONLY_LUA51 "load lua51.dll" OFF)
option(ENABLE_USE_LISTENER "use api listener" OFF)
option(ENABLE_STEAM_SUPPORT "Enable Steam support" ON)

set(SOURCES
        DontStarveInjector.cpp
        lua_fake.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/inlinehook.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/gum_platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/lua51_object.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/PersistentString.cpp
        gameModConfig.cpp
        GameJitModConfigCascade.cpp
        luajit_config.cpp
        game_info.cpp
        config.cpp
        core/PluginHost.cpp
        core/PluginOptionRules.cpp
        core/ConfigSchema.cpp
        core/RegisterBuiltinPlugins.cpp
        core/PluginConfigBridge.cpp
        core/DynamicPluginLoader.cpp
        core/CoreVmBootstrap.cpp
)


if (ENABLE_STEAM_SUPPORT)
    list(APPEND SOURCES ${DONTSTARVEINJECTOR_UTIL_DIR}/steam.cpp)
    find_package(Steam REQUIRED)
endif ()

if (NOT MSVC)
    # GameForkSave lives in plugin_save_fork (all platforms).
else()
    list(APPEND SOURCES
        #profiler.cpp
        # Re-export static frida-gum symbols from Injector.dll so plugins can
        # call gum_* without linking a second Gum copy (official devkit is static-only).
        FridaGum.def
    )
endif()

find_package(libzip CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(range-v3 CONFIG REQUIRED)
find_package(Tracy CONFIG REQUIRED)
find_package(mimalloc CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS pfr)
find_package(slikenet CONFIG REQUIRED)

find_path(SOL2_INCLUDE_DIRS "sol/abort.hpp")
find_path(PLF_HIVE_INCLUDE_DIRS "plf_hive.h")

if (WIN32)
    find_package(unofficial-angle REQUIRED MODULE)
endif()

set(CMAKE_SKIP_BUILD_RPATH  FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

add_library(Injector SHARED ${SOURCES})
if (MSVC)
    target_compile_definitions(Injector PRIVATE SUPPORT_PROGRESS)
endif()
target_compile_definitions(Injector PRIVATE MOD_VERSION="${CMAKE_PROJECT_VERSION}")
target_compile_definitions(Injector PRIVATE DONTSTARVEINJECTOR_BUILD)
target_include_directories(Injector PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if (ENABLE_STEAM_SUPPORT)
    target_compile_definitions(Injector PRIVATE ENABLE_STEAM_SUPPORT)
    target_include_directories(Injector PUBLIC ${STEAM_INCLUDE_DIR})
    target_include_directories(Injector PUBLIC ${STEAM_SDK_INCLUDE_DIR})
    target_link_libraries(Injector PRIVATE ${STEAM_LIBRARIES})
    # add_library(GameSteamTest SHARED GameSteamTest.cpp)
    # target_include_directories(GameSteamTest PUBLIC ${STEAM_INCLUDE_DIR})
    # target_include_directories(GameSteamTest PUBLIC ${STEAM_SDK_INCLUDE_DIR})
    # target_link_libraries(GameSteamTest PRIVATE ${STEAM_LIBRARIES})
endif()

if (APPLE)
    set_target_properties(Injector PROPERTIES INSTALL_RPATH "\$ORIGIN/../lib64")
    set_target_properties(Injector PROPERTIES BUILD_RPATH "\$ORIGIN/../lib64")
else()
    set_target_properties(Injector PROPERTIES INSTALL_RPATH "./lib64:\$ORIGIN/lib64")
    set_target_properties(Injector PROPERTIES BUILD_RPATH "./lib64:\$ORIGIN/lib64")
endif()

add_dependencies(Injector create_missfuncs)
add_dependencies(Injector create_modinfo_hpp)

target_include_directories(Injector PRIVATE ${SOL2_INCLUDE_DIRS})
target_include_directories(Injector PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(Injector PRIVATE ${FRIDA_GUM_LIBRARIES})

target_link_libraries(Injector PRIVATE Boost::pfr)
target_link_libraries(Injector PRIVATE libzip::zip)
target_link_libraries(Injector PRIVATE ZLIB::ZLIB)
target_link_libraries(Injector PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(Injector PRIVATE spdlog::spdlog)
target_link_libraries(Injector PRIVATE range-v3::meta range-v3::concepts range-v3::range-v3)
target_link_libraries(Injector PRIVATE SLikeNet)
target_include_directories(Injector PRIVATE ${PLF_HIVE_INCLUDE_DIRS})
#target_link_libraries(Injector PRIVATE $<IF:$<TARGET_EXISTS:mimalloc-static>,mimalloc-static,mimalloc>)
if (NOT DISABLE_TRACY_FUTURE)
    target_link_libraries(Injector PRIVATE Tracy::TracyClient)
else()
    target_compile_definitions(Injector PRIVATE DISABLE_TRACY_FUTURE)
endif()
target_link_libraries(Injector PRIVATE function_relocation)
target_include_directories(Injector PUBLIC ${FUNCTION_RELOCATION_INCLUDE_DIR})

if (NOT ENABLE_ONLY_LUA51)
    target_include_directories(Injector PUBLIC ${LUAJIT_INCLUDE_DIR})
    add_dependencies(Injector ${LUAJIT_LIBRARIES})
    # Config cascade (GameJitModConfigCascade) uses sol → needs a real Lua C API.
    # GameDbg_* lua_* re-exports moved to plugin_core_vm; link LuaJIT into Injector for cascade.
    target_link_libraries(Injector PRIVATE ${LUAJIT_LIBRARIES})
elseif (ENABLE_FAKE_API)
    target_include_directories(Injector PUBLIC ${LUA_INCLUDE_DIR})
    target_link_directories(Injector PUBLIC ${PROJECT_SOURCE_DIR}/src/lua51/$<IF:$<CONFIG:Debug>,Debug,Release>)
    add_dependencies(Injector ${LUA_LIBRARIES})
    #target_link_libraries(Injector PRIVATE ${LUA_LIBRARIES})
else ()
    target_include_directories(Injector PUBLIC ${LUA_INCLUDE_DIR})
    add_dependencies(Injector liblua)
    #target_link_libraries(Injector PRIVATE liblua)
endif ()

if (MSVC)
    target_link_options(Injector PUBLIC "/NODEFAULTLIB:LIBCMT")
endif ()

if (ENABLE_FAKE_API)
    target_compile_definitions(Injector PUBLIC ENABLE_FAKE_API)
endif ()

if (ENABLE_USE_LISTENER)
    target_compile_definitions(Injector PUBLIC ENABLE_USE_LISTENER)
endif ()

if (ENABLE_ONLY_LUA51)
    target_compile_definitions(Injector PUBLIC ENABLE_ONLY_LUA51)
endif ()

install(TARGETS Injector RUNTIME DESTINATION .)

if (WIN32)
    add_subdirectory(loader)
endif ()

add_subdirectory(util)

# Dynamic plugin modules (Phase B). Output next to Injector under plugins/.
function(ds_add_dynamic_plugin name)
    add_library(${name} MODULE ${ARGN})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_features(${name} PRIVATE cxx_std_23)
    target_link_libraries(${name} PRIVATE Injector)
    set_target_properties(${name} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${name}"
        RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins"
        LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins"
        ARCHIVE_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins"
    )
endfunction()

ds_add_dynamic_plugin(plugin_dummy
    plugins/plugin_dummy/plugin_dummy.cpp)

# save.fork — no Frida Gum; builds on all platforms (Win clone + Linux fork).
ds_add_dynamic_plugin(plugin_save_fork
    plugins/plugin_save_fork/plugin_save_fork.cpp
    plugins/plugin_save_fork/GameForkSave.cpp)
target_link_libraries(plugin_save_fork PRIVATE
    spdlog::spdlog)
target_compile_definitions(plugin_save_fork PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_save_fork PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/plugins/plugin_save_fork)

# core.vm — optional Signature + GameLua (V-S2+V-S3). All platforms.
# Gum symbols come from Injector re-exports (FridaGum.def on MSVC).
set(PLUGIN_CORE_VM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/plugins/plugin_core_vm)
add_custom_command(OUTPUT ${PLUGIN_CORE_VM_DIR}/GameLuaInjectFramework.c
        COMMAND ${PYTHON_EXECUTABLE_NAME} "${PROJECT_SOURCE_DIR}/tools/lua2c.py"
                "${PLUGIN_CORE_VM_DIR}/GameLuaInjectFramework.lua"
                "${PLUGIN_CORE_VM_DIR}/GameLuaInjectFramework.c"
        DEPENDS ${PLUGIN_CORE_VM_DIR}/GameLuaInjectFramework.lua
        WORKING_DIRECTORY ${PLUGIN_CORE_VM_DIR}
)
add_custom_target(GameLuaInjectFramework DEPENDS ${PLUGIN_CORE_VM_DIR}/GameLuaInjectFramework.c)

set(PLUGIN_CORE_VM_SOURCES
    plugins/plugin_core_vm/plugin_core_vm.cpp
    plugins/plugin_core_vm/GameLua.cpp
    plugins/plugin_core_vm/DontStarveSignature.cpp
    plugins/plugin_core_vm/SignatureJson.cpp
    plugins/plugin_core_vm/GameSignature.cpp
    plugins/plugin_core_vm/GameLuaModule.cpp
    plugins/plugin_core_vm/GameLuaInjectFramework.c
    plugins/plugin_core_vm/lua_debugger_helper.cpp
    plugins/plugin_core_vm/gameio.cpp
    plugins/plugin_core_vm/GameSteam.cpp
    ${DONTSTARVEINJECTOR_UTIL_DIR}/lua_io2.cpp
    ${DONTSTARVEINJECTOR_UTIL_DIR}/zipfile.cpp
)
if (MSVC)
    list(APPEND PLUGIN_CORE_VM_SOURCES
        plugins/plugin_core_vm/GameLua.def
        Progress.cpp)
endif()

ds_add_dynamic_plugin(plugin_core_vm ${PLUGIN_CORE_VM_SOURCES})
add_dependencies(plugin_core_vm GameLuaInjectFramework create_missfuncs)

target_link_libraries(plugin_core_vm PRIVATE
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    function_relocation
    range-v3::meta range-v3::concepts range-v3::range-v3
    ZLIB::ZLIB
    libzip::zip
    SLikeNet
)
if (MSVC)
    target_link_options(plugin_core_vm PRIVATE
        "/NODEFAULTLIB:frida-gum.lib")
endif()
target_compile_definitions(plugin_core_vm PRIVATE
    GUM_STATIC=1
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL
    # Import Injector C++ APIs (Hook, loadlib, InjectorCtx, ...).
    DS_INJECTOR_CONSUMER=1
    # Export GAME_API implemented in this module (GameDbg_*, DS_LUAJIT_set_vm_type, ...).
    DS_CORE_VM_BUILD=1
)
if (MSVC)
    target_compile_definitions(plugin_core_vm PRIVATE SUPPORT_PROGRESS)
endif()
# Headers for moved TUs + L0 shared headers (config, GameLuaType, ...).
target_include_directories(plugin_core_vm PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PLUGIN_CORE_VM_DIR}
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${SOL2_INCLUDE_DIRS}
    ${LUAJIT_INCLUDE_DIR}
    ${PLF_HIVE_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/3rd
)
# lagcomp / remaining Injector TUs still include GameLua.hpp etc.

if (ENABLE_STEAM_SUPPORT)
    target_compile_definitions(plugin_core_vm PRIVATE ENABLE_STEAM_SUPPORT)
    target_include_directories(plugin_core_vm PRIVATE ${STEAM_INCLUDE_DIR} ${STEAM_SDK_INCLUDE_DIR})
    target_link_libraries(plugin_core_vm PRIVATE ${STEAM_LIBRARIES})
    # SteamUser() / interface accessors for GameSteam account id + UGC path.
    target_sources(plugin_core_vm PRIVATE ${DONTSTARVEINJECTOR_UTIL_DIR}/steam.cpp)
endif()

target_include_directories(Injector PUBLIC ${PLUGIN_CORE_VM_DIR})

# Gum-using dynamic plugins need Injector to re-export static frida-gum symbols.
# Windows: FridaGum.def. Linux/macOS: not implemented — skip targets (source also
# #errors via gum_plugin_export.hpp if pulled in by mistake).
if (WIN32)
    ds_add_dynamic_plugin(plugin_network_rpc
        plugins/plugin_network_rpc/plugin_network_rpc.cpp
        plugins/plugin_network_rpc/GameNetwork.cpp)
    # RPC4 / entity network extension (Path A M-N1).
    # Sources under plugins/plugin_network_rpc/. Gum from Injector re-exports.
    target_link_libraries(plugin_network_rpc PRIVATE
        spdlog::spdlog
        SLikeNet
        function_relocation)
    target_link_options(plugin_network_rpc PRIVATE
        "/NODEFAULTLIB:frida-gum.lib")
    target_compile_definitions(plugin_network_rpc PRIVATE
        GUM_STATIC=1
        SPDLOG_COMPILED_LIB
        SPDLOG_FMT_EXTERNAL)
    target_include_directories(plugin_network_rpc PRIVATE
        ${PROJECT_SOURCE_DIR}/3rd
        ${PLF_HIVE_INCLUDE_DIRS}
        ${FRIDA_GUM_INCLUDE_DIR}
        ${FUNCTION_RELOCATION_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugins/plugin_network_rpc)

    ds_add_dynamic_plugin(plugin_network_sim
        plugins/plugin_network_sim/plugin_network_sim.cpp
        plugins/plugin_network_sim/GameNetworkSim.cpp)
    # Outbound net simulation (Path A network.sim). Lazy hook on enable.
    target_link_libraries(plugin_network_sim PRIVATE
        spdlog::spdlog
        function_relocation)
    target_link_options(plugin_network_sim PRIVATE
        "/NODEFAULTLIB:frida-gum.lib")
    target_compile_definitions(plugin_network_sim PRIVATE
        GUM_STATIC=1
        SPDLOG_COMPILED_LIB
        SPDLOG_FMT_EXTERNAL)
    target_include_directories(plugin_network_sim PRIVATE
        ${PROJECT_SOURCE_DIR}/3rd
        ${FRIDA_GUM_INCLUDE_DIR}
        ${FUNCTION_RELOCATION_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugins/plugin_network_sim)

    ds_add_dynamic_plugin(plugin_sim_lagcomp
        plugins/plugin_sim_lagcomp/plugin_sim_lagcomp.cpp
        plugins/plugin_sim_lagcomp/GameSimHook.cpp)
    # Lag compensation entity snapshot (Path A sim.lagcomp). Win x64 only.
    target_link_libraries(plugin_sim_lagcomp PRIVATE
        spdlog::spdlog)
    # GameSimHook includes GameLua.hpp → frida-gum.h #pragma comment; Gum via Injector only.
    target_link_options(plugin_sim_lagcomp PRIVATE
        "/NODEFAULTLIB:frida-gum.lib")
    target_compile_definitions(plugin_sim_lagcomp PRIVATE
        GUM_STATIC=1
        SPDLOG_COMPILED_LIB
        SPDLOG_FMT_EXTERNAL)
    target_include_directories(plugin_sim_lagcomp PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/plugins/plugin_sim_lagcomp)

    ds_add_dynamic_plugin(plugin_render_vbpool
        plugins/plugin_render_vbpool/plugin_render_vbpool.cpp
        plugins/plugin_render_vbpool/GameRenderHook.cpp)
    # HWBuffer pool (Path A M-R2). Sources under plugins/plugin_render_vbpool/.
    target_link_libraries(plugin_render_vbpool PRIVATE
        spdlog::spdlog
        function_relocation)
    target_link_options(plugin_render_vbpool PRIVATE
        "/NODEFAULTLIB:frida-gum.lib")
    target_compile_definitions(plugin_render_vbpool PRIVATE
        GUM_STATIC=1
        SPDLOG_COMPILED_LIB
        SPDLOG_FMT_EXTERNAL)
    target_include_directories(plugin_render_vbpool PRIVATE
        ${PROJECT_SOURCE_DIR}/3rd
        ${PROJECT_SOURCE_DIR}/3rd/angle/win64/include
        ${FRIDA_GUM_INCLUDE_DIR}
        ${FUNCTION_RELOCATION_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugins/plugin_render_vbpool)

    ds_add_dynamic_plugin(plugin_render_angle
        plugins/plugin_render_angle/plugin_render_angle.cpp
        plugins/plugin_render_angle/GameOpenGl.cpp)
    # ANGLE + OpenGL (Path A M-R1). Sources live under plugins/plugin_render_angle/.
    target_link_libraries(plugin_render_angle PRIVATE
        unofficial::angle::libGLESv2
        unofficial::angle::libEGL
        spdlog::spdlog)
    target_link_options(plugin_render_angle PRIVATE
        "/NODEFAULTLIB:frida-gum.lib")
    target_compile_definitions(plugin_render_angle PRIVATE
        GUM_STATIC=1
        SPDLOG_COMPILED_LIB
        SPDLOG_FMT_EXTERNAL)
    target_include_directories(plugin_render_angle PRIVATE
        ${PROJECT_SOURCE_DIR}/3rd
        ${FRIDA_GUM_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugins/plugin_render_angle)

    # debug.profiler — Tracy / FullGC / FrameGC (Path A). Win gum plugins section.
    # AlwaysOn native face; Lua AfterModMain gates business work (later tasks).
    ds_add_dynamic_plugin(plugin_debug_profiler
        plugins/plugin_debug_profiler/plugin_debug_profiler.cpp
        plugins/plugin_debug_profiler/ProfilerApi.cpp
        plugins/plugin_debug_profiler/FullGcPolicy.cpp)
    target_link_libraries(plugin_debug_profiler PRIVATE
        spdlog::spdlog
        function_relocation
        Tracy::TracyClient)
    if (MSVC)
        target_link_options(plugin_debug_profiler PRIVATE "/NODEFAULTLIB:frida-gum.lib")
    endif()
    target_compile_definitions(plugin_debug_profiler PRIVATE
        GUM_STATIC=1
        SPDLOG_COMPILED_LIB
        SPDLOG_FMT_EXTERNAL
        DS_INJECTOR_CONSUMER=1)
    target_include_directories(plugin_debug_profiler PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PLUGIN_CORE_VM_DIR}
        ${FRIDA_GUM_INCLUDE_DIR}
        ${FUNCTION_RELOCATION_INCLUDE_DIR}
        ${LUAJIT_INCLUDE_DIR})
else()
    message(WARNING
        "Skipping gum-using dynamic plugins (network.rpc / network.sim / sim.lagcomp / render.vbpool / render.angle / debug.profiler): "
        "Injector Frida Gum re-export is unimplemented on Linux/macOS (Windows uses FridaGum.def). "
        "Wait for ELF/Mach-O export-list fix; do not static-link a second frida-gum into plugins.")
endif()


