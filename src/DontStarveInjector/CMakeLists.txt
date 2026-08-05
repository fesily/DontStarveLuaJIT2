option(ENABLE_FAKE_API "check inejctor hook lua func" OFF)
option(ENABLE_ONLY_LUA51 "load lua51.dll" OFF)
option(ENABLE_USE_LISTENER "use api listener" OFF)
option(ENABLE_STEAM_SUPPORT "Enable Steam support" ON)

set(SOURCES
        DontStarveInjector.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/inlinehook.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/gum_platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/lua51_object.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/PersistentString.cpp
        config/ConfigSession.cpp
        config/write/SaveConfigWriter.cpp
        GameRuntimeApis.cpp
        config/sources/LuajitConfigFile.cpp
        game_info.cpp
        config/InjectorHostConfig.cpp
        core/PluginHost.cpp
        core/PluginServices.cpp
        core/LuaEventBus.cpp
        core/PluginOptionRules.cpp
        config/ConfigSchema.cpp
        config/CascadeEngine.cpp
        config/ConfigResolve.cpp
        config/path/ConfigPaths.cpp
        config/path/ModIdentity.cpp
        config/sources/ModinfoDefaultSource.cpp
        config/sources/LuajitConfigSource.cpp
        config/sources/SaveFileSource.cpp
        config/sources/ModOverridesSource.cpp
        config/sources/EnvOrCmdSource.cpp
        config/sources/SaveParse.cpp
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

# L0 config cascade (save write-back + stock sol2) uses a dedicated PUC
# Lua 5.1 VM (src/lua51original → liblua_static). Do NOT link game LuaJIT here:
# core.vm owns the game VM; sol in GameLuaModule is GameDbg-specialized and lives
# only in plugin_core_vm.
#
# Headers: PRIVATE lua51original so Injector TUs (sol cascade, lua_event_notifyer
# incomplete type) see stock lua.h — not LUAJIT_INCLUDE_DIR (that stays on core.vm).
target_include_directories(Injector PRIVATE
    ${PROJECT_SOURCE_DIR}/src/lua51original/src
    ${CMAKE_BINARY_DIR}/src/lua51original  # generated luaconf.h if needed
)
# Prefer build-tree include for configured luaconf.h
if (TARGET liblua_static)
    # PRIVATE static embed: cascade-only VM. Symbols must not export from Injector
    # (liblua_static is built with hidden visibility on ELF).
    target_link_libraries(Injector PRIVATE liblua_static)
    add_dependencies(Injector liblua_static)
    if (NOT MSVC)
        # Defense in depth: do not re-export static lib symbols from Injector.so
        target_link_options(Injector PRIVATE "-Wl,--exclude-libs,ALL")
    endif()
else()
    message(FATAL_ERROR "liblua_static (src/lua51original) required for L0 config cascade")
endif()

# Optional legacy switches: macros only — do not re-link game JIT into L0.
if (ENABLE_ONLY_LUA51)
    target_compile_definitions(Injector PUBLIC ENABLE_ONLY_LUA51)
endif ()
if (ENABLE_FAKE_API)
    target_compile_definitions(Injector PUBLIC ENABLE_FAKE_API)
    target_include_directories(Injector PRIVATE ${LUA_INCLUDE_DIR})
endif ()
if (ENABLE_USE_LISTENER)
    target_compile_definitions(Injector PUBLIC ENABLE_USE_LISTENER)
endif ()

if (MSVC)
    target_link_options(Injector PUBLIC "/NODEFAULTLIB:LIBCMT")
endif ()

install(TARGETS Injector RUNTIME DESTINATION .)

if (WIN32)
    add_subdirectory(loader)
endif ()

add_subdirectory(util)

# Dynamic plugin modules (Phase B). Output next to Injector under plugins/.
# Each plugin owns plugins/<name>/CMakeLists.txt; this file only defines the
# shared helper and orchestrates add_subdirectory.
function(ds_add_dynamic_plugin name)
    add_library(${name} MODULE ${ARGN})
    # Plugin dir (CMAKE_CURRENT_SOURCE_DIR when called from plugins/<name>/)
    # plus Injector root so "config/InjectorHostConfig.hpp", "util/...", "core/..." resolve.
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${DONTSTARVEINJECTOR_ROOT}
        ${DONTSTARVEINJECTOR_UTIL_DIR})
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

# Always-on / cross-platform plugins (no second Frida Gum).
add_subdirectory(plugins/plugin_dummy)
add_subdirectory(plugins/plugin_save_fork)
add_subdirectory(plugins/plugin_core_vm)

# Gum-using dynamic plugins need Injector to re-export static frida-gum symbols.
# Windows: FridaGum.def. Linux/macOS: not implemented — skip targets (source also
# #errors via gum_plugin_export.hpp if pulled in by mistake).
if (WIN32)
    add_subdirectory(plugins/plugin_network_rpc)
    add_subdirectory(plugins/plugin_network_sim)
    add_subdirectory(plugins/plugin_sim_lagcomp)
    add_subdirectory(plugins/plugin_render_vbpool)
    add_subdirectory(plugins/plugin_render_angle)
    add_subdirectory(plugins/plugin_debug_profiler)
    add_subdirectory(plugins/plugin_fps_render)
    add_subdirectory(plugins/plugin_network_tick)
else()
    message(WARNING
        "Skipping gum-using dynamic plugins (network.rpc / network.sim / sim.lagcomp / render.vbpool / render.angle / debug.profiler): "
        "Injector Frida Gum re-export is unimplemented on Linux/macOS (Windows uses FridaGum.def). "
        "Wait for ELF/Mach-O export-list fix; do not static-link a second frida-gum into plugins.")
endif()

