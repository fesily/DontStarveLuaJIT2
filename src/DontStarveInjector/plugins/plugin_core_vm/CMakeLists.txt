# core.vm — required Signature + GameLua + game I/O (force-loaded at inject). All platforms.
# Gum symbols from Frida::Gum shared (linked explicitly on this gum-using plugin).
#
# Layout:
#   signature_load/  → STATIC ds_signature (scan/json/progress)
#   io/              → gameio + GameSteam (workshop path + lj_* I/O)
#   this dir         → MODULE plugin_core_vm (VM replace, GameInjector open)

set(PLUGIN_CORE_VM_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(signature_load)

add_custom_command(OUTPUT ${PLUGIN_CORE_VM_DIR}/GameLuaInjectFramework.c
        COMMAND ${PYTHON_EXECUTABLE_NAME} "${PROJECT_SOURCE_DIR}/tools/lua2c.py"
                "${PLUGIN_CORE_VM_DIR}/GameLuaInjectFramework.lua"
                "${PLUGIN_CORE_VM_DIR}/GameLuaInjectFramework.c"
        DEPENDS ${PLUGIN_CORE_VM_DIR}/GameLuaInjectFramework.lua
        WORKING_DIRECTORY ${PLUGIN_CORE_VM_DIR}
)
add_custom_target(GameLuaInjectFramework DEPENDS ${PLUGIN_CORE_VM_DIR}/GameLuaInjectFramework.c)

# --- I/O face (same MODULE, grouped under io/) ---
set(PLUGIN_CORE_VM_IO_SOURCES
    io/gameio.cpp
    io/GameSteam.cpp
    ${DONTSTARVEINJECTOR_UTIL_DIR}/lua_io2.cpp
    ${DONTSTARVEINJECTOR_UTIL_DIR}/zipfile.cpp
)

# --- VM replace + GameInjector ---
set(PLUGIN_CORE_VM_VM_SOURCES
    plugin_core_vm.cpp
    GameLua.cpp
    GameLuaModule.cpp
    GameLuaInjectFramework.c
    lua_debugger_helper.cpp
    LuaEventBus.cpp
    GameInjectorApply.cpp
    lua_fake.cpp
)

set(PLUGIN_CORE_VM_SOURCES
    ${PLUGIN_CORE_VM_VM_SOURCES}
    ${PLUGIN_CORE_VM_IO_SOURCES}
)
if (MSVC)
    list(APPEND PLUGIN_CORE_VM_SOURCES GameLua.def)
endif()

ds_add_dynamic_plugin(plugin_core_vm ${PLUGIN_CORE_VM_SOURCES})
add_dependencies(plugin_core_vm GameLuaInjectFramework create_missfuncs)

target_link_libraries(plugin_core_vm PRIVATE
    ds_signature
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    function_relocation
    range-v3::meta range-v3::concepts range-v3::range-v3
    ZLIB::ZLIB
    libzip::zip
    SLikeNet
)
target_compile_definitions(plugin_core_vm PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL
    DS_INJECTOR_CONSUMER=1
    DS_CORE_VM_BUILD=1
)
if (MSVC)
    target_compile_definitions(plugin_core_vm PRIVATE SUPPORT_PROGRESS)
endif()

target_include_directories(plugin_core_vm PRIVATE
    ${DONTSTARVEINJECTOR_ROOT}
    ${PLUGIN_CORE_VM_DIR}
    ${PLUGIN_CORE_VM_DIR}/io
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${SOL2_INCLUDE_DIRS}
    ${LUAJIT_INCLUDE_DIR}
    ${PLF_HIVE_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/3rd
)

if (ENABLE_STEAM_SUPPORT)
    target_compile_definitions(plugin_core_vm PRIVATE ENABLE_STEAM_SUPPORT)
    target_include_directories(plugin_core_vm PRIVATE ${STEAM_INCLUDE_DIR} ${STEAM_SDK_INCLUDE_DIR})
    target_link_libraries(plugin_core_vm PRIVATE ${STEAM_LIBRARIES})
    # SteamUser() accessors for GameSteam account id (io/GameSteam.cpp).
    target_sources(plugin_core_vm PRIVATE ${DONTSTARVEINJECTOR_UTIL_DIR}/steam.cpp)
endif()

# Consumers (lagcomp, profiler, Injector) need GameLua.hpp + signature headers.
target_include_directories(Injector PUBLIC
    ${PLUGIN_CORE_VM_DIR}
    ${PLUGIN_CORE_VM_DIR}/signature_load
    ${PLUGIN_CORE_VM_DIR}/io)

# Optional fake-API trampolines (lua_fake.cpp) — parent option ENABLE_FAKE_API.
if (ENABLE_FAKE_API)
    target_compile_definitions(plugin_core_vm PRIVATE ENABLE_FAKE_API)
endif()
if (ENABLE_ONLY_LUA51)
    target_compile_definitions(plugin_core_vm PRIVATE ENABLE_ONLY_LUA51)
endif()

# Build-tree stage: lua51* under Injector/deps; require Mod/signatures_*.json present.
# Package install: lua51* → Mod/deps, signatures → Mod/ root.
add_custom_command(TARGET plugin_core_vm POST_BUILD
    COMMAND ${CMAKE_COMMAND}
        "-DDS_OUT=$<TARGET_FILE_DIR:Injector>/deps"
        "-DDS_CFG=$<CONFIG>"
        "-DDS_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
        "-DDS_BINARY_DIR=${CMAKE_BINARY_DIR}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/stage_core_vm_deps.cmake"
    COMMENT "stage core.vm lua into Injector/deps; require Mod/signatures_*.json"
    VERBATIM)
