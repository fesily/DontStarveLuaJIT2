# core.vm — optional Signature + GameLua (V-S2+V-S3). All platforms.
# Gum symbols come from Injector re-exports (FridaGum.def on MSVC).
#
# Layout:
#   signature_load/  → STATIC ds_signature (scan/json/progress)
#   this dir         → MODULE plugin_core_vm (VM replace, gameio, GameInjector)

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

set(PLUGIN_CORE_VM_SOURCES
    plugin_core_vm.cpp
    GameLua.cpp
    GameLuaModule.cpp
    GameLuaInjectFramework.c
    lua_debugger_helper.cpp
    gameio.cpp
    GameSteam.cpp
    ${DONTSTARVEINJECTOR_UTIL_DIR}/lua_io2.cpp
    ${DONTSTARVEINJECTOR_UTIL_DIR}/zipfile.cpp
)
if (MSVC)
    list(APPEND PLUGIN_CORE_VM_SOURCES
        GameLua.def)
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
    # Match pre-split behavior: ShowProgressWindow during signature update.
    target_compile_definitions(plugin_core_vm PRIVATE SUPPORT_PROGRESS)
endif()

target_include_directories(plugin_core_vm PRIVATE
    ${DONTSTARVEINJECTOR_ROOT}
    ${PLUGIN_CORE_VM_DIR}
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
    target_sources(plugin_core_vm PRIVATE ${DONTSTARVEINJECTOR_UTIL_DIR}/steam.cpp)
endif()

# lagcomp / remaining Injector TUs still include GameLua.hpp etc.
# Also expose signature_load headers (DontStarveSignature.hpp) via PUBLIC on ds_signature;
# keep plugin_core_vm dir PUBLIC for GameLua.hpp consumers.
target_include_directories(Injector PUBLIC
    ${PLUGIN_CORE_VM_DIR}
    ${PLUGIN_CORE_VM_DIR}/signature_load)
