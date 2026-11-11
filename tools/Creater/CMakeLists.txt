cmake_minimum_required(VERSION 3.15)

set(DONTSTARVEINJECTOR_PLUGINS_DIR ${DONTSTARVEINJECTOR_ROOT}/plugins)

# Repository signature providers, linked into the tool directly: the tool must
# check every shipped definition without loading the Injector or a plugin DLL.
# One entry per provider TU — the table itself lives in signature_providers.cpp.
set(DS_PROVIDER_SOURCES
        signature_providers.cpp
        ${DONTSTARVEINJECTOR_ROOT}/core/InjectorSignatures.cpp
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_debug_profiler/ProfilerSignatures.cpp
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_fps_render/FpsSignatures.cpp
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_network_rpc/NetworkRpcSignatures.cpp
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_network_sim/NetworkSimSignatures.cpp
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_network_stats/NetStatsSignatures.cpp
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_network_stats/ClientPingDecode.cpp
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_network_tick/NetworkTickSignatures.cpp
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_render_shadow/ShadowSignatures.cpp
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_render_vbpool/VbpoolSignatures.cpp
)
set(DS_PROVIDER_INCLUDE_DIRS
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_debug_profiler
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_fps_render
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_network_rpc
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_network_sim
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_network_stats
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_network_tick
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_render_shadow
        ${DONTSTARVEINJECTOR_PLUGINS_DIR}/plugin_render_vbpool
)

set(SOURCES
        main.cpp
        ${DS_PROVIDER_SOURCES}
        ${DONTSTARVEINJECTOR_ROOT}/config/InjectorHostConfig.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
        # loadlib() walks the roots registered by configure_plugin_dll_search();
        # these tools compile util/platform.cpp standalone, so the registry owner
        # (core/PluginPath.cpp) has to be linked in as well.
        ${DONTSTARVEINJECTOR_ROOT}/core/PluginPath.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/gum_platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_library(signature_updater SHARED ${SOURCES})

    if (APPLE)
        set(GAME_EXECUTABLE_DIR ${GAME_INSTALL_PREFIX}/MacOS)
        set(GAME_EXECUTABLE_NAME "dontstarve_steam_x64_1")
        if(NOT EXISTS ${GAME_EXECUTABLE_DIR}/${GAME_EXECUTABLE_NAME})
            set(GAME_EXECUTABLE_NAME "dontstarve_steam_x64")
        endif()
        set(GAME_SERVER_EXECUTABLE_NAME "dontstarve_dedicated_server_nullrenderer_x64_1")
        if(NOT EXISTS ${GAME_EXECUTABLE_DIR}/${GAME_SERVER_EXECUTABLE_NAME})
            set(GAME_SERVER_EXECUTABLE_NAME "dontstarve_dedicated_server_nullrenderer_x64")
        endif()
        set(PRELOAD_ENV_KEY DYLD_INSERT_LIBRARIES)
        add_custom_target(create_signatures
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" SIGNATURE_TOOL_MODE=create ${GAME_INSTALL_PREFIX}/${GAME_EXECUTABLE_NAME}
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" SIGNATURE_TOOL_MODE=create ${GAME_INSTALL_PREFIX}/${GAME_SERVER_EXECUTABLE_NAME}
                WORKING_DIRECTORY ${GAME_INSTALL_PREFIX}
        )
        add_custom_target(check_signatures
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" SIGNATURE_TOOL_MODE=check ${GAME_INSTALL_PREFIX}/${GAME_EXECUTABLE_NAME}
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" SIGNATURE_TOOL_MODE=check ${GAME_INSTALL_PREFIX}/${GAME_SERVER_EXECUTABLE_NAME}
                WORKING_DIRECTORY ${GAME_INSTALL_PREFIX}
        )
        add_custom_target(update_signatures
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" SIGNATURE_TOOL_MODE=update ${GAME_INSTALL_PREFIX}/${GAME_EXECUTABLE_NAME}
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" SIGNATURE_TOOL_MODE=update ${GAME_INSTALL_PREFIX}/${GAME_SERVER_EXECUTABLE_NAME}
                WORKING_DIRECTORY ${GAME_INSTALL_PREFIX}
        )
    else ()
        set(GAME_EXECUTABLE_DIR ${GAME_INSTALL_PREFIX})
        set(GAME_EXECUTABLE_NAME "dontstarve_steam_x64_1")
        if(NOT EXISTS ${GAME_EXECUTABLE_DIR}/${GAME_EXECUTABLE_NAME})
            set(GAME_EXECUTABLE_NAME "dontstarve_steam_x64")
        endif()
        set(GAME_SERVER_EXECUTABLE_NAME "dontstarve_dedicated_server_nullrenderer_x64_1")
        if(NOT EXISTS ${GAME_EXECUTABLE_DIR}/${GAME_SERVER_EXECUTABLE_NAME})
            set(GAME_SERVER_EXECUTABLE_NAME "dontstarve_dedicated_server_nullrenderer_x64")
        endif()
        set(PRELOAD_ENV_KEY LD_PRELOAD)

        add_custom_target(create_signatures
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" LUA51_SIGNATURE_OUTPUT_DIR="${CMAKE_INSTALL_PREFIX}" SIGNATURE_TOOL_MODE=create
                ${CMAKE_CURRENT_SOURCE_DIR}/update_signatures.sh ${LUA_EXECUTABLE_PATH} "./${GAME_EXECUTABLE_NAME}" "./${GAME_SERVER_EXECUTABLE_NAME}"
                WORKING_DIRECTORY ${GAME_INSTALL_PREFIX}
        )
        add_custom_target(update_signatures
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" LUA51_SIGNATURE_OUTPUT_DIR="${CMAKE_INSTALL_PREFIX}" SIGNATURE_TOOL_MODE=update
                ${CMAKE_CURRENT_SOURCE_DIR}/update_signatures.sh ${LUA_EXECUTABLE_PATH} "./${GAME_EXECUTABLE_NAME}" "./${GAME_SERVER_EXECUTABLE_NAME}"
                WORKING_DIRECTORY ${GAME_INSTALL_PREFIX}
        )
        add_custom_target(check_signatures
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" LUA51_SIGNATURE_OUTPUT_DIR="${CMAKE_INSTALL_PREFIX}" SIGNATURE_TOOL_MODE=check
                ${CMAKE_CURRENT_SOURCE_DIR}/update_signatures.sh ${LUA_EXECUTABLE_PATH} "./${GAME_EXECUTABLE_NAME}" "./${GAME_SERVER_EXECUTABLE_NAME}"
                WORKING_DIRECTORY ${GAME_INSTALL_PREFIX}
        )
    endif ()
else ()
    add_executable(signature_updater ${SOURCES})
    # Two explicit targets: `create_signatures` rebuilds every entry from
    # scratch (stored DB ignored); `update_signatures` requires the stored DB and
    # re-runs the update pass on it, so a matching version can no longer turn the
    # run into a no-op.
    add_custom_target(create_signatures
            COMMAND signature_updater create
    )
    add_custom_target(update_signatures
            COMMAND signature_updater update
    )
    # Read-only verification of both DBs (Lua + fixed) against the installed game.
    add_custom_target(check_signatures
            COMMAND signature_updater check
    )
endif ()

target_include_directories(signature_updater PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(signature_updater PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR})
target_include_directories(signature_updater PUBLIC ${DONTSTARVEINJECTOR_ROOT})
target_link_libraries(signature_updater PRIVATE spdlog::spdlog)


target_include_directories(signature_updater PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(signature_updater PRIVATE Frida::Gum)

target_link_libraries(signature_updater PRIVATE nlohmann_json::nlohmann_json)
# Order matters for static archives: dependents first, then providers.
# ds_signature calls nucleus_analyze_file / apply_nucleus_* in function_relocation_static.
target_link_libraries(signature_updater PRIVATE ds_signature ds_signature_provider function_relocation_static)
if (TARGET stage_lua51_training)
    add_dependencies(signature_updater stage_lua51_training)
endif()
target_include_directories(signature_updater PRIVATE ${DONTSTARVEINJECTOR_ROOT}/plugins/plugin_core_vm/signature_load)
target_include_directories(signature_updater PRIVATE ${DS_PROVIDER_INCLUDE_DIRS})
target_include_directories(signature_updater PUBLIC ${FUNCTION_RELOCATION_INCLUDE_DIR})

target_compile_definitions(signature_updater PUBLIC
        DS_PLUGIN_HOST_STATIC
        GAMEDIR="${GAME_DIR}"
        LUA51_PATH="${LUA_LIBRARIES_PATH}"
        WORKER_DIR="${CMAKE_INSTALL_PREFIX}"
        EXECUTABLE_SUFFIX="${CMAKE_EXECUTABLE_SUFFIX}"
)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(verify_linux_signatures
        verify_linux_signatures.cpp
        ${DS_PROVIDER_SOURCES}
        ${DONTSTARVEINJECTOR_ROOT}/config/InjectorHostConfig.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
        ${DONTSTARVEINJECTOR_ROOT}/core/PluginPath.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/gum_platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp)
    target_include_directories(verify_linux_signatures PRIVATE
        ${PROJECT_SOURCE_DIR}/src ${DONTSTARVEINJECTOR_ROOT} ${DONTSTARVEINJECTOR_UTIL_DIR}
        ${DONTSTARVEINJECTOR_ROOT}/plugins/plugin_core_vm/signature_load
        ${DS_PROVIDER_INCLUDE_DIRS})
    target_compile_definitions(verify_linux_signatures PRIVATE DS_PLUGIN_HOST_STATIC)
    target_link_libraries(verify_linux_signatures PRIVATE ds_signature ds_signature_provider
        function_relocation_static Frida::Gum)
endif()

if (MSVC)
    target_link_options(signature_updater PUBLIC "/NODEFAULTLIB:LIBCMT")
endif ()

# Copy every config-matched runtime DLL next to the tool (frida-gum, spdlog,
# fmt, bzip/zlib, and pe-parse). pe-parse matters most: it is an imported SHARED
# dependency whose std::string crosses the ABI, so a Debug consumer that loads
# the Release copy staged in Mod/deps reads back section names through a
# mismatched std::string layout and crashes (0xC0000005) inside IterSec.
if (WIN32)
    add_custom_command(TARGET signature_updater POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:signature_updater>
            "$<TARGET_FILE_DIR:signature_updater>"
        COMMAND_EXPAND_LISTS
        VERBATIM)
endif()

add_dependencies(signature_updater create_missfuncs)

if (WIN32)
    # Standalone tool: enumerates game EXE imports via util/module.cpp.
    # module.hpp pulls config/InjectorHostConfig.hpp (export macros only).
    add_executable(angle_iat_api_generator
            angle_iat_api_generator.cpp
            ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
            ${DONTSTARVEINJECTOR_ROOT}/core/PluginPath.cpp
            ${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
    )

    target_include_directories(angle_iat_api_generator PRIVATE
            ${DONTSTARVEINJECTOR_UTIL_DIR}
            ${DONTSTARVEINJECTOR_ROOT}
            ${PROJECT_SOURCE_DIR}/src
    )
    # Compile util sources into this EXE — not dllimport from Injector.
    target_compile_definitions(angle_iat_api_generator PRIVATE
            DS_PLUGIN_HOST_STATIC
            GAMEDIR="${GAME_DIR}"
            EXECUTABLE_SUFFIX="${CMAKE_EXECUTABLE_SUFFIX}"
            OUTPUT_HPP_PATH="${PROJECT_SOURCE_DIR}/src/DontStarveInjector/angle_iat_generated.hpp"
    )

    if (MSVC)
        target_link_options(angle_iat_api_generator PRIVATE "/NODEFAULTLIB:LIBCMT")
    endif ()
endif ()
