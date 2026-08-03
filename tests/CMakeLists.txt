if (WIN32)
    add_library(lua51_sync_strfmt_pushfstring_module MODULE
        lua51_sync/strfmt_pushfstring_module.c)
    add_custom_target(lua51_sync_artifacts
        DEPENDS lua ${LUAJIT_EXECUTABLE_TARGET} lua51_sync_strfmt_pushfstring_module)
    set_target_properties(lua51_sync_strfmt_pushfstring_module PROPERTIES
        PREFIX ""
        OUTPUT_NAME "strfmt_pushfstring_module")
    foreach (cfg Debug Release RelWithDebInfo MinSizeRel)
        string(TOUPPER "${cfg}" cfg_upper)
        set_target_properties(lua51_sync_strfmt_pushfstring_module PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY_${cfg_upper} "${CMAKE_CURRENT_BINARY_DIR}/lua51_sync/${cfg}"
            LIBRARY_OUTPUT_DIRECTORY_${cfg_upper} "${CMAKE_CURRENT_BINARY_DIR}/lua51_sync/${cfg}")
    endforeach ()

    add_test(
        NAME lua51_sync
        COMMAND ${CMAKE_COMMAND} -E env
            LUA51_SYNC_BUILD_DIR=${CMAKE_BINARY_DIR}
            LUA51_SYNC_CONFIG=$<CONFIG>
            ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/lua51_sync/run.py
    )
    set_tests_properties(lua51_sync PROPERTIES
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif ()

add_test(
    NAME fork_save_lua
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/fork_save/run.py
)
set_tests_properties(fork_save_lua PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(test_buffer_name_pool
    ${CMAKE_CURRENT_SOURCE_DIR}/test_buffer_name_pool.cpp)
target_include_directories(test_buffer_name_pool PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_buffer_name_pool PRIVATE cxx_std_17)
add_test(NAME BufferNamePool COMMAND test_buffer_name_pool)

# --- PluginHost pure-logic unit tests (M0) ---
set(PLUGIN_HOST_SOURCES
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginHost.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginOptionRules.cpp
)

add_executable(test_plugin_host_graph
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_host_graph.cpp
    ${PLUGIN_HOST_SOURCES})
target_include_directories(test_plugin_host_graph PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_host_graph PRIVATE cxx_std_23)
add_test(NAME plugin_host_graph COMMAND test_plugin_host_graph)

add_executable(test_plugin_option_rules
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_option_rules.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginOptionRules.cpp)
target_include_directories(test_plugin_option_rules PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_option_rules PRIVATE cxx_std_23)
add_test(NAME plugin_option_rules COMMAND test_plugin_option_rules)

set(PLUGIN_CONFIG_BRIDGE_SOURCES
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginConfigBridge.cpp
)

add_executable(test_plugin_config_bridge
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_config_bridge.cpp
    ${PLUGIN_HOST_SOURCES}
    ${PLUGIN_CONFIG_BRIDGE_SOURCES})
target_include_directories(test_plugin_config_bridge PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_config_bridge PRIVATE cxx_std_23)
add_test(NAME plugin_config_bridge COMMAND test_plugin_config_bridge)

add_test(
    NAME plugin_host_lua
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/run_lua_host.py
)
set_tests_properties(plugin_host_lua PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_test(
    NAME plugin_trunk_surface
    COMMAND ${PYTHON_EXECUTABLE_NAME}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugin/check_trunk_surface.py
        ${CMAKE_SOURCE_DIR})
set_tests_properties(plugin_trunk_surface PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})




add_test(NAME plugin_dedicated_sim_pause
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        DST_GAME_DIR=$ENV{DST_GAME_DIR}
        ${PYTHON_EXECUTABLE_NAME}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugin_server/run_dedicated_sim_pause.py)
set_tests_properties(plugin_dedicated_sim_pause PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    TIMEOUT 600)

add_test(NAME plugin_client_inject_smoke
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        DST_GAME_DIR=$ENV{DST_GAME_DIR}
        ${PYTHON_EXECUTABLE_NAME}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugin_client/run_client_inject_smoke.py)
set_tests_properties(plugin_client_inject_smoke PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    TIMEOUT 900)

add_test(NAME plugin_client_host_smoke
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        DST_GAME_DIR=$ENV{DST_GAME_DIR}
        LC_MODE=host
        ${PYTHON_EXECUTABLE_NAME}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugin_client/run_client_inject_smoke.py
        --mode host)
set_tests_properties(plugin_client_host_smoke PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    TIMEOUT 900)


# --- LuaJIT variant registry characterization test ---
# Asserts that the generated variant contract file describes the registered
# LuaJIT variants and their target/output/executable names. The contract file
# is generated at configure time by luajit_generate_variant_contract().
add_test(
    NAME luajit_variant_registry
    COMMAND ${CMAKE_COMMAND}
        -DLUAJIT_VARIANT_CONTRACT_FILE=${CMAKE_BINARY_DIR}/luajit_variant_contract.txt
        -P ${CMAKE_CURRENT_SOURCE_DIR}/luajit_variant_registry_test.cmake
)

add_test(
    NAME luajit_gengc_output_name
    COMMAND ${CMAKE_COMMAND}
        -DLUAJIT_GENGC_TARGET_FILE_NAME_FILE=${CMAKE_BINARY_DIR}/$<CONFIG>/luajit_gengc_target_file_name.txt
        -P ${CMAKE_CURRENT_SOURCE_DIR}/luajit_gengc_output_name_test.cmake
)
