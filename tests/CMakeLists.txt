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
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginServices.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/GameInjectorLuaRegistry.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/config/ConfigSchema.cpp
)

add_executable(test_plugin_host_graph
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_host_graph.cpp
    ${PLUGIN_HOST_SOURCES})
target_include_directories(test_plugin_host_graph PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_host_graph PRIVATE cxx_std_23)
target_compile_definitions(test_plugin_host_graph PRIVATE DS_PLUGIN_HOST_STATIC)
add_test(NAME plugin_host_graph COMMAND test_plugin_host_graph)

add_executable(test_plugin_option_rules
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_option_rules.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginOptionRules.cpp)
target_include_directories(test_plugin_option_rules PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_option_rules PRIVATE cxx_std_23)
add_test(NAME plugin_option_rules COMMAND test_plugin_option_rules)

add_executable(test_config_schema
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_config_schema.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/config/ConfigSchema.cpp)
target_include_directories(test_config_schema PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_config_schema PRIVATE cxx_std_23)
add_test(NAME config_schema COMMAND test_config_schema)

add_executable(test_config_source_whitelist
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_config_source_whitelist.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/config/CascadeEngine.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/config/ConfigSchema.cpp)
target_include_directories(test_config_source_whitelist PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_config_source_whitelist PRIVATE cxx_std_23)
target_compile_definitions(test_config_source_whitelist PRIVATE DS_PLUGIN_HOST_STATIC)
find_package(spdlog CONFIG REQUIRED)
target_link_libraries(test_config_source_whitelist PRIVATE spdlog::spdlog)
add_test(NAME config_source_whitelist COMMAND test_config_source_whitelist)

add_executable(test_config_resolve
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_config_resolve.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/config/CascadeEngine.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/config/ConfigSchema.cpp)
target_include_directories(test_config_resolve PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_config_resolve PRIVATE cxx_std_23)
target_compile_definitions(test_config_resolve PRIVATE DS_PLUGIN_HOST_STATIC)
find_package(spdlog CONFIG REQUIRED)
target_link_libraries(test_config_resolve PRIVATE spdlog::spdlog)
add_test(NAME config_resolve COMMAND test_config_resolve)


set(PLUGIN_CONFIG_VIEW_SOURCES
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginConfigBridge.cpp
)

# ConfigView SSOT merge (BuildConfigView). Historical ctest name plugin_config_bridge
# remains as an alias so -R plugin_ still matches this gate.
add_executable(test_config_view_build
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_config_view_build.cpp
    ${PLUGIN_HOST_SOURCES}
    ${PLUGIN_CONFIG_VIEW_SOURCES})
target_include_directories(test_config_view_build PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_config_view_build PRIVATE cxx_std_23)
target_compile_definitions(test_config_view_build PRIVATE DS_PLUGIN_HOST_STATIC)
add_test(NAME config_view_build COMMAND test_config_view_build)
add_test(NAME plugin_config_bridge COMMAND test_config_view_build)

add_executable(test_dynamic_plugin_loader
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_dynamic_plugin_loader.cpp
    ${PLUGIN_HOST_SOURCES}
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/DynamicPluginLoader.cpp)
target_include_directories(test_dynamic_plugin_loader PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_dynamic_plugin_loader PRIVATE cxx_std_23)
target_compile_definitions(test_dynamic_plugin_loader PRIVATE DS_PLUGIN_HOST_STATIC)
add_test(NAME plugin_dynamic_loader COMMAND test_dynamic_plugin_loader)

# L0 lua_event bus — no hard-coded plugin DLL forwarder
add_executable(test_lua_event_bus
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_lua_event_bus.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/LuaEventBus.cpp)
target_include_directories(test_lua_event_bus PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_lua_event_bus PRIVATE cxx_std_23)
target_compile_definitions(test_lua_event_bus PRIVATE DS_PLUGIN_HOST_STATIC)
add_test(NAME lua_event_bus COMMAND test_lua_event_bus)

# Process-wide named service table (plugin → host → core.vm)
add_executable(test_plugin_services
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_services.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginServices.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginHost.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginOptionRules.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/GameInjectorLuaRegistry.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/config/ConfigSchema.cpp)
target_include_directories(test_plugin_services PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_services PRIVATE cxx_std_23)
target_compile_definitions(test_plugin_services PRIVATE DS_PLUGIN_HOST_STATIC)
add_test(NAME plugin_services COMMAND test_plugin_services)

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
