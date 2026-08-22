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
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_render_vbpool)
target_compile_features(test_buffer_name_pool PRIVATE cxx_std_17)
add_test(NAME BufferNamePool COMMAND test_buffer_name_pool)

# --- PluginHost pure-logic unit tests (M0) ---
find_path(SOL2_INCLUDE_DIRS "sol/abort.hpp")
set(PLUGIN_HOST_SOURCES
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginHost.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginOptionRules.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginServices.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/GameInjectorLuaRegistry.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/config/ConfigSchema.cpp
)

# ConfigSchema.cpp includes generated src/modinfo.hpp (create_modinfo_hpp).
# Any target that compiles ConfigSchema.cpp must depend on that custom target.
set(DS_CONFIG_SCHEMA_TARGETS
    test_plugin_host_graph
    test_config_schema
    test_config_source_whitelist
    test_config_resolve
    test_config_view_build
    test_dynamic_plugin_loader
    test_plugin_services
)
# Targets added later that also use PLUGIN_HOST_SOURCES / ConfigSchema should
# call: add_dependencies(<tgt> create_modinfo_hpp)


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

add_executable(test_sun_model
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_sun_model.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_render_shadow/SunModel.cpp)
target_include_directories(test_sun_model PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_render_shadow)
target_compile_features(test_sun_model PRIVATE cxx_std_23)
add_test(NAME sun_model COMMAND test_sun_model)

add_executable(test_shadow_matrix
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_shadow_matrix.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_render_shadow/SilhouetteMath.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_render_shadow/SunModel.cpp)
target_include_directories(test_shadow_matrix PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_render_shadow)
target_compile_features(test_shadow_matrix PRIVATE cxx_std_23)
add_test(NAME shadow_matrix COMMAND test_shadow_matrix)

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
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/DynamicPluginLoader.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginPath.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginPendingUpdates.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/ExternalPluginDiscovery.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/EnabledDstMods.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginPackModinfo.cpp)
target_include_directories(test_dynamic_plugin_loader PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector
    ${SOL2_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/src/lua51original/src
    ${CMAKE_BINARY_DIR}/src/lua51original)
target_compile_features(test_dynamic_plugin_loader PRIVATE cxx_std_23)
target_compile_definitions(test_dynamic_plugin_loader PRIVATE DS_PLUGIN_HOST_STATIC)
if (TARGET liblua_static)
    target_link_libraries(test_dynamic_plugin_loader PRIVATE liblua_static)
    add_dependencies(test_dynamic_plugin_loader liblua_static)
endif()
add_test(NAME plugin_dynamic_loader COMMAND test_dynamic_plugin_loader)

add_executable(test_plugin_path
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_path.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginPath.cpp)
target_include_directories(test_plugin_path PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_path PRIVATE cxx_std_23)
target_compile_definitions(test_plugin_path PRIVATE DS_PLUGIN_HOST_STATIC)
add_test(NAME plugin_path COMMAND test_plugin_path)

add_executable(test_injector_bootstrap
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_injector_bootstrap.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/loader/bootstrap/InjectorBootstrap.cpp)
target_include_directories(test_injector_bootstrap PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_injector_bootstrap PRIVATE cxx_std_23)
# Bootstrap must not require DONTSTARVEINJECTOR_BUILD / Gum.
add_test(NAME injector_bootstrap COMMAND test_injector_bootstrap)
if (WIN32)
    target_link_libraries(test_injector_bootstrap PRIVATE shell32)
else()
    target_link_libraries(test_injector_bootstrap PRIVATE ${CMAKE_DL_LIBS})
endif()



add_executable(test_plugin_pending_updates
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_pending_updates.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginPendingUpdates.cpp)
target_include_directories(test_plugin_pending_updates PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_pending_updates PRIVATE cxx_std_23)
add_test(NAME plugin_pending_updates COMMAND test_plugin_pending_updates)

add_executable(test_plugin_pin_config
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_pin_config.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_manager/PluginPinConfig.cpp)
target_include_directories(test_plugin_pin_config PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_pin_config PRIVATE cxx_std_23)
find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(test_plugin_pin_config PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME plugin_pin_config COMMAND test_plugin_pin_config)

add_executable(test_plugin_proxy_url
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_proxy_url.cpp)
target_include_directories(test_plugin_proxy_url PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_proxy_url PRIVATE cxx_std_23)
add_test(NAME plugin_proxy_url COMMAND test_plugin_proxy_url)

add_executable(test_plugin_local_inventory
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_local_inventory.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_manager/PluginLocalInventory.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_manager/PluginPinConfig.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginPath.cpp)
target_include_directories(test_plugin_local_inventory PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_local_inventory PRIVATE cxx_std_23)
# Compile PluginPath into the test image (not via Injector import lib).
target_compile_definitions(test_plugin_local_inventory PRIVATE DS_PLUGIN_HOST_STATIC)
find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(test_plugin_local_inventory PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME plugin_local_inventory COMMAND test_plugin_local_inventory)

add_executable(test_plugin_hash_zip
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_hash_zip.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_manager/PluginHash.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_manager/PluginZipExtract.cpp)
target_include_directories(test_plugin_hash_zip PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_hash_zip PRIVATE cxx_std_23)
find_package(libzip CONFIG REQUIRED)
target_link_libraries(test_plugin_hash_zip PRIVATE libzip::zip)
add_test(NAME plugin_hash_zip COMMAND test_plugin_hash_zip)

add_executable(test_plugin_apply_offline
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_apply_offline.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_manager/PluginApply.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_manager/PluginHash.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_manager/PluginHttp.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_manager/PluginZipExtract.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_manager/PluginPinConfig.cpp)
target_include_directories(test_plugin_apply_offline PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_plugin_apply_offline PRIVATE cxx_std_23)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(libzip CONFIG REQUIRED)
target_link_libraries(test_plugin_apply_offline PRIVATE
    nlohmann_json::nlohmann_json
    libzip::zip)
if (WIN32)
    target_link_libraries(test_plugin_apply_offline PRIVATE winhttp)
endif()
add_test(NAME plugin_apply_offline COMMAND test_plugin_apply_offline)

# L0 lua_event bus — no hard-coded plugin DLL forwarder
add_executable(test_lua_event_bus
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_lua_event_bus.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/event/LuaEventBus.cpp)
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

# External plugin pack modinfo trust gate (sol2 + liblua_static, L0 cascade style)
add_executable(test_plugin_pack_modinfo
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_pack_modinfo.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginPackModinfo.cpp)
target_include_directories(test_plugin_pack_modinfo PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector
    ${SOL2_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/src/lua51original/src
    ${CMAKE_BINARY_DIR}/src/lua51original)
target_compile_features(test_plugin_pack_modinfo PRIVATE cxx_std_23)
target_compile_definitions(test_plugin_pack_modinfo PRIVATE DS_PLUGIN_HOST_STATIC)
if (TARGET liblua_static)
    target_link_libraries(test_plugin_pack_modinfo PRIVATE liblua_static)
    add_dependencies(test_plugin_pack_modinfo liblua_static)
else()
    message(FATAL_ERROR "liblua_static required for test_plugin_pack_modinfo")
endif()
add_test(NAME plugin_pack_modinfo COMMAND test_plugin_pack_modinfo)

add_executable(test_external_plugin_discovery
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_external_plugin_discovery.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/ExternalPluginDiscovery.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/EnabledDstMods.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginPackModinfo.cpp)
target_include_directories(test_external_plugin_discovery PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector
    ${SOL2_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/src/lua51original/src
    ${CMAKE_BINARY_DIR}/src/lua51original)
target_compile_features(test_external_plugin_discovery PRIVATE cxx_std_23)
target_compile_definitions(test_external_plugin_discovery PRIVATE DS_PLUGIN_HOST_STATIC)
if (TARGET liblua_static)
    target_link_libraries(test_external_plugin_discovery PRIVATE liblua_static)
    add_dependencies(test_external_plugin_discovery liblua_static)
endif()
add_test(NAME external_plugin_discovery COMMAND test_external_plugin_discovery)

# Enabled DST mod enumeration (modoverrides parse + root resolve)
add_executable(test_enabled_dst_mods
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_enabled_dst_mods.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/EnabledDstMods.cpp)
target_include_directories(test_enabled_dst_mods PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector
    ${SOL2_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/src/lua51original/src
    ${CMAKE_BINARY_DIR}/src/lua51original)
target_compile_features(test_enabled_dst_mods PRIVATE cxx_std_23)
target_compile_definitions(test_enabled_dst_mods PRIVATE DS_PLUGIN_HOST_STATIC)
if (TARGET liblua_static)
    target_link_libraries(test_enabled_dst_mods PRIVATE liblua_static)
    add_dependencies(test_enabled_dst_mods liblua_static)
else()
    message(FATAL_ERROR "liblua_static required for test_enabled_dst_mods")
endif()
add_test(NAME enabled_dst_mods COMMAND test_enabled_dst_mods)

# External discovery trust gate (mock load_fn; no real LoadLibrary)
add_executable(test_external_discover_gate
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_external_discover_gate.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/ExternalPluginDiscovery.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/EnabledDstMods.cpp
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/core/PluginPackModinfo.cpp
    ${PLUGIN_HOST_SOURCES})
target_include_directories(test_external_discover_gate PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector
    ${SOL2_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/src/lua51original/src
    ${CMAKE_BINARY_DIR}/src/lua51original)
target_compile_features(test_external_discover_gate PRIVATE cxx_std_23)
target_compile_definitions(test_external_discover_gate PRIVATE DS_PLUGIN_HOST_STATIC)
if (TARGET liblua_static)
    target_link_libraries(test_external_discover_gate PRIVATE liblua_static)
    add_dependencies(test_external_discover_gate liblua_static)
else()
    message(FATAL_ERROR "liblua_static required for test_external_discover_gate")
endif()
add_test(NAME external_discover_gate COMMAND test_external_discover_gate)

add_test(
    NAME plugin_discover_external
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/run_discover_external.py
)
set_tests_properties(plugin_discover_external PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_test(
    NAME plugin_host_lua
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/run_lua_host.py
)
set_tests_properties(plugin_host_lua PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_test(
    NAME plugin_package_load
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/run_package_load.py
)
set_tests_properties(plugin_package_load PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_test(
    NAME plugin_option_bake
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/run_bake_plugin_options.py
)
set_tests_properties(plugin_option_bake PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_test(
    NAME plugin_option_bake_check
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/run_bake_check.py
)
set_tests_properties(plugin_option_bake_check PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_test(
    NAME plugin_trunk_surface
    COMMAND ${PYTHON_EXECUTABLE_NAME}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugin/check_trunk_surface.py
        ${CMAKE_SOURCE_DIR})
set_tests_properties(plugin_trunk_surface PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_test(
    NAME plugin_package_identity
    COMMAND ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/plugin/test_plugin_package_identity.py)
set_tests_properties(plugin_package_identity PROPERTIES
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

# Ensure generated modinfo.hpp exists before compiling ConfigSchema.cpp.
foreach(_ds_cfg_tgt IN LISTS DS_CONFIG_SCHEMA_TARGETS)
    if (TARGET ${_ds_cfg_tgt})
        add_dependencies(${_ds_cfg_tgt} create_modinfo_hpp)
    endif()
endforeach()

if (WIN32)
  add_executable(test_function_ranges
      ${CMAKE_CURRENT_SOURCE_DIR}/function_relocation/test_function_ranges.cpp)
  target_include_directories(test_function_ranges PRIVATE
      ${FUNCTION_RELOCATION_INCLUDE_DIR}
      ${FRIDA_GUM_INCLUDE_DIR})
  target_compile_features(test_function_ranges PRIVATE cxx_std_23)
  # Prefer static so the test does not delay-load Injector for gum.
  # Static reloc TUs pull frida-gum via headers; tools/tests must link gum.
  target_link_libraries(test_function_ranges PRIVATE function_relocation_static Frida::Gum)
  if (DEFINED FRIDA_GUM_RUNTIME)
    add_custom_command(TARGET test_function_ranges POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${FRIDA_GUM_RUNTIME}"
          "$<TARGET_FILE_DIR:test_function_ranges>"
      VERBATIM)
  endif()
  add_test(NAME function_ranges COMMAND test_function_ranges)

  add_executable(test_nucleus_adapter
      ${CMAKE_CURRENT_SOURCE_DIR}/function_relocation/test_nucleus_adapter.cpp)
  target_include_directories(test_nucleus_adapter PRIVATE
      ${FUNCTION_RELOCATION_INCLUDE_DIR}
      ${FRIDA_GUM_INCLUDE_DIR})
  target_compile_features(test_nucleus_adapter PRIVATE cxx_std_23)
  # Static reloc: tools/tests link frida-gum directly (no Injector delay-load).
  target_link_libraries(test_nucleus_adapter PRIVATE function_relocation_static ${FRIDA_GUM_LIBRARIES})
  add_test(NAME nucleus_adapter COMMAND test_nucleus_adapter)
  set_tests_properties(nucleus_adapter PROPERTIES
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

# Soft-match accept policy primitives (plan function-relocation-match-v2 todo 1).
# Header-only: depends only on MatchPolicy.hpp + the C++23 standard library, so
# the test is portable across all platforms that build function_relocation.
add_executable(test_match_accept_policy
    ${CMAKE_CURRENT_SOURCE_DIR}/function_relocation/test_match_accept_policy.cpp)
target_include_directories(test_match_accept_policy PRIVATE
    ${FUNCTION_RELOCATION_INCLUDE_DIR})
target_compile_features(test_match_accept_policy PRIVATE cxx_std_23)
add_test(NAME match_accept_policy COMMAND test_match_accept_policy)

# Micro-window pattern generator + multi-hit same-entry resolver (plan todo 2).
# Header-only: depends on MatchPolicy.hpp + MicroWindow.hpp + the C++23 stdlib.
add_executable(test_micro_windows
    ${CMAKE_CURRENT_SOURCE_DIR}/function_relocation/test_micro_windows.cpp)
target_include_directories(test_micro_windows PRIVATE
    ${FUNCTION_RELOCATION_INCLUDE_DIR})
target_compile_features(test_micro_windows PRIVATE cxx_std_23)
add_test(NAME micro_windows COMMAND test_micro_windows)

# Soft multi-feature scoring + twin fail-closed (plan todo 3).
# Header-only: depends on MatchPolicy.hpp + MicroWindow.hpp + the C++23 stdlib.
add_executable(test_soft_score
    ${CMAKE_CURRENT_SOURCE_DIR}/function_relocation/test_soft_score.cpp)
target_include_directories(test_soft_score PRIVATE
    ${FUNCTION_RELOCATION_INCLUDE_DIR})
target_compile_features(test_soft_score PRIVATE cxx_std_23)
add_test(NAME soft_score COMMAND test_soft_score)

# Virtual flatten1 + call-edit StillCall|Inlined|Missing + dual-channel agree
# (plan function-relocation-match-v2 todo 4). Header-only.
add_executable(test_virtual_flatten
    ${CMAKE_CURRENT_SOURCE_DIR}/function_relocation/test_virtual_flatten.cpp)
target_include_directories(test_virtual_flatten PRIVATE
    ${FUNCTION_RELOCATION_INCLUDE_DIR})
target_compile_features(test_virtual_flatten PRIVATE cxx_std_23)
add_test(NAME virtual_flatten COMMAND test_virtual_flatten)

# limit_signature + knowns isolation + fix_func_address_by_signature
# orchestration (plan function-relocation-match-v2 todo 5). Header-only.
add_executable(test_orchestration
    ${CMAKE_CURRENT_SOURCE_DIR}/function_relocation/test_orchestration.cpp)
target_include_directories(test_orchestration PRIVATE
    ${FUNCTION_RELOCATION_INCLUDE_DIR})
target_compile_features(test_orchestration PRIVATE cxx_std_23)
add_test(NAME orchestration COMMAND test_orchestration)

# SignatureInfo schema freeze (plan function-relocation-match-v2 todo 7).
# Header-only: structured binding fails to compile if a fourth field is added.
add_executable(test_schema_freeze
    ${CMAKE_CURRENT_SOURCE_DIR}/function_relocation/test_schema_freeze.cpp)
target_include_directories(test_schema_freeze PRIVATE
    ${FUNCTION_RELOCATION_INCLUDE_DIR})
target_compile_features(test_schema_freeze PRIVATE cxx_std_23)
add_test(NAME schema_freeze COMMAND test_schema_freeze)

set_tests_properties(
    match_accept_policy
    micro_windows
    soft_score
    virtual_flatten
    orchestration
    schema_freeze
    PROPERTIES LABELS match_v2)
