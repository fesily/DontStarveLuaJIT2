# network.tick — DS_LUAJIT_replace_network_tick only (no rpc/sim coupling).
ds_add_dynamic_plugin(plugin_network_tick
    plugin_network_tick.cpp
    NetworkTickApi.cpp)
target_link_libraries(plugin_network_tick PRIVATE
    spdlog::spdlog
    function_relocation)
target_compile_definitions(plugin_network_tick PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_network_tick PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(plugin_network_tick PRIVATE
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})

target_include_directories(plugin_network_tick PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io
    ${LUAJIT_INCLUDE_DIR})
