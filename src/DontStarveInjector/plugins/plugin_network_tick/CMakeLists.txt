# network.tick — DS_LUAJIT_replace_network_tick only (no rpc/sim coupling).
ds_add_dynamic_plugin(plugin_network_tick
    plugin_network_tick.cpp
    NetworkTickApi.cpp)
target_link_libraries(plugin_network_tick PRIVATE
    spdlog::spdlog
    function_relocation)
target_link_options(plugin_network_tick PRIVATE
    "/NODEFAULTLIB:frida-gum.lib")
target_compile_definitions(plugin_network_tick PRIVATE
    GUM_STATIC=1
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_network_tick PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
