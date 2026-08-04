# Outbound net simulation (Path A network.sim). Lazy hook on enable.
ds_add_dynamic_plugin(plugin_network_sim
    plugin_network_sim.cpp
    GameNetworkSim.cpp)
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
    ${CMAKE_CURRENT_SOURCE_DIR})
