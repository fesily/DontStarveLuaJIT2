# Outbound net simulation (Path A network.sim). Lazy hook on enable.
ds_add_dynamic_plugin(plugin_network_sim
    plugin_network_sim.cpp
    GameNetworkSim.cpp)
target_link_libraries(plugin_network_sim PRIVATE
    spdlog::spdlog
    function_relocation)
target_compile_definitions(plugin_network_sim PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_network_sim PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(plugin_network_sim PRIVATE
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})

target_include_directories(plugin_network_sim PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io
    ${LUAJIT_INCLUDE_DIR})
