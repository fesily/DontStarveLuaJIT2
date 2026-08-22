# RPC4 / entity network extension (Path A M-N1). Gum via Frida::Gum shared.
ds_add_dynamic_plugin(plugin_network_rpc
    plugin_network_rpc.cpp
    GameNetwork.cpp)
target_link_libraries(plugin_network_rpc PRIVATE
    spdlog::spdlog
    SLikeNet
    function_relocation)
target_compile_definitions(plugin_network_rpc PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_network_rpc PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${PLF_HIVE_INCLUDE_DIRS}
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(plugin_network_rpc PRIVATE
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})

target_include_directories(plugin_network_rpc PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io
    ${LUAJIT_INCLUDE_DIR})
