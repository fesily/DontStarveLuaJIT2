# network.stats: per-client RTT (native hook + Lua exports). Windows/Linux x64.
ds_add_dynamic_plugin(plugin_network_stats
    plugin_network_stats.cpp
    ClientPingDecode.cpp
    ClientPingHook.cpp
    ClientPingApi.cpp)
target_link_libraries(plugin_network_stats PRIVATE
    spdlog::spdlog
    function_relocation)
target_compile_definitions(plugin_network_stats PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_network_stats PRIVATE
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${DONTSTARVEINJECTOR_ROOT})
