# debug.jitterprobe — temporary client prediction-OFF movement jitter probes.
ds_add_dynamic_plugin(plugin_debug_jitterprobe
    plugin_debug_jitterprobe.cpp
    JitterProbeHooks.cpp)
target_link_libraries(plugin_debug_jitterprobe PRIVATE
    spdlog::spdlog
    function_relocation)
target_compile_definitions(plugin_debug_jitterprobe PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_debug_jitterprobe PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io)
