# debug.profiler — Tracy / FullGC / FrameGC. AlwaysOn native; Lua AfterModMain gates work.
ds_add_dynamic_plugin(plugin_debug_profiler
    plugin_debug_profiler.cpp
    ProfilerApi.cpp
    FullGcPolicy.cpp)
target_link_libraries(plugin_debug_profiler PRIVATE
    spdlog::spdlog
    function_relocation
    Tracy::TracyClient)
target_compile_definitions(plugin_debug_profiler PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL
    DS_INJECTOR_CONSUMER=1)
target_include_directories(plugin_debug_profiler PRIVATE
    ${DONTSTARVEINJECTOR_ROOT}
    ${DONTSTARVEINJECTOR_ROOT}/plugins/plugin_core_vm
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${LUAJIT_INCLUDE_DIR})

target_include_directories(plugin_debug_profiler PRIVATE
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})
