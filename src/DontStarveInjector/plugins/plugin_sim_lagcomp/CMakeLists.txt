# Lag compensation entity snapshot (Path A sim.lagcomp). Win x64 only.
ds_add_dynamic_plugin(plugin_sim_lagcomp
    plugin_sim_lagcomp.cpp
    GameSimHook.cpp)
target_link_libraries(plugin_sim_lagcomp PRIVATE
    spdlog::spdlog)
# GameSimHook includes GameLua.hpp → frida-gum.h #pragma comment; Gum via Injector only.
target_link_options(plugin_sim_lagcomp PRIVATE
    "/NODEFAULTLIB:frida-gum.lib")
target_compile_definitions(plugin_sim_lagcomp PRIVATE
    GUM_STATIC=1
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_sim_lagcomp PRIVATE
    ${LUAJIT_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(plugin_sim_lagcomp PRIVATE
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})

target_include_directories(plugin_sim_lagcomp PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io
    ${LUAJIT_INCLUDE_DIR})
