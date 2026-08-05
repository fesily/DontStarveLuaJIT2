# HWBuffer pool (Path A M-R2).
ds_add_dynamic_plugin(plugin_render_vbpool
    plugin_render_vbpool.cpp
    GameRenderHook.cpp)
target_link_libraries(plugin_render_vbpool PRIVATE
    spdlog::spdlog
    function_relocation)
target_link_options(plugin_render_vbpool PRIVATE
    "/NODEFAULTLIB:frida-gum.lib")
target_compile_definitions(plugin_render_vbpool PRIVATE
    GUM_STATIC=1
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_render_vbpool PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${PROJECT_SOURCE_DIR}/3rd/angle/win64/include
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(plugin_render_vbpool PRIVATE
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})

target_include_directories(plugin_render_vbpool PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io
    ${LUAJIT_INCLUDE_DIR})
