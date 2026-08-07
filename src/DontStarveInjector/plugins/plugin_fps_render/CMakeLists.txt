# fps.render — TargetRenderFPS / frame budget (Win Gum signatures).
ds_add_dynamic_plugin(plugin_fps_render
    plugin_fps_render.cpp
    FpsRenderApi.cpp)
target_link_libraries(plugin_fps_render PRIVATE
    spdlog::spdlog
    function_relocation)
target_compile_definitions(plugin_fps_render PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_fps_render PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(plugin_fps_render PRIVATE
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})

target_include_directories(plugin_fps_render PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io
    ${LUAJIT_INCLUDE_DIR})
