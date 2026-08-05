# ANGLE + OpenGL (Path A M-R1).
ds_add_dynamic_plugin(plugin_render_angle
    plugin_render_angle.cpp
    GameOpenGl.cpp)
target_link_libraries(plugin_render_angle PRIVATE
    unofficial::angle::libGLESv2
    unofficial::angle::libEGL
    spdlog::spdlog)
target_link_options(plugin_render_angle PRIVATE
    "/NODEFAULTLIB:frida-gum.lib")
target_compile_definitions(plugin_render_angle PRIVATE
    GUM_STATIC=1
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_render_angle PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${FRIDA_GUM_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(plugin_render_angle PRIVATE
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})

target_include_directories(plugin_render_angle PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io
    ${LUAJIT_INCLUDE_DIR})
