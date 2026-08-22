# ANGLE + OpenGL — shared libGLESv2/libEGL (see 2026-08-08-angle-shared-design.md)
# Headers-only ANGLE: runtime LoadLibrary/GetProcAddress from Mod/deps.
# Do not link unofficial::angle::libGLESv2/libEGL import libs (no load-time DLL dep).
ds_add_dynamic_plugin(plugin_render_angle
    plugin_render_angle.cpp
    GameOpenGl.cpp)

target_link_libraries(plugin_render_angle PRIVATE
    spdlog::spdlog)

target_compile_definitions(plugin_render_angle PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)

target_include_directories(plugin_render_angle PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${FRIDA_GUM_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io
    ${UNOFFICIAL_ANGLE_INCLUDE_DIR})

target_compile_options(plugin_render_angle PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/utf-8>)
