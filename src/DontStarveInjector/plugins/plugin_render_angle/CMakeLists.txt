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

# release_only ANGLE is built with /MD + _ITERATOR_DEBUG_LEVEL=0. Linking that
# into a /MDd Debug plugin fails LNK2038. When debug ANGLE libs are absent,
# compile/link this plugin with the release MSVC runtime for all configs.
if (MSVC AND DEFINED UNOFFICIAL_ANGLE_HAS_DEBUG_LIBS AND NOT UNOFFICIAL_ANGLE_HAS_DEBUG_LIBS)
    set_property(TARGET plugin_render_angle PROPERTY MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
    target_compile_definitions(plugin_render_angle PRIVATE _ITERATOR_DEBUG_LEVEL=0)
    message(STATUS "plugin_render_angle: release_only ANGLE — using /MD for all configs")
endif()
