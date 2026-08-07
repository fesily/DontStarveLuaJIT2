# ANGLE + OpenGL (Path A M-R1).
#
# When unofficial-angle has no Debug libs (release_only), this plugin is forced
# to /MD for every config. Loading that DLL into a Debug (/MDd) process that
# already hosts Injector + plugins on MSVCP140D/ucrtbased mixes CRTs and aborts
# ("Runtime to terminate it in an unusual way").
#
# Debug is still *buildable* for link experiments, but Debug `cmake --install`
# removes plugin_render_angle.dll from Mod/plugins so a Debug package stays pure.
ds_add_dynamic_plugin(plugin_render_angle
    plugin_render_angle.cpp
    GameOpenGl.cpp)
target_link_libraries(plugin_render_angle PRIVATE
    unofficial::angle::libGLESv2
    unofficial::angle::libEGL
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
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io)

if (MSVC AND DEFINED UNOFFICIAL_ANGLE_HAS_DEBUG_LIBS AND NOT UNOFFICIAL_ANGLE_HAS_DEBUG_LIBS)
    set_property(TARGET plugin_render_angle PROPERTY MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
    target_compile_definitions(plugin_render_angle PRIVATE _ITERATOR_DEBUG_LEVEL=0)
    target_compile_options(plugin_render_angle PRIVATE /utf-8)
    # After packaging plugins, drop the hybrid /MD angle DLL from Debug installs.
    install(CODE [[
      if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
        set(_ds_angle "${CMAKE_INSTALL_PREFIX}/plugins/plugin_render_angle.dll")
        if(EXISTS "${_ds_angle}")
          file(REMOVE "${_ds_angle}")
          message(STATUS "plugin_render_angle: removed from Debug package (release_only ANGLE is /MD-only; mixed CRT unsafe)")
        endif()
      endif()
    ]] COMPONENT plugins)
    message(STATUS "plugin_render_angle: release_only ANGLE — /MD; Debug install removes from Mod/plugins")
endif()
