# ANGLE + OpenGL (Path A M-R1).
#
# Code depends on *static* ANGLE (IAT rebind to static egl/gles symbols in this
# DLL). Do not convert ANGLE to shared without a dedicated plan — GameOpenGl
# rebinds main-module imports to symbols resolved inside this image.
#
# ANGLE stage is release_only: static libs built with /MD + IDL=0.
# Pure /MDd cannot absorb those objects (LNK2038). Debug *config* keeps /Od /Zi
# but uses /MD + IDL=0 and links absolute *Release* import/static libs so vcpkg
# Debug generator expressions (spdlogd/fmtd/zlibd via ZLIB::ZLIB INTERFACE on
# unofficial::angle::*) never enter the link line.

ds_add_dynamic_plugin(plugin_render_angle
    plugin_render_angle.cpp
    GameOpenGl.cpp)

target_compile_definitions(plugin_render_angle PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL
    KHRONOS_STATIC)

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

if (MSVC AND DEFINED UNOFFICIAL_ANGLE_HAS_DEBUG_LIBS AND NOT UNOFFICIAL_ANGLE_HAS_DEBUG_LIBS)
    set_property(TARGET plugin_render_angle PROPERTY MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
    target_compile_definitions(plugin_render_angle PRIVATE
        $<$<CONFIG:Debug>:_ITERATOR_DEBUG_LEVEL=0>)
    target_compile_options(plugin_render_angle PRIVATE /utf-8)

    set(_ds_angle_lib_dir "${PROJECT_SOURCE_DIR}/3rd/angle/win64/lib")
    if (DEFINED UNOFFICIAL_ANGLE_GLESv2_LIBRARY_RELEASE AND EXISTS "${UNOFFICIAL_ANGLE_GLESv2_LIBRARY_RELEASE}")
        get_filename_component(_ds_angle_lib_dir "${UNOFFICIAL_ANGLE_GLESv2_LIBRARY_RELEASE}" DIRECTORY)
    endif()

    set(_ds_vcpkg_rel_lib "")
    foreach(_cand IN ITEMS
            "${CMAKE_BINARY_DIR}/vcpkg_installed/x64-windows-custom/lib"
            "${CMAKE_SOURCE_DIR}/builds/ninja-multi-vcpkg/vcpkg_installed/x64-windows-custom/lib")
        if (EXISTS "${_cand}/spdlog.lib" AND EXISTS "${_cand}/fmt.lib" AND EXISTS "${_cand}/zlib.lib")
            set(_ds_vcpkg_rel_lib "${_cand}")
            break()
        endif()
    endforeach()
    if (_ds_vcpkg_rel_lib STREQUAL "")
        message(FATAL_ERROR
            "plugin_render_angle: release spdlog/fmt/zlib.lib not found "
            "(needed for Debug /MD + static release ANGLE)")
    endif()

    # Debug: absolute release static ANGLE + release vcpkg libs (no imported INTERFACE).
    # Non-Debug: normal imported targets + spdlog.
    target_link_libraries(plugin_render_angle PRIVATE
        $<$<CONFIG:Debug>:${_ds_angle_lib_dir}/libGLESv2.lib>
        $<$<CONFIG:Debug>:${_ds_angle_lib_dir}/libEGL.lib>
        $<$<CONFIG:Debug>:${_ds_angle_lib_dir}/ANGLE.lib>
        $<$<CONFIG:Debug>:${_ds_angle_lib_dir}/SPIRV-Tools.lib>
        $<$<CONFIG:Debug>:${_ds_angle_lib_dir}/vulkan-1.lib>
        $<$<CONFIG:Debug>:${_ds_vcpkg_rel_lib}/spdlog.lib>
        $<$<CONFIG:Debug>:${_ds_vcpkg_rel_lib}/fmt.lib>
        $<$<CONFIG:Debug>:${_ds_vcpkg_rel_lib}/zlib.lib>
        $<$<CONFIG:Debug>:dxguid>
        $<$<CONFIG:Debug>:dxgi>
        $<$<CONFIG:Debug>:synchronization>
        $<$<CONFIG:Debug>:d3d9>
        $<$<NOT:$<CONFIG:Debug>>:unofficial::angle::libGLESv2>
        $<$<NOT:$<CONFIG:Debug>>:unofficial::angle::libEGL>
        $<$<NOT:$<CONFIG:Debug>>:spdlog::spdlog>
    )

    message(STATUS
        "plugin_render_angle: static release_only ANGLE; Debug=/MD+IDL0 + absolute "
        "release ANGLE/spdlog/fmt/zlib (IAT static rebind; no *d import libs)")
else()
    target_link_libraries(plugin_render_angle PRIVATE
        unofficial::angle::libGLESv2
        unofficial::angle::libEGL
        spdlog::spdlog)
endif()
