# Finds a prebuilt ANGLE package staged under 3rd/angle by tools/setup_angle.py.
# Provides the same imported targets as the vcpkg unofficial-angle package:
#   unofficial::angle::libEGL
#   unofficial::angle::libGLESv2
#   unofficial::angle::libANGLE

if(TARGET unofficial::angle::libEGL AND TARGET unofficial::angle::libGLESv2)
    set(unofficial-angle_FOUND TRUE)
    return()
endif()

if(NOT WIN32)
    set(unofficial-angle_FOUND FALSE)
    if(unofficial-angle_FIND_REQUIRED)
        message(FATAL_ERROR "unofficial-angle is only available on Windows")
    endif()
    return()
endif()

set(_ANGLE_ROOT "${PROJECT_SOURCE_DIR}/3rd/angle/win64")
if(DEFINED ANGLE_ROOT AND NOT "${ANGLE_ROOT}" STREQUAL "")
    set(_ANGLE_ROOT "${ANGLE_ROOT}")
endif()

find_path(UNOFFICIAL_ANGLE_INCLUDE_DIR
    NAMES EGL/egl.h GLES2/gl2.h
    PATHS "${_ANGLE_ROOT}/include"
    NO_DEFAULT_PATH
)

find_library(UNOFFICIAL_ANGLE_EGL_LIBRARY_RELEASE
    NAMES libEGL
    PATHS "${_ANGLE_ROOT}/lib"
    NO_DEFAULT_PATH
)
find_library(UNOFFICIAL_ANGLE_GLESv2_LIBRARY_RELEASE
    NAMES libGLESv2
    PATHS "${_ANGLE_ROOT}/lib"
    NO_DEFAULT_PATH
)
find_library(UNOFFICIAL_ANGLE_ANGLE_LIBRARY_RELEASE
    NAMES ANGLE
    PATHS "${_ANGLE_ROOT}/lib"
    NO_DEFAULT_PATH
)
find_library(UNOFFICIAL_ANGLE_SPIRV_TOOLS_LIBRARY_RELEASE
    NAMES SPIRV-Tools
    PATHS "${_ANGLE_ROOT}/lib"
    NO_DEFAULT_PATH
)
find_library(UNOFFICIAL_ANGLE_VULKAN_LIBRARY_RELEASE
    NAMES vulkan-1
    PATHS "${_ANGLE_ROOT}/lib"
    NO_DEFAULT_PATH
)

find_library(UNOFFICIAL_ANGLE_EGL_LIBRARY_DEBUG
    NAMES libEGL
    PATHS "${_ANGLE_ROOT}/debug/lib"
    NO_DEFAULT_PATH
)
find_library(UNOFFICIAL_ANGLE_GLESv2_LIBRARY_DEBUG
    NAMES libGLESv2
    PATHS "${_ANGLE_ROOT}/debug/lib"
    NO_DEFAULT_PATH
)
find_library(UNOFFICIAL_ANGLE_ANGLE_LIBRARY_DEBUG
    NAMES ANGLE
    PATHS "${_ANGLE_ROOT}/debug/lib"
    NO_DEFAULT_PATH
)
find_library(UNOFFICIAL_ANGLE_SPIRV_TOOLS_LIBRARY_DEBUG
    NAMES SPIRV-Tools
    PATHS "${_ANGLE_ROOT}/debug/lib"
    NO_DEFAULT_PATH
)
find_library(UNOFFICIAL_ANGLE_VULKAN_LIBRARY_DEBUG
    NAMES vulkan-1
    PATHS "${_ANGLE_ROOT}/debug/lib"
    NO_DEFAULT_PATH
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(unofficial-angle
    REQUIRED_VARS
        UNOFFICIAL_ANGLE_INCLUDE_DIR
        UNOFFICIAL_ANGLE_EGL_LIBRARY_RELEASE
        UNOFFICIAL_ANGLE_GLESv2_LIBRARY_RELEASE
        UNOFFICIAL_ANGLE_ANGLE_LIBRARY_RELEASE
        UNOFFICIAL_ANGLE_SPIRV_TOOLS_LIBRARY_RELEASE
        UNOFFICIAL_ANGLE_VULKAN_LIBRARY_RELEASE
)

if(NOT unofficial-angle_FOUND)
    if(unofficial-angle_FIND_REQUIRED)
        message(FATAL_ERROR
            "unofficial-angle not found under ${_ANGLE_ROOT}.\n"
            "Run: python tools/setup_angle.py\n"
            "Or stage from an existing install:\n"
            "  python tools/setup_angle.py --from-prefix <vcpkg_installed/x64-windows-custom>"
        )
    endif()
    return()
endif()

if(NOT TARGET ZLIB::ZLIB)
    find_package(ZLIB REQUIRED)
endif()

if(NOT TARGET unofficial::angle::libANGLE)
    add_library(unofficial::angle::libANGLE STATIC IMPORTED)
    set_target_properties(unofficial::angle::libANGLE PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${UNOFFICIAL_ANGLE_INCLUDE_DIR}"
        INTERFACE_COMPILE_DEFINITIONS
            "ANGLE_ENABLE_ESSL;ANGLE_ENABLE_GLSL;ANGLE_CAPTURE_ENABLED=0;ANGLE_VK_MOCK_ICD_JSON=\"VkICD_mock_icd.json\";ANGLE_VK_LAYERS_DIR=\".\";ANGLE_PROGRAM_LINK_VALIDATE_UNIFORM_PRECISION=0;VK_USE_PLATFORM_WIN32_KHR;GL_APICALL=;GL_API=;NOMINMAX;ANGLE_ENABLE_D3D11;ANGLE_ENABLE_HLSL;ANGLE_PRELOADED_D3DCOMPILER_MODULE_NAMES={ \"d3dcompiler_47.dll\", \"d3dcompiler_46.dll\", \"d3dcompiler_43.dll\" };ANGLE_ENABLE_D3D9;ANGLE_ENABLE_D3D11_COMPOSITOR_NATIVE_WINDOW;ANGLE_ENABLE_GLSL;ANGLE_ENABLE_OPENGL;ANGLE_ENABLE_GL_DESKTOP_BACKEND;ANGLE_ENABLE_VULKAN;ANGLE_ENABLE_CRC_FOR_PIPELINE_CACHE;ANGLE_USE_CUSTOM_VULKAN_OUTSIDE_RENDER_PASS_CMD_BUFFERS=1;ANGLE_USE_CUSTOM_VULKAN_RENDER_PASS_CMD_BUFFERS=1;KHRONOS_STATIC"
        IMPORTED_LOCATION_RELEASE "${UNOFFICIAL_ANGLE_ANGLE_LIBRARY_RELEASE}"
        IMPORTED_CONFIGURATIONS "RELEASE"
    )
    if(UNOFFICIAL_ANGLE_ANGLE_LIBRARY_DEBUG)
        set_property(TARGET unofficial::angle::libANGLE APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
        set_target_properties(unofficial::angle::libANGLE PROPERTIES
            IMPORTED_LOCATION_DEBUG "${UNOFFICIAL_ANGLE_ANGLE_LIBRARY_DEBUG}"
        )
    else()
        set_target_properties(unofficial::angle::libANGLE PROPERTIES
            MAP_IMPORTED_CONFIG_DEBUG RELEASE
        )
    endif()
    set_target_properties(unofficial::angle::libANGLE PROPERTIES
        MAP_IMPORTED_CONFIG_RELWITHDEBINFO RELEASE
        MAP_IMPORTED_CONFIG_MINSIZEREL RELEASE
    )

    set(_angle_vulkan_lib "${UNOFFICIAL_ANGLE_VULKAN_LIBRARY_RELEASE}")
    if(UNOFFICIAL_ANGLE_VULKAN_LIBRARY_DEBUG)
        set(_angle_vulkan_lib
            "$<$<CONFIG:Debug>:${UNOFFICIAL_ANGLE_VULKAN_LIBRARY_DEBUG}>$<$<NOT:$<CONFIG:Debug>>:${UNOFFICIAL_ANGLE_VULKAN_LIBRARY_RELEASE}>"
        )
    endif()
    set(_angle_spirv_lib "${UNOFFICIAL_ANGLE_SPIRV_TOOLS_LIBRARY_RELEASE}")
    if(UNOFFICIAL_ANGLE_SPIRV_TOOLS_LIBRARY_DEBUG)
        set(_angle_spirv_lib
            "$<$<CONFIG:Debug>:${UNOFFICIAL_ANGLE_SPIRV_TOOLS_LIBRARY_DEBUG}>$<$<NOT:$<CONFIG:Debug>>:${UNOFFICIAL_ANGLE_SPIRV_TOOLS_LIBRARY_RELEASE}>"
        )
    endif()

    set(_angle_vma_include "${_ANGLE_ROOT}/include/vma")
    target_link_libraries(unofficial::angle::libANGLE INTERFACE
        $<LINK_ONLY:ZLIB::ZLIB>
        $<LINK_ONLY:${_angle_vulkan_lib}>
        $<LINK_ONLY:${_angle_spirv_lib}>
    )
    if(EXISTS "${_angle_vma_include}")
        target_include_directories(unofficial::angle::libANGLE INTERFACE "${_angle_vma_include}")
    endif()
endif()

if(NOT TARGET unofficial::angle::libGLESv2)
    add_library(unofficial::angle::libGLESv2 STATIC IMPORTED)
    set_target_properties(unofficial::angle::libGLESv2 PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${UNOFFICIAL_ANGLE_INCLUDE_DIR}"
        INTERFACE_COMPILE_DEFINITIONS "KHRONOS_STATIC"
        INTERFACE_LINK_LIBRARIES
            "$<LINK_ONLY:unofficial::angle::libANGLE>;$<LINK_ONLY:dxguid>;$<LINK_ONLY:dxgi>;$<LINK_ONLY:synchronization>;$<LINK_ONLY:d3d9>"
        IMPORTED_LOCATION_RELEASE "${UNOFFICIAL_ANGLE_GLESv2_LIBRARY_RELEASE}"
        IMPORTED_CONFIGURATIONS "RELEASE"
        MAP_IMPORTED_CONFIG_RELWITHDEBINFO RELEASE
        MAP_IMPORTED_CONFIG_MINSIZEREL RELEASE
    )
    if(UNOFFICIAL_ANGLE_GLESv2_LIBRARY_DEBUG)
        set_property(TARGET unofficial::angle::libGLESv2 APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
        set_target_properties(unofficial::angle::libGLESv2 PROPERTIES
            IMPORTED_LOCATION_DEBUG "${UNOFFICIAL_ANGLE_GLESv2_LIBRARY_DEBUG}"
        )
    else()
        set_target_properties(unofficial::angle::libGLESv2 PROPERTIES
            MAP_IMPORTED_CONFIG_DEBUG RELEASE
        )
    endif()
endif()

if(NOT TARGET unofficial::angle::libEGL)
    add_library(unofficial::angle::libEGL STATIC IMPORTED)
    set_target_properties(unofficial::angle::libEGL PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${UNOFFICIAL_ANGLE_INCLUDE_DIR}"
        INTERFACE_COMPILE_DEFINITIONS "KHRONOS_STATIC"
        INTERFACE_LINK_LIBRARIES "$<LINK_ONLY:unofficial::angle::libGLESv2>"
        IMPORTED_LOCATION_RELEASE "${UNOFFICIAL_ANGLE_EGL_LIBRARY_RELEASE}"
        IMPORTED_CONFIGURATIONS "RELEASE"
        MAP_IMPORTED_CONFIG_RELWITHDEBINFO RELEASE
        MAP_IMPORTED_CONFIG_MINSIZEREL RELEASE
    )
    if(UNOFFICIAL_ANGLE_EGL_LIBRARY_DEBUG)
        set_property(TARGET unofficial::angle::libEGL APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
        set_target_properties(unofficial::angle::libEGL PROPERTIES
            IMPORTED_LOCATION_DEBUG "${UNOFFICIAL_ANGLE_EGL_LIBRARY_DEBUG}"
        )
    else()
        set_target_properties(unofficial::angle::libEGL PROPERTIES
            MAP_IMPORTED_CONFIG_DEBUG RELEASE
        )
    endif()
endif()

mark_as_advanced(
    UNOFFICIAL_ANGLE_INCLUDE_DIR
    UNOFFICIAL_ANGLE_EGL_LIBRARY_RELEASE
    UNOFFICIAL_ANGLE_GLESv2_LIBRARY_RELEASE
    UNOFFICIAL_ANGLE_ANGLE_LIBRARY_RELEASE
    UNOFFICIAL_ANGLE_SPIRV_TOOLS_LIBRARY_RELEASE
    UNOFFICIAL_ANGLE_VULKAN_LIBRARY_RELEASE
    UNOFFICIAL_ANGLE_EGL_LIBRARY_DEBUG
    UNOFFICIAL_ANGLE_GLESv2_LIBRARY_DEBUG
    UNOFFICIAL_ANGLE_ANGLE_LIBRARY_DEBUG
    UNOFFICIAL_ANGLE_SPIRV_TOOLS_LIBRARY_DEBUG
    UNOFFICIAL_ANGLE_VULKAN_LIBRARY_DEBUG
)
