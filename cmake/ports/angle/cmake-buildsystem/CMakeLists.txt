cmake_minimum_required(VERSION 3.8)
project(angle CXX C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
include(WebKitCommon-minimal)

set(ANGLE_FRAMEWORK_HEADERS_DIR "${CMAKE_BINARY_DIR}/ANGLE/headers")

set(USE_ANGLE_EGL ON)
if (NOT WINDOWS_STORE AND NOT USE_METAL)
    set(USE_OPENGL ON)
endif()

if(MSVC)
    add_compile_options(/d2guard4 /Wv:18 /guard:cf /permissive /bigobj)
    add_link_options(/guard:cf)
endif()

option(ANGLE_ENABLE_TRACE "Enable ANGLE debug trace logging" OFF)
option(ANGLE_ENABLE_TRACE_EVENTS "Enable ANGLE trace event logging" OFF)
option(ANGLE_ALWAYS_LOG_INFO "Enable ANGLE INFO-level logging" OFF)
option(ANGLE_ENABLE_VULKAN_VALIDATION_LAYERS "Build ANGLE Vulkan validation layer support" OFF)
option(ANGLE_ENABLE_VULKAN_VALIDATION_LAYERS_BY_DEFAULT "Enable ANGLE Vulkan validation layers by default when available" OFF)
option(ANGLE_ENABLE_VULKAN_API_DUMP_LAYER "Build ANGLE Vulkan API dump layer support" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS}")
set(CMAKE_STATIC_LIBRARY_PREFIX "")
if(WIN32)
    set(CMAKE_SHARED_LIBRARY_PREFIX "")
endif()

if (WINDOWS_STORE)
    set(WINRT_DEFINES -DANGLE_ENABLE_WINDOWS_UWP -DWINAPI_FAMILY=WINAPI_FAMILY_PC_APP)
else()
    set(WINRT_DEFINES)
endif()
add_definitions(
    -D_CRT_SECURE_NO_DEPRECATE
    -D_SCL_SECURE_NO_WARNINGS
    -DGL_SILENCE_DEPRECATION
    -D_HAS_EXCEPTIONS=0
    -DNOMINMAX
    -DANGLE_STANDALONE_BUILD
    ${WINRT_DEFINES}
)
add_compile_options("$<$<CONFIG:DEBUG>:-DANGLE_ENABLE_DEBUG_ANNOTATIONS>")
if(WIN32)
    add_definitions(-DANGLE_IS_WIN)
endif()
if(LINUX)
    add_definitions(-DANGLE_IS_LINUX)
endif()
if(ANGLE_IS_64_BIT_CPU)
    add_definitions(-DANGLE_IS_64_BIT_CPU)
elseif(ANGLE_IS_32_BIT_CPU)
    add_definitions(-DANGLE_IS_32_BIT_CPU)
endif()
if(ANGLE_USE_D3D11_COMPOSITOR_NATIVE_WINDOW)
    if(NOT WIN32)
        message(FATAL_ERROR "ANGLE_USE_D3D11_COMPOSITOR_NATIVE_WINDOW is set, but is only supported on Windows")
    endif()
    set(angle_enable_d3d11_compositor_native_window TRUE)
endif()
if(NOT BUILD_SHARED_LIBS)
    add_definitions(
        -DANGLE_EXPORT=
        -DANGLE_STATIC=1
        -DANGLE_UTIL_EXPORT=
        -DEGLAPI=
        -DGL_APICALL=
        -DGL_API=
    )
endif()

find_package(ZLIB REQUIRED)
if (USE_VULKAN)
    find_package(Vulkan REQUIRED)
    find_package(SPIRV-Tools CONFIG REQUIRED)
    find_package(VulkanMemoryAllocator CONFIG REQUIRED)
endif()

##################################################

# Derived from: https://github.com/WebKit/WebKit/blob/92dbcacf4c3e3a8fc6eea68e7022ca59401749e0/Source/ThirdParty/ANGLE/CMakeLists.txt
# With modifications for vcpkg port (marked with "VCPKG EDIT:" comments)

set_property(DIRECTORY . PROPERTY FOLDER "ANGLE")

# VCPKG EDIT: modified block
if (APPLE)
    set(is_apple TRUE)
    if (IOS)
        set(is_ios TRUE)
        if (USE_OPENGL)
            set(angle_enable_eagl TRUE)
        endif()
    else()
        set(is_mac TRUE)
    endif()
    if (USE_OPENGL AND NOT angle_enable_eagl)
        set(angle_enable_cgl TRUE)
    endif()
elseif (WIN32)
    set(is_win TRUE)
    if (NOT WINDOWS_STORE)
        set(angle_is_winuwp FALSE)
    else()
        set(angle_is_winuwp TRUE)
        set(target_os "winuwp")
    endif()
    if (NOT angle_is_winuwp)
        set(angle_enable_d3d9 TRUE)
    endif()
    set(angle_enable_d3d11 TRUE)
elseif (UNIX)
    set(is_linux TRUE)
endif ()
# VCPKG EDIT: end vcpkg modified block

include(Compiler.cmake)
include(GLESv2.cmake)

# ANGLE Renderer backends
include(D3D.cmake)
include(GL.cmake)
include(Metal.cmake)
include(Vulkan.cmake)

set(no_gl_prototypes
    GL_GLES_PROTOTYPES=0
    EGL_EGL_PROTOTYPES=0
)

set(gl_prototypes
    GL_GLES_PROTOTYPES=1
    EGL_EGL_PROTOTYPES=1
    GL_GLEXT_PROTOTYPES
    EGL_EGLEXT_PROTOTYPES
)

# Default library types for ANGLE
# Override these in Platform*.cmake for your port as needed.
set(ANGLE_LIBRARY_TYPE STATIC) # libANGLE static library (matches expected behavior & prior behavior)
set(GLESv2_LIBRARY_TYPE) # VCPKG EDIT: Default to BUILD_SHARED_LIBS setting
set(EGL_LIBRARY_TYPE) # VCPKG EDIT: Default to BUILD_SHARED_LIBS setting

# ANGLE makes a number of small static libraries that are then joined into a
# bigger library that is built shared. Rather than making the small libraries
# there will be a ANGLE whose sources are dependent on whether the library
# is being used as a compiler or as a GLES implementation.
#
# The corresponding gn targets are described below
#
# ANGLE (Compiler only)
# + angle_common
# + preprocessor
# + translator
#
# ANGLE (GLES)
# + ANGLE (Compiler only)
# + xxhash
# + angle_image_util
# + angle_system_utils (OS specific)
# + angle_(renderer) (Backend and OS specific)

set(ANGLE_PRIVATE_INCLUDE_DIRECTORIES
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/KHR"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common/third_party/base"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common/base"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common/third_party/xxhash"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/zlib/google"
    "${CMAKE_CURRENT_BINARY_DIR}/include"
)
if (USE_VULKAN)
    list(APPEND ANGLE_PRIVATE_INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/spirv-headers/src/include"
    )
endif()

set(ANGLE_DEFINITIONS
    ANGLE_ENABLE_ESSL
    ANGLE_ENABLE_GLSL
)

if (ANGLE_ENABLE_TRACE)
    list(APPEND ANGLE_DEFINITIONS ANGLE_ENABLE_DEBUG_TRACE=1)
endif()

if (ANGLE_ENABLE_TRACE_EVENTS)
    list(APPEND ANGLE_DEFINITIONS ANGLE_ENABLE_TRACE_EVENTS=1)
endif()

if (ANGLE_ALWAYS_LOG_INFO)
    list(APPEND ANGLE_DEFINITIONS ANGLE_ALWAYS_LOG_INFO)
endif()

if (ANGLE_ENABLE_VULKAN_VALIDATION_LAYERS)
    list(APPEND ANGLE_DEFINITIONS ANGLE_ENABLE_VULKAN_VALIDATION_LAYERS)
endif()

if (ANGLE_ENABLE_VULKAN_VALIDATION_LAYERS_BY_DEFAULT)
    list(APPEND ANGLE_DEFINITIONS ANGLE_ENABLE_VULKAN_VALIDATION_LAYERS_BY_DEFAULT)
endif()

# VCPKG EDIT
list(APPEND ANGLE_DEFINITIONS ANGLE_CAPTURE_ENABLED=0)
if (NOT WIN32)
    list(APPEND ANGLE_DEFINITIONS
        "-DGL_API=__attribute__((visibility(\"default\")))"
        "-DGL_APICALL=__attribute__((visibility(\"default\")))"
    )
endif()
# END VCPKG EDIT

set(ANGLE_SOURCES
    ${libangle_common_sources}
    ${libangle_common_shader_state_sources}
    ${angle_preprocessor_sources}
    ${angle_translator_glsl_base_sources}
    ${angle_translator_essl_sources}
    ${angle_translator_essl_symbol_table_sources}
    ${angle_translator_glsl_and_vulkan_base_sources}
    ${angle_translator_glsl_sources}
    ${angle_translator_sources}
    ${angle_system_utils_sources}
    src/common/angle_version_info.cpp
    src/libANGLE/capture/FrameCapture_mock.cpp
    src/libANGLE/capture/serialize_mock.cpp
)

if (USE_VULKAN)
    list(APPEND ANGLE_SOURCES
        src/common/spirv/angle_spirv_utils.cpp
        src/common/spirv/spirv_instruction_builder_autogen.cpp
        src/common/spirv/spirv_instruction_parser_autogen.cpp
        src/common/vulkan/libvulkan_loader.cpp
        src/common/vulkan/vulkan_icd.cpp
        src/compiler/translator/spirv/BuildSPIRV.cpp
        src/compiler/translator/spirv/BuiltinsWorkaround.cpp
        src/compiler/translator/spirv/OutputSPIRV.cpp
        src/compiler/translator/spirv/TranslatorSPIRV.cpp
        src/compiler/translator/tree_ops/spirv/ClampGLLayer.cpp
        src/compiler/translator/tree_ops/spirv/EmulateAdvancedBlendEquations.cpp
        src/compiler/translator/tree_ops/spirv/EmulateDithering.cpp
        src/compiler/translator/tree_ops/spirv/EmulateFragColorData.cpp
        src/compiler/translator/tree_ops/spirv/EmulateFramebufferFetch.cpp
        src/compiler/translator/tree_ops/spirv/EmulateYUVBuiltIns.cpp
        src/compiler/translator/tree_ops/spirv/FlagSamplersWithTexelFetch.cpp
        src/compiler/translator/tree_ops/spirv/ReswizzleYUVOps.cpp
        src/compiler/translator/tree_ops/spirv/RewriteInterpolateAtOffset.cpp
        src/compiler/translator/tree_ops/spirv/RewriteR32fImages.cpp
        src/compiler/translator/tree_ops/spirv/RewriteSamplerExternalTexelFetch.cpp
        src/gpu_info_util/SystemInfo_vulkan.cpp
        src/libANGLE/renderer/vulkan/vk_mem_alloc_wrapper.cpp
    )

    list(APPEND ANGLE_DEFINITIONS
        ANGLE_VK_MOCK_ICD_JSON=\"VkICD_mock_icd.json\"
        ANGLE_VK_LAYERS_DIR=\".\"
        ANGLE_PROGRAM_LINK_VALIDATE_UNIFORM_PRECISION=0
    )

    if (ANGLE_ENABLE_VULKAN_API_DUMP_LAYER)
        list(APPEND ANGLE_DEFINITIONS ANGLE_ENABLE_VULKAN_API_DUMP_LAYER)
    endif()

    set_source_files_properties(
        src/libANGLE/renderer/vulkan/vk_mem_alloc_wrapper.cpp
        PROPERTIES COMPILE_DEFINITIONS VMA_IMPLEMENTATION
    )
endif()

if (WIN32)
    # FIXME: DX11 support will not compile if this preprocessor definition is set
    # DirectX Documentation is setting that version to 0x700 but there is no
    # corresponding value in sdkddkver.h
    remove_definitions(-D_WIN32_WINNT=0x601 -DWINVER=0x601)

    if (USE_VULKAN)
        list(APPEND ANGLE_DEFINITIONS VK_USE_PLATFORM_WIN32_KHR)
    endif()

    list(APPEND ANGLE_SOURCES
        "src/libANGLE/renderer/dxgi_format_map.h"
        "src/libANGLE/renderer/dxgi_format_map_autogen.cpp"
        "src/libANGLE/renderer/dxgi_support_table.h"
        "src/libANGLE/renderer/dxgi_support_table_autogen.cpp"
    )
    if (NOT angle_is_winuwp)
        list(APPEND ANGLE_SOURCES
            "src/libANGLE/renderer/d3d_format.cpp"
            "src/libANGLE/renderer/d3d_format.h"
        )
    endif()
endif ()

set(ANGLEGLESv2_LIBRARIES
    ANGLE
)

set(zlib_wrapper_sources
    "third_party/zlib/google/compression_utils_portable.h"
    "third_party/zlib/google/compression_utils_portable.cc"
)

set(angle_gl_enum_utils # VCPKG EDIT: Update paths
    "src/common/gl_enum_utils.cpp"
    "src/common/gl_enum_utils.h"
    "src/common/gl_enum_utils_autogen.cpp"
    "src/common/gl_enum_utils_autogen.h"
)

WEBKIT_INCLUDE_CONFIG_FILES_IF_EXISTS()

add_subdirectory(include)

add_library(ANGLEFramework INTERFACE)
add_dependencies(ANGLEFramework GLSLANGHeaders ANGLEHeaders)

if (USE_ANGLE_EGL OR ENABLE_WEBGL)
    add_library(ANGLE ${ANGLE_LIBRARY_TYPE}
        ${ANGLE_SOURCES}
        ${libangle_sources}
        ${libangle_headers}
        ${libangle_image_util_sources}
        ${libangle_image_util_headers}
        ${xxhash_sources}
        ${zlib_wrapper_sources}
        ${angle_gl_enum_utils}
    )
    target_include_directories(ANGLE PRIVATE ${ANGLE_PRIVATE_INCLUDE_DIRECTORIES})
    target_compile_definitions(ANGLE PRIVATE
        ${no_gl_prototypes}
        LIBANGLE_IMPLEMENTATION
    )
    target_compile_definitions(ANGLE PUBLIC ${ANGLE_DEFINITIONS})
    target_link_libraries(ANGLE PRIVATE ZLIB::ZLIB ${CMAKE_DL_LIBS})
    if (USE_VULKAN)
        target_link_libraries(ANGLE PRIVATE Vulkan::Vulkan SPIRV-Tools-static GPUOpen::VulkanMemoryAllocator)
    endif()

    target_compile_definitions(ANGLEFramework INTERFACE ${gl_prototypes})

    add_library(GLESv2 ${GLESv2_LIBRARY_TYPE}
        ${libglesv2_entry_point_sources}
        ${libglesv2_sources}
    )
    target_include_directories(GLESv2 PRIVATE ${ANGLE_PRIVATE_INCLUDE_DIRECTORIES})
    target_compile_definitions(GLESv2 PRIVATE 
        ${no_gl_prototypes}
        LIBGLESV2_IMPLEMENTATION
    )

    target_link_libraries(GLESv2 PRIVATE ${ANGLEGLESv2_LIBRARIES} ${CMAKE_DL_LIBS})

    if (WIN32)
        # Output library name according to the .def
        target_sources(GLESv2 PRIVATE src/libGLESv2/libGLESv2_autogen.def)
        set_target_properties(GLESv2 PROPERTIES OUTPUT_NAME libGLESv2)
    endif ()
    # Rename libs to avoid conflict with system OpenGL
    if(NOT VCPKG_TARGET_IS_WINDOWS)
        set_target_properties(GLESv2 PROPERTIES OUTPUT_NAME libGLESv2_angle)
    endif()

    add_library(GLESv2Framework INTERFACE)
    target_link_libraries(GLESv2Framework INTERFACE GLESv2)
    target_include_directories(GLESv2Framework INTERFACE ${ANGLE_FRAMEWORK_HEADERS_DIR})
    target_compile_definitions(GLESv2Framework INTERFACE USE_SYSTEM_EGL)
    add_library(ANGLE::GLES ALIAS GLESv2Framework)

    if (USE_ANGLE_EGL)
        add_library(EGL ${EGL_LIBRARY_TYPE}
            ${libegl_sources}
        )
        target_include_directories(EGL PRIVATE ${ANGLE_PRIVATE_INCLUDE_DIRECTORIES})
        target_compile_definitions(EGL PRIVATE
            ${ANGLE_DEFINITIONS}
            ${gl_prototypes}
            EGLAPI=
        )

        target_link_libraries(EGL PRIVATE GLESv2 ${CMAKE_DL_LIBS})

        set_target_properties(EGL PROPERTIES LINKER_LANGUAGE CXX)
        if (WIN32)
            # Output library names according to the .def
            target_sources(EGL PRIVATE src/libEGL/libEGL_autogen.def)
            set_target_properties(EGL PROPERTIES OUTPUT_NAME libEGL)
        endif ()
        # Rename libs to avoid conflict with system OpenGL
        if(NOT VCPKG_TARGET_IS_WINDOWS)
            set_target_properties(EGL PROPERTIES OUTPUT_NAME libEGL_angle)
        endif()

        add_library(EGLFramework INTERFACE)
        target_include_directories(EGLFramework INTERFACE ${ANGLE_FRAMEWORK_HEADERS_DIR}/)
        target_compile_definitions(EGLFramework INTERFACE ${gl_prototypes})
        target_link_libraries(EGLFramework INTERFACE EGL)
        add_library(ANGLE::EGL ALIAS EGLFramework)
    endif ()
else ()
    add_library(ANGLE ${ANGLE_LIBRARY_TYPE} ${ANGLE_SOURCES})
    target_include_directories(ANGLE PRIVATE ${ANGLE_PRIVATE_INCLUDE_DIRECTORIES})
    target_link_libraries(ANGLE PRIVATE ${CMAKE_DL_LIBS})
    target_compile_definitions(ANGLE PRIVATE
        ${ANGLE_DEFINITIONS}
        ${no_gl_prototypes}
        LIBANGLE_IMPLEMENTATION
    )
    if (USE_VULKAN)
        target_link_libraries(ANGLE PRIVATE Vulkan::Vulkan SPIRV-Tools-static GPUOpen::VulkanMemoryAllocator)
    endif()
endif ()

if (ENABLE_WEBGL)
    set(libglesv2_entry_points_headers
        src/libGLESv2/entry_points_egl_autogen.h
        src/libGLESv2/entry_points_egl_ext_autogen.h
        src/libGLESv2/entry_points_gles_2_0_autogen.h
        src/libGLESv2/entry_points_gles_3_0_autogen.h
        src/libGLESv2/entry_points_gles_ext_autogen.h
    )

    WEBKIT_COPY_FILES(LibGLESv2EntryPointsHeaders
        DESTINATION ${ANGLE_FRAMEWORK_HEADERS_DIR}/ANGLE
        FILES ${libglesv2_entry_points_headers}
        FLATTENED
    )
    if (WIN32 AND TARGET GLESv2)
        # GLESv2 needs to have a direct or indirect dependency to
        # LibGLESv2EntryPointsHeaders for CMake Visual Studio generator
        # to eliminate duplicated custom commands. Otherwise,
        # entry_points_*.h will be copied twice in both projects.
        add_dependencies(GLESv2 LibGLESv2EntryPointsHeaders)
    endif ()

    add_custom_target(ANGLE-webgl-headers
        DEPENDS LibGLESv2EntryPointsHeaders ANGLEWebGLHeaders
        COMMAND ${CMAKE_COMMAND} -E env
            BUILT_PRODUCTS_DIR=${ANGLE_FRAMEWORK_HEADERS_DIR}
            PUBLIC_HEADERS_FOLDER_PATH=/ANGLE
            ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/adjust-angle-include-paths.py
        VERBATIM
    )
    add_dependencies(GLESv2Framework ANGLE-webgl-headers)
endif ()

if (COMPILER_IS_GCC_OR_CLANG)
    foreach (angle_target ANGLE EGL GLESv2)
        if (TARGET ${angle_target})
            WEBKIT_ADD_TARGET_C_FLAGS(${angle_target} -w)
            WEBKIT_ADD_TARGET_CXX_FLAGS(${angle_target} -w)
        endif ()
    endforeach ()
endif ()

target_link_libraries(ANGLEFramework INTERFACE ANGLE)
target_include_directories(ANGLEFramework INTERFACE ${ANGLE_FRAMEWORK_HEADERS_DIR})

add_library(ANGLE::ANGLE ALIAS ANGLEFramework)


##################################################

#### VCPKG EDIT:
#### various vcpkg additions and install commands

# set export names of some targets to match prior vcpkg port buildsystem
if(TARGET EGL)
    set_target_properties(EGL PROPERTIES EXPORT_NAME libEGL)
endif()
if(TARGET GLESv2)
    set_target_properties(GLESv2 PROPERTIES EXPORT_NAME libGLESv2)
endif()
set_target_properties(ANGLE PROPERTIES EXPORT_NAME libANGLE)

set(_possibleTargets EGL GLESv2 ANGLE)
foreach(_target IN LISTS _possibleTargets)
    if(TARGET ${_target})
        list(APPEND _installableTargets "${_target}")
    endif()
endforeach()

install(TARGETS ${_installableTargets} EXPORT ANGLEExport
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(EXPORT ANGLEExport FILE unofficial-angle-targets.cmake NAMESPACE unofficial::angle:: DESTINATION share/unofficial-angle)
install(FILES unofficial-angle-config.cmake DESTINATION share/unofficial-angle)

install(
    DIRECTORY "${ANGLE_FRAMEWORK_HEADERS_DIR}/"
    DESTINATION include
    FILES_MATCHING
    PATTERN "*.h"
    PATTERN "*.inc"
    PATTERN "CL" EXCLUDE
    PATTERN "GLSLANG" EXCLUDE
    PATTERN "EGL/egl.h" EXCLUDE
    PATTERN "EGL/eglext.h" EXCLUDE
    PATTERN "EGL/eglplatform.h" EXCLUDE
    PATTERN "KHR" EXCLUDE
    PATTERN "WGL" EXCLUDE
    PATTERN "export.h" EXCLUDE
    PATTERN "GLES/egl.h" EXCLUDE
    PATTERN "GLES/gl.h" EXCLUDE
    PATTERN "GLES/glext.h" EXCLUDE
    PATTERN "GLES/glplatform.h" EXCLUDE
    PATTERN "GLES2/gl2.h" EXCLUDE
    PATTERN "GLES2/gl2ext.h" EXCLUDE
    PATTERN "GLES2/gl2platform.h" EXCLUDE
    PATTERN "GLES3/gl3.h" EXCLUDE
    PATTERN "GLES3/gl31.h" EXCLUDE
    PATTERN "GLES3/gl32.h" EXCLUDE
    PATTERN "GLES3/gl3platform.h" EXCLUDE
)
install(
    DIRECTORY "${ANGLE_FRAMEWORK_HEADERS_DIR}/"
    DESTINATION include/angle
    FILES_MATCHING
    PATTERN "*.h"
    PATTERN "*.inc"
    PATTERN "CL" EXCLUDE
    PATTERN "GLSLANG" EXCLUDE
    PATTERN "EGL/egl.h" EXCLUDE
    PATTERN "EGL/eglext.h" EXCLUDE
    PATTERN "EGL/eglplatform.h" EXCLUDE
    PATTERN "KHR" EXCLUDE
    PATTERN "WGL" EXCLUDE
    PATTERN "export.h" EXCLUDE
)

if(NOT BUILD_SHARED_LIBS)
    foreach(angle_target EGL GLESv2 ANGLE)
        if(TARGET ${angle_target})
            target_compile_definitions(${angle_target} INTERFACE $<INSTALL_INTERFACE:KHRONOS_STATIC>)
        endif()
    endforeach()
endif()
