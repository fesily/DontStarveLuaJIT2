# Nucleus static library (engineering surface for DontStarveLuaJIT2)
# Algorithm sources (cfg/disasm/strategy) are stock; loader/util/endian may be
# patched for Windows PE + Capstone coexistence. See VENDOR.md and patches/.

cmake_minimum_required(VERSION 3.15)

set(NUCLEUS_SOURCES
    bb.cc
    cfg.cc
    dataregion.cc
    disasm.cc
    disasm-aarch64.cc
    disasm-arm.cc
    disasm-mips.cc
    disasm-ppc.cc
    disasm-x86.cc
    edge.cc
    endian.cc
    function.cc
    insn.cc
    loader.cc
    log.cc
    options_defaults.cc
    strategy.cc
    util.cc
    # intentionally omit nucleus.cc (CLI), options.cc (getopt), export.cc, exception.cc
)

add_library(nucleus_static STATIC ${NUCLEUS_SOURCES})
add_library(Nucleus::nucleus_static ALIAS nucleus_static)

target_compile_features(nucleus_static PUBLIC cxx_std_17)

target_include_directories(nucleus_static
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        # Consumers of nucleus headers (insn.h) need <capstone/capstone.h> -> frida-gum.
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/capstone_shim
)

# Capstone / Frida Gum surface:
#   - Includes + GUM_STATIC only on this archive (compile-time).
#   - Do NOT target_link_libraries frida-gum/capstone here.
#     CMake propagates PRIVATE deps of STATIC libs to every final link unit,
#     which would force a second frida-gum into SHARED function_relocation
#     (game path must import gum from Injector only). Tools/tests that use
#     nucleus_static / function_relocation_static link ${FRIDA_GUM_LIBRARIES}
#     (or Capstone) explicitly on the final executable/DLL.
if (NOT FRIDA_GUM_INCLUDE_DIR)
    # When added early from FunctionRelocation, Frida-gum may already be found
    # at the top level. Fall back to module path search.
    find_package(Frida-gum QUIET)
endif()

if (FRIDA_GUM_INCLUDE_DIR)
    target_include_directories(nucleus_static PRIVATE ${FRIDA_GUM_INCLUDE_DIR})
    target_compile_definitions(nucleus_static PRIVATE GUM_STATIC=1)
else()
    find_path(CAPSTONE_INCLUDE_DIR NAMES capstone/capstone.h)
    if (NOT CAPSTONE_INCLUDE_DIR)
        message(FATAL_ERROR
            "nucleus_static: need Frida-gum Capstone surface or system Capstone headers")
    endif()
    target_include_directories(nucleus_static PRIVATE ${CAPSTONE_INCLUDE_DIR})
endif()

if (WIN32)
    target_compile_definitions(nucleus_static PRIVATE NUCLEUS_LOADER_PE_PARSE=1)
    find_package(pe-parse CONFIG REQUIRED)
    target_link_libraries(nucleus_static PRIVATE pe-parse::pe-parse)
else()
    # Keep stock BFD loader when available; otherwise allow raw-only builds.
    find_library(BFD_LIBRARY NAMES bfd bfd-multiarch)
    if (BFD_LIBRARY)
        target_link_libraries(nucleus_static PRIVATE ${BFD_LIBRARY})
    else()
        message(WARNING "nucleus_static: libbfd not found; non-raw load will fail")
        target_compile_definitions(nucleus_static PRIVATE NUCLEUS_LOADER_NO_BFD=1)
    endif()
endif()

if (MSVC)
    target_compile_options(nucleus_static PRIVATE
        /W3
        /wd4018  # signed/unsigned mismatch (upstream style)
        /wd4244  # conversion warnings in disasm
        /wd4267  # size_t conversions
        /wd4996  # CRT deprecations
        /permissive-
    )
else()
    target_compile_options(nucleus_static PRIVATE
        -Wall
        -Wno-unused-parameter
        -fpermissive
    )
endif()

set_target_properties(nucleus_static PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
