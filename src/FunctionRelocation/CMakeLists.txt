
find_package(pe-parse CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

set(SOURCE
        Signature.cpp
        ModuleSections.cpp
        MemorySignature.cpp
        KartaConfig.cpp
        ctx.cpp
        disasm.h
        ScanCtx.cpp
        ExectuableSignature.cpp
        FunctionRanges.cpp
)

find_package(spdlog CONFIG REQUIRED)
find_package(libdwarf CONFIG REQUIRED)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Gum resolution policy
# ---------------------------------------------------------------------------
# function_relocation uses gum_*/cs_* via the process-wide shared Frida::Gum
# library. There is no Injector re-export and no second Gum copy.
#
# Windows / POSIX:
#   - function_relocation        SHARED for Injector + plugins (links Frida::Gum)
#   - function_relocation_static STATIC for standalone tools
#       tools also link Frida::Gum at the final EXE link
# ---------------------------------------------------------------------------

function(_function_relocation_common_config target)
    target_compile_features(${target} PUBLIC cxx_std_23)
    target_include_directories(${target} PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${FRIDA_GUM_INCLUDE_DIR})
    target_link_libraries(${target} PRIVATE nlohmann_json::nlohmann_json)
    target_link_libraries(${target} PRIVATE spdlog::spdlog)
    if (MSVC)
        target_link_libraries(${target} PRIVATE pe-parse::pe-parse)
    else()
        target_link_libraries(${target} PRIVATE ${KEYSTONE_LIBRARIES})
        target_link_libraries(${target} PRIVATE libdwarf::dwarf)
    endif()
endfunction()

if (WIN32)
    add_library(function_relocation SHARED ${SOURCE})
    target_compile_definitions(function_relocation PRIVATE FUNCTION_RELOCATION_BUILD)
    _function_relocation_common_config(function_relocation)
    target_link_libraries(function_relocation PRIVATE Frida::Gum)

    set_target_properties(function_relocation PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            ARCHIVE_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            PDB_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
    )

    install(TARGETS function_relocation
            RUNTIME DESTINATION deps COMPONENT deps
            LIBRARY DESTINATION deps COMPONENT deps)

    add_library(function_relocation_static STATIC ${SOURCE})
    target_compile_definitions(function_relocation_static PUBLIC FUNCTION_RELOCATION_STATIC)
    _function_relocation_common_config(function_relocation_static)
    # Tools link Frida::Gum for gum_*/cs_* at final link.
else()
    # Prefer SHARED when Frida::Gum shared is available (same as Windows).
    add_library(function_relocation SHARED ${SOURCE})
    target_compile_definitions(function_relocation PRIVATE FUNCTION_RELOCATION_BUILD)
    _function_relocation_common_config(function_relocation)
    target_link_libraries(function_relocation PRIVATE Frida::Gum)
    set_target_properties(function_relocation PROPERTIES
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
            INSTALL_RPATH "$ORIGIN"
    )
    install(TARGETS function_relocation
            LIBRARY DESTINATION deps COMPONENT deps)
    add_library(function_relocation_static STATIC ${SOURCE})
    target_compile_definitions(function_relocation_static PUBLIC FUNCTION_RELOCATION_STATIC)
    _function_relocation_common_config(function_relocation_static)
endif()
