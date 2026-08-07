
# Nucleus CFG stack (function body authority). Built as nucleus_static.
# Link is deferred to Task 2 (NucleusAdapter); only ensure the target exists.
if (NOT TARGET nucleus_static)
    add_subdirectory(${CMAKE_SOURCE_DIR}/3rd/nucleus ${CMAKE_BINARY_DIR}/3rd/nucleus)
endif()

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
# function_relocation uses gum_*/cs_* but MUST NOT link a second frida-gum copy
# into game plugins (Injector already embeds Gum and re-exports on Windows via
# FridaGum.def).
#
# Windows:
#   - function_relocation        SHARED for Injector + plugins
#       gum via Injector.dll import lib + /DELAYLOAD (breaks hard circular load)
#   - function_relocation_static STATIC for standalone tools
#       no Injector; tools already link frida-gum themselves
#
# Non-Windows:
#   - SHARED is gated off: ELF/Mach-O gum re-export from Injector is still
#     unimplemented (same residual as gum-using plugin skip). A SHARED reloc
#     under -z,defs / -undefined,error would either leave gum_* undefined or
#     force a second frida-gum into the .so — both are wrong for plugins.
#   - Keep one STATIC target named function_relocation; tools alias it.
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
    # --- SHARED: game Injector + plugins (one process-wide Gum from Injector) ---
    add_library(function_relocation SHARED ${SOURCE})
    target_compile_definitions(function_relocation PRIVATE FUNCTION_RELOCATION_BUILD)
    _function_relocation_common_config(function_relocation)

    # Import gum_*/cs_* from Injector.dll (same re-export surface plugins use).
    set(_gum_import_def "${CMAKE_CURRENT_BINARY_DIR}/InjectorGumImport.def")
    set(_gum_import_lib "${CMAKE_CURRENT_BINARY_DIR}/InjectorGumImport.lib")
    file(READ "${DONTSTARVEINJECTOR_ROOT}/FridaGum.def" _frida_def_content)
    file(WRITE "${_gum_import_def}" "LIBRARY Injector\n${_frida_def_content}")
    add_custom_command(
            OUTPUT "${_gum_import_lib}"
            COMMAND lib /nologo "/def:${_gum_import_def}" "/out:${_gum_import_lib}" /machine:x64
            DEPENDS "${DONTSTARVEINJECTOR_ROOT}/FridaGum.def" "${_gum_import_def}"
            COMMENT "Generating Injector gum import lib for function_relocation"
            VERBATIM)
    add_custom_target(function_relocation_gum_import DEPENDS "${_gum_import_lib}")
    # Delay-load Injector so mapping function_relocation as Injector's import
    # dependency does not create a hard circular load (gum imports resolve on first use,
    # after Injector is already mapped).
    target_link_libraries(function_relocation PRIVATE "${_gum_import_lib}" delayimp)
    target_link_options(function_relocation PRIVATE
        "/DELAYLOAD:Injector.dll"
        # frida-gum.h always #pragma comment(lib,"frida-gum.lib") under _MSC_VER.
        # Ignore it — gum is imported from Injector, never linked as a second copy.
        "/NODEFAULTLIB:frida-gum.lib")

    # Build tree: colocate with Injector so the OS loader resolves function_relocation
    # when mapping Injector.dll (import dependency). Package install stages to deps/
    # (mod/deps at runtime via PluginPath — Task 4 packaging).
    set_target_properties(function_relocation PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            ARCHIVE_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            PDB_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
    )

    # RUNTIME only for package deps/ (import .lib is build-only, not shipped).
    install(TARGETS function_relocation
            RUNTIME DESTINATION deps COMPONENT deps
            LIBRARY DESTINATION deps COMPONENT deps)

    # --- STATIC: tools (signature_updater / signature_checker) ---
    # Tools already link ${FRIDA_GUM_LIBRARIES}. They must not depend on
    # function_relocation.dll delay-loading Injector.dll for gum.
    add_library(function_relocation_static STATIC ${SOURCE})
    # PUBLIC: consumers see FUNCTION_RELOCATION_STATIC so headers skip dllimport.
    target_compile_definitions(function_relocation_static PUBLIC FUNCTION_RELOCATION_STATIC)
    _function_relocation_common_config(function_relocation_static)
    # frida-gum.h pragma pulls frida-gum.lib into the final tool link — intended.
else()
    # Residual: non-Windows dynamic reloc (SHARED + Injector gum re-export) is
    # unimplemented. STATIC keeps gum_* resolved by the final link unit only
    # (Injector embeds Gum; tools link frida-gum). Matches gum plugin skip.
    add_library(function_relocation STATIC ${SOURCE})
    _function_relocation_common_config(function_relocation)
    set_target_properties(function_relocation PROPERTIES
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
    )
    # Same target for tool CMake that always asks for function_relocation_static.
    add_library(function_relocation_static ALIAS function_relocation)

    # Non-Windows: STATIC only (no SHARED runtime to ship under deps/).
    # Tools keep their own frida-gum; nothing to package for mod/deps.
endif()
