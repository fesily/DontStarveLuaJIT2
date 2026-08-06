
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
)

find_package(spdlog CONFIG REQUIRED)
find_package(libdwarf CONFIG REQUIRED)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(function_relocation SHARED ${SOURCE})
target_compile_definitions(function_relocation PRIVATE FUNCTION_RELOCATION_BUILD)
target_compile_features(function_relocation PUBLIC cxx_std_23)

# Gum symbols are provided by Injector (not a second frida-gum copy):
# - Injector.dll links frida-gum statically and re-exports gum_* / cs_* (FridaGum.def)
# - This SHARED lib only includes gum headers; on MSVC it links an import lib that
#   binds those symbols to Injector.dll so the DLL links without frida-gum.lib.
# - Do NOT link frida-gum here or a second Gum instance is pulled into the process.
target_include_directories(function_relocation PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(function_relocation PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(function_relocation PRIVATE spdlog::spdlog)
if (MSVC)
    target_link_libraries(function_relocation PRIVATE pe-parse::pe-parse)

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
else()
    target_link_libraries(function_relocation PRIVATE ${KEYSTONE_LIBRARIES})
    target_link_libraries(function_relocation PRIVATE libdwarf::dwarf)
endif ()

# Build tree: colocate with Injector so the OS loader resolves function_relocation
# when mapping Injector.dll (import dependency). Package install stages to deps/
# (mod/deps at runtime via PluginPath — Task 4 packaging).
set_target_properties(function_relocation PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
        ARCHIVE_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
        LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
        PDB_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>"
        # Hide non-API symbols on ELF when visibility is supported.
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
)

install(TARGETS function_relocation
        RUNTIME DESTINATION deps COMPONENT deps
        LIBRARY DESTINATION deps COMPONENT deps
        ARCHIVE DESTINATION deps COMPONENT deps)
