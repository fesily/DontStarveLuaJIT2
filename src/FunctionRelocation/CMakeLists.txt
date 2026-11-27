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
        FunctionRanges.cpp
        FunctionDiscovery.cpp
        GraphSeed.cpp
        CallTargetResolver.cpp
        UniqueSignature.cpp
)

find_package(spdlog CONFIG REQUIRED)
# libdwarf parses the ELF .eh_frame FDE table; only the Linux enumerator uses it.
if (UNIX AND NOT APPLE)
    find_package(libdwarf CONFIG REQUIRED)
endif()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Mach-O function starts probe (Apple).
# ---------------------------------------------------------------------------
# The staged Frida devkit exposes either the current GumMacho API or the older
# GumDarwin names. Probe what this devkit actually provides, refresh the result
# on every configure, and let the translation unit pick matching declarations.
if (APPLE)
    include(CheckCXXSourceCompiles)
    unset(DS_GUM_HAS_MACHO_FUNCTION_STARTS CACHE)
    unset(DS_GUM_HAS_DARWIN_FUNCTION_STARTS CACHE)
    set(_ds_gum_probe_includes ${CMAKE_REQUIRED_INCLUDES})
    set(_ds_gum_probe_libraries ${CMAKE_REQUIRED_LIBRARIES})
    set(CMAKE_REQUIRED_INCLUDES ${FRIDA_GUM_INCLUDE_DIR})
    if (TARGET Frida::Gum)
        set(CMAKE_REQUIRED_LIBRARIES Frida::Gum)
    endif()
    check_cxx_source_compiles("
        #include <frida-gum.h>
        int main(int, char **) {
          GumMachoModule * module = gum_macho_module_new_from_memory(
              \"probe\", 0, 0, GUM_MACHO_MODULE_FLAGS_NONE, nullptr);
          (void) module;
          // Assign through a volatile so the undefined-symbol check survives -O2.
          auto volatile enumerate =
              &gum_macho_module_enumerate_function_starts;
          (void) enumerate;
          GumMachoFunctionStartsDetails details{};
          (void) details.vm_address;
          (void) details.size;
          return 0;
        }" DS_GUM_HAS_MACHO_FUNCTION_STARTS)
    check_cxx_source_compiles("
        #include <frida-gum.h>
        int main(int, char **) {
          GumDarwinModule * module = gum_darwin_module_new_from_memory(
              \"probe\", 0, 0, GUM_DARWIN_MODULE_FLAGS_NONE, nullptr);
          (void) module;
          auto volatile enumerate =
              &gum_darwin_module_enumerate_function_starts;
          (void) enumerate;
          GumDarwinFunctionStartsDetails details{};
          (void) details.vm_address;
          (void) details.size;
          return 0;
        }" DS_GUM_HAS_DARWIN_FUNCTION_STARTS)
    set(CMAKE_REQUIRED_INCLUDES ${_ds_gum_probe_includes})
    set(CMAKE_REQUIRED_LIBRARIES ${_ds_gum_probe_libraries})
    message(STATUS "Frida Mach-O function starts: MACHO=${DS_GUM_HAS_MACHO_FUNCTION_STARTS} "
            "DARWIN=${DS_GUM_HAS_DARWIN_FUNCTION_STARTS}")
endif()

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
    if (APPLE)
        # Native Mach-O fallback vs. the Frida devkit's own function-starts API.
        if (DS_GUM_HAS_MACHO_FUNCTION_STARTS)
            target_compile_definitions(${target} PRIVATE DS_GUM_HAS_MACHO_FUNCTION_STARTS=1)
        elseif (DS_GUM_HAS_DARWIN_FUNCTION_STARTS)
            target_compile_definitions(${target} PRIVATE DS_GUM_HAS_DARWIN_FUNCTION_STARTS=1)
        endif()
    endif()
    if (MSVC)
        target_link_libraries(${target} PRIVATE pe-parse::pe-parse)
    else()
        # Prefer multi-config IMPORTED target (avoids lib/debug/lib RPATH cycles).
        if (TARGET keystone::keystone)
            target_link_libraries(${target} PRIVATE keystone::keystone)
        else()
            target_link_libraries(${target} PRIVATE ${KEYSTONE_LIBRARIES})
        endif()
        if (UNIX AND NOT APPLE)
            target_link_libraries(${target} PRIVATE libdwarf::dwarf)
        endif()
    endif()
endfunction()

if (WIN32)
    add_library(function_relocation SHARED ${SOURCE})
    target_compile_definitions(function_relocation PRIVATE FUNCTION_RELOCATION_BUILD)
    _function_relocation_common_config(function_relocation)
    target_link_libraries(function_relocation PRIVATE Frida::Gum)

    # Build-tree: next to Injector under deps/ (package install also → Mod/deps).
    # Never next to Injector.dll itself — that was applocal pollution.
    set_target_properties(function_relocation PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/deps"
            ARCHIVE_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/deps"
            LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/deps"
            PDB_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/deps"
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
            BUILD_RPATH "$ORIGIN"
    )
    install(TARGETS function_relocation
            LIBRARY DESTINATION deps COMPONENT deps)
    add_library(function_relocation_static STATIC ${SOURCE})
    target_compile_definitions(function_relocation_static PUBLIC FUNCTION_RELOCATION_STATIC)
    _function_relocation_common_config(function_relocation_static)
endif()
