# ds_signature — signature scan/load static library for core.vm + tools.
# Owns: DontStarveSignature, SignatureJson, GameSignature, Progress (MSVC UI).
# Consumers link this STATIC lib; do not compile these TUs into other targets twice.

set(DS_SIGNATURE_SOURCES
    DontStarveSignature.cpp
    SignatureJson.cpp
    GameSignature.cpp
)
if (MSVC)
    list(APPEND DS_SIGNATURE_SOURCES Progress.cpp)
endif()

add_library(ds_signature STATIC ${DS_SIGNATURE_SOURCES})
target_compile_features(ds_signature PUBLIC cxx_std_23)

# Public headers live in this directory (DontStarveSignature.hpp, ...).
target_include_directories(ds_signature
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${DONTSTARVEINJECTOR_ROOT}
        ${DONTSTARVEINJECTOR_UTIL_DIR}
        ${FRIDA_GUM_INCLUDE_DIR}
        ${FUNCTION_RELOCATION_INCLUDE_DIR}
        ${PROJECT_SOURCE_DIR}/src
)

# Do NOT link frida-gum here: plugins already get gum_* from Injector re-exports.
# Do NOT PUBLIC-link function_relocation:
#   - Plugins/Injector link the SHARED target (Windows) themselves.
#   - Tools link function_relocation_static + their own frida-gum.
# PUBLIC-linking SHARED would force tools to delay-load Injector.dll for gum.
target_link_libraries(ds_signature
    PUBLIC
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        range-v3::meta range-v3::concepts range-v3::range-v3
)
# Headers/types from function_relocation; link unit chooses SHARED vs STATIC.
target_include_directories(ds_signature PUBLIC ${FUNCTION_RELOCATION_INCLUDE_DIR})

target_compile_definitions(ds_signature
    PRIVATE
        GUM_STATIC=1
        SPDLOG_COMPILED_LIB
        SPDLOG_FMT_EXTERNAL
        # Progress UI only on MSVC builds of this lib when SUPPORT_PROGRESS is set by consumer
)

# Progress window (Win) is optional; enable when consumer defines SUPPORT_PROGRESS.
# Propagate as INTERFACE so consumers that want the UI can set SUPPORT_PROGRESS on themselves
# and still see Progress symbols from this lib. Define SUPPORT_PROGRESS on this target for MSVC
# so Progress.cpp is not compiled as empty stubs.
if (MSVC)
    target_compile_definitions(ds_signature PRIVATE SUPPORT_PROGRESS)
    # Progress.cpp uses Win32 common controls
    target_link_libraries(ds_signature PRIVATE comctl32)
endif()

# Position-independent for linking into MODULE plugins (Linux/macOS).
set_target_properties(ds_signature PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

add_dependencies(ds_signature create_missfuncs)
