cmake_minimum_required(VERSION 3.15)

# ds_signature_provider — shared, global-state-free signature provider machinery.
#
# Owns: the generic scan/select/verify implementation behind ProviderDesc, the
# fixed-cache reader/writer and the stateless create/update/check runner.
# Consumers: Injector (SignatureManager), every plugin that declares signatures,
# and the offline tools (which link the same provider TUs — never the plugins).
#
# No mutable global state lives in this library: the Injector's SignatureManager
# is the only runtime registry, and each provider's descriptor is static data in
# the module that owns it.

set(DS_SIGNATURE_PROVIDER_SOURCES
    SignatureCache.cpp
    SignatureScan.cpp
    SignatureRunner.cpp
)

add_library(ds_signature_provider STATIC ${DS_SIGNATURE_PROVIDER_SOURCES})
target_compile_features(ds_signature_provider PUBLIC cxx_std_23)

target_include_directories(ds_signature_provider
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${DONTSTARVEINJECTOR_ROOT}
        ${FUNCTION_RELOCATION_INCLUDE_DIR}
    PRIVATE
        ${FRIDA_GUM_INCLUDE_DIR}
        ${PROJECT_SOURCE_DIR}/src
)

find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

# Headers of function_relocation + frida-gum are needed to compile; the final
# MODULE/EXE consumer links Frida::Gum and function_relocation itself (same
# policy as ds_signature).
target_link_libraries(ds_signature_provider
    PUBLIC
        nlohmann_json::nlohmann_json
        spdlog::spdlog
)

target_compile_definitions(ds_signature_provider
    PRIVATE
        SPDLOG_COMPILED_LIB
        SPDLOG_FMT_EXTERNAL
)

set_target_properties(ds_signature_provider PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)
