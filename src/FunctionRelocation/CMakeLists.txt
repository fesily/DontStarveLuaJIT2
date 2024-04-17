
find_package(pe-parse CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

set(SOURCE
        Signature.cpp
        ModuleSections.cpp
        MemorySignature.cpp
        KartaConfig.cpp
        ctx.cpp
        disasm.h
        ScanCtx.hpp
)

find_package(spdlog CONFIG REQUIRED)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(function_relocation STATIC ${SOURCE})

target_include_directories(function_relocation PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(function_relocation PRIVATE ${FRIDA_GUM_LIBRARIES})

target_link_libraries(function_relocation PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(function_relocation PRIVATE spdlog::spdlog)
if (MSVC)
    target_link_libraries(function_relocation PRIVATE pe-parse::pe-parse)
endif ()