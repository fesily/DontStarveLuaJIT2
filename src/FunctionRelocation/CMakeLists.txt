
find_package(pe-parse CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

set(SOURCE
        Signature.cpp
        KartaConfig.cpp
)

find_package(spdlog CONFIG REQUIRED)

add_library(function_relocation STATIC ${SOURCE})

target_include_directories(function_relocation PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(function_relocation PRIVATE ${FRIDA_GUM_LIBRARIES})

target_link_libraries(function_relocation PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(function_relocation PRIVATE spdlog::spdlog)
if (MSVC)
    target_link_libraries(function_relocation PRIVATE pe-parse::pe-parse)
endif ()