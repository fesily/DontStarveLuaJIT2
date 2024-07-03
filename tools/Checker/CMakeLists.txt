cmake_minimum_required(VERSION 3.15)

set(SOURCES
        main.cpp
        ${DONTSTARVEINJECTOR_ROOT}/SignatureJson.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

add_executable(signature_checker ${SOURCES})

target_include_directories(signature_checker PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(signature_checker PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR})
target_include_directories(signature_checker PUBLIC ${DONTSTARVEINJECTOR_ROOT})

target_include_directories(signature_checker PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(signature_checker PRIVATE ${FRIDA_GUM_LIBRARIES})

target_link_libraries(signature_checker PRIVATE nlohmann_json::nlohmann_json)
target_include_directories(signature_checker PUBLIC ${FUNCTION_RELOCATION_INCLUDE_DIR})
target_link_libraries(signature_checker PRIVATE function_relocation)
target_link_libraries(signature_checker PRIVATE spdlog::spdlog)

file(TO_NATIVE_PATH "${GAME_DIR}" GAMEDIR)
string(REPLACE "\\" "\\\\" GAMEDIR ${GAMEDIR})
file(TO_NATIVE_PATH "${LUA_LIBRARIES_PATH}" LUA51_PATH)
string(REPLACE "\\" "\\\\" LUA51_PATH ${LUA51_PATH})
target_compile_definitions(signature_checker PUBLIC GAMEDIR="${GAMEDIR}" LUA51_PATH="${LUA51_PATH}" PROJECT_DIR="${PROJECT_SOURCE_DIR}")

if (MSVC)
    target_link_options(signature_checker PUBLIC "/NODEFAULTLIB:LIBCMT")
endif ()

add_dependencies(signature_checker signature_updater)