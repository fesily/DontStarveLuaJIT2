cmake_minimum_required(VERSION 3.15)

set (SOURCES
main.cpp
${DONTSTARVEINJECTOR_ROOT}/DontStarveSignature.cpp
${DONTSTARVEINJECTOR_ROOT}/SignatureJson.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/Signature.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(signature_updater ${SOURCES})

target_include_directories(signature_updater PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(signature_updater PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR})
target_include_directories(signature_updater PUBLIC ${DONTSTARVEINJECTOR_ROOT})
target_link_libraries(signature_updater PRIVATE spdlog::spdlog)


target_include_directories(signature_updater PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(signature_updater PRIVATE ${FRIDA_GUM_LIBRARIES})

target_link_libraries(signature_updater PRIVATE nlohmann_json::nlohmann_json)

file(TO_NATIVE_PATH "${GAME_DIR}" GAMEDIR)
string(REPLACE "\\" "\\\\" GAMEDIR ${GAMEDIR})
target_compile_definitions(signature_updater PUBLIC GAMEDIR="${GAMEDIR}" LUA51_PATH="${LUA_LIBRARIES_PATH}" PROJECT_DIR="${PROJECT_SOURCE_DIR}")

if (MSVC)
    target_link_options(signature_updater PUBLIC "/NODEFAULTLIB:LIBCMT")
endif()

add_dependencies(signature_updater create_missfuncs)
