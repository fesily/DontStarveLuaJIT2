cmake_minimum_required(VERSION 3.15)

set (SOURCES
main.cpp
${PROJECT_SOURCE_DIR}/src/DontStarveInjector/DontStarveSignature.cpp
${PROJECT_SOURCE_DIR}/src/DontStarveInjector/Signature.cpp
)
find_package(spdlog CONFIG REQUIRED)

add_executable(signature_Creater ${SOURCES})

target_include_directories(signature_Creater PUBLIC ${PROJECT_SOURCE_DIR}/src/frida-gum)
target_include_directories(signature_Creater PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(signature_Creater PUBLIC ${PROJECT_SOURCE_DIR}/src/DontStarveInjector)
target_link_directories(signature_Creater PUBLIC ${PROJECT_SOURCE_DIR}/src/frida-gum)
target_link_libraries(signature_Creater frida-gum spdlog::spdlog)

file(TO_NATIVE_PATH "${GAME_DIR}" GAMEDIR)
string(REPLACE "\\" "\\\\" GAMEDIR ${GAMEDIR})
target_compile_definitions(signature_Creater PUBLIC GAMEDIR="${GAMEDIR}" LUA51_PATH="${LUA_LIBRARIES_PATH}" PROJECT_DIR="${PROJECT_SOURCE_DIR}")

if (MSVC)
    target_link_options(signature_Creater PUBLIC "/NODEFAULTLIB:LIBCMT")
endif()

add_dependencies(signature_Creater create_missfuncs)
