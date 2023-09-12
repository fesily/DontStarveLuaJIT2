cmake_minimum_required(VERSION 3.15)

set (SOURCES
main.cpp
${PROJECT_SOURCE_DIR}/src/DontStarveInjector/signature.cpp
)

add_executable(signature_checker ${SOURCES})

target_include_directories(signature_checker PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(signature_checker PUBLIC ${PROJECT_SOURCE_DIR}/src/DontStarveInjector)

target_include_directories(signature_checker PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_directories(signature_checker PUBLIC ${FRIDA_GUM_LIBRARY_DIR})
target_link_libraries(signature_checker PRIVATE ${FRIDA_GUM_LIBRARIES})

file(TO_NATIVE_PATH "${GAME_DIR}" GAMEDIR)
string(REPLACE "\\" "\\\\" GAMEDIR ${GAMEDIR})
file(TO_NATIVE_PATH "${LUA_LIBRARIES_PATH}" LUA51_PATH)
string(REPLACE "\\" "\\\\" LUA51_PATH ${LUA51_PATH})
target_compile_definitions(signature_checker PUBLIC GAMEDIR="${GAMEDIR}" LUA51_PATH="${LUA51_PATH}")

if (MSVC)
    target_link_options(signature_checker PUBLIC "/NODEFAULTLIB:LIBCMT")
endif()

add_dependencies(signature_checker create_Signatures)