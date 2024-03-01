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

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_library(signature_updater SHARED ${SOURCES})
    set(GAME_EXECUTABLE_NAME "dontstarve_steam_x64")
    set(GAME_SERVER_EXECUTABLE_NAME "dontstarve_dedicated_server_nullrenderer_x64")
    set(INJECT_LOADER ${PROJECT_SOURCE_DIR}/tools/inject_loader.py)
    add_custom_target(update_signatures
        COMMAND ${PYTHON_EXECUTABLE_NAME} ${INJECT_LOADER} --game_target=${GAME_EXECUTABLE_NAME} --inject=$<TARGET_FILE:signature_updater>
        COMMAND ${PYTHON_EXECUTABLE_NAME} ${INJECT_LOADER} --game_target=${GAME_SERVER_EXECUTABLE_NAME} --inject=$<TARGET_FILE:signature_updater>
        WORKING_DIRECTORY ${GAME_INSTALL_PREFIX}
    )
else()
    add_executable(signature_updater ${SOURCES})
    add_custom_target(update_signatures
        COMMAND signature_updater
    )
endif()

target_include_directories(signature_updater PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(signature_updater PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR})
target_include_directories(signature_updater PUBLIC ${DONTSTARVEINJECTOR_ROOT})
target_link_libraries(signature_updater PRIVATE spdlog::spdlog)


target_include_directories(signature_updater PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(signature_updater PRIVATE ${FRIDA_GUM_LIBRARIES})

target_link_libraries(signature_updater PRIVATE nlohmann_json::nlohmann_json)

target_compile_definitions(signature_updater PUBLIC 
    GAMEDIR="${GAME_DIR}"
    LUA51_PATH="${LUA_LIBRARIES_PATH}"
    WORKER_DIR="${CMAKE_INSTALL_PREFIX}"
    EXECUTABLE_SUFFIX="${CMAKE_EXECUTABLE_SUFFIX}"
)

if (MSVC)
    target_link_options(signature_updater PUBLIC "/NODEFAULTLIB:LIBCMT")
endif()

add_dependencies(signature_updater create_missfuncs)
