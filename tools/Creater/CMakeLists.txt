cmake_minimum_required(VERSION 3.15)

set(SOURCES
        main.cpp
        ${DONTSTARVEINJECTOR_ROOT}/DontStarveSignature.cpp
        ${DONTSTARVEINJECTOR_ROOT}/SignatureJson.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/gum_platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_library(signature_updater SHARED ${SOURCES})

    if (APPLE)
        set(GAME_EXECUTABLE_DIR ${GAME_INSTALL_PREFIX}/MacOS)
        set(GAME_EXECUTABLE_NAME "dontstarve_steam_x64_1")
        if(NOT EXISTS ${GAME_EXECUTABLE_DIR}/${GAME_EXECUTABLE_NAME})
            set(GAME_EXECUTABLE_NAME "dontstarve_steam_x64")
        endif()
        set(GAME_SERVER_EXECUTABLE_NAME "dontstarve_dedicated_server_nullrenderer_x64_1")
        if(NOT EXISTS ${GAME_EXECUTABLE_DIR}/${GAME_SERVER_EXECUTABLE_NAME})
            set(GAME_SERVER_EXECUTABLE_NAME "dontstarve_dedicated_server_nullrenderer_x64")
        endif()
        set(PRELOAD_ENV_KEY DYLD_INSERT_LIBRARIES)
        add_custom_target(update_signatures
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" ${GAME_INSTALL_PREFIX}/${GAME_EXECUTABLE_NAME}
                COMMAND ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" ${GAME_INSTALL_PREFIX}/${GAME_SERVER_EXECUTABLE_NAME}
                WORKING_DIRECTORY ${GAME_INSTALL_PREFIX}
        )
    else ()
        set(GAME_EXECUTABLE_DIR ${GAME_INSTALL_PREFIX}/bin64)
        set(GAME_EXECUTABLE_NAME "dontstarve_steam_x64_1")
        if(NOT EXISTS ${GAME_EXECUTABLE_DIR}/${GAME_EXECUTABLE_NAME})
            set(GAME_EXECUTABLE_NAME "dontstarve_steam_x64")
        endif()
        set(GAME_SERVER_EXECUTABLE_NAME "dontstarve_dedicated_server_nullrenderer_x64_1")
        if(NOT EXISTS ${GAME_EXECUTABLE_DIR}/${GAME_SERVER_EXECUTABLE_NAME})
            set(GAME_SERVER_EXECUTABLE_NAME "dontstarve_dedicated_server_nullrenderer_x64")
        endif()
        set(PRELOAD_ENV_KEY LD_PRELOAD)

        add_custom_target(update_signatures
                ${CMAKE_COMMAND} -E env ${PRELOAD_ENV_KEY}="$<TARGET_FILE:signature_updater>" LUA51_SIGNATURE_OUTPUT_DIR="${CMAKE_INSTALL_PREFIX}"
                ${CMAKE_CURRENT_SOURCE_DIR}/update_signatures.sh ${LUA_EXECUTABLE_PATH} ${GAME_INSTALL_PREFIX}/${GAME_EXECUTABLE_NAME} ${GAME_INSTALL_PREFIX}/${GAME_SERVER_EXECUTABLE_NAME}
                WORKING_DIRECTORY ${GAME_INSTALL_PREFIX}
        )
    endif ()
else ()
    add_executable(signature_updater ${SOURCES})
    add_custom_target(update_signatures
            COMMAND signature_updater
    )
endif ()

target_include_directories(signature_updater PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(signature_updater PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR})
target_include_directories(signature_updater PUBLIC ${DONTSTARVEINJECTOR_ROOT})
target_link_libraries(signature_updater PRIVATE spdlog::spdlog)


target_include_directories(signature_updater PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(signature_updater PRIVATE ${FRIDA_GUM_LIBRARIES})

target_link_libraries(signature_updater PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(signature_updater PRIVATE function_relocation)
target_include_directories(signature_updater PUBLIC ${FUNCTION_RELOCATION_INCLUDE_DIR})

target_compile_definitions(signature_updater PUBLIC
        GAMEDIR="${GAME_DIR}"
        LUA51_PATH="${LUA_LIBRARIES_PATH}"
        WORKER_DIR="${CMAKE_INSTALL_PREFIX}"
        EXECUTABLE_SUFFIX="${CMAKE_EXECUTABLE_SUFFIX}"
)

if (MSVC)
    target_link_options(signature_updater PUBLIC "/NODEFAULTLIB:LIBCMT")
endif ()

add_dependencies(signature_updater create_missfuncs)
