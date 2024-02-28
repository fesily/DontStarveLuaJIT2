find_package(libzip CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

option(ENABLE_STEAM_SUPPORT "Enable Steam support" OFF)

set (Winmm_SOURCES
winmm.cpp
winmm_main.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/inlinehook.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
PersistentString.cpp
)
if(ENABLE_STEAM_SUPPORT)
    list(APPEND Winmm_SOURCES steam.cpp)
    list(APPEND Winmm_SOURCES updater.cpp)
    list(APPEND Winmm_SOURCES ${PROJECT_SOURCE_DIR}/version.txt)
endif()

add_library(Winmm SHARED ${Winmm_SOURCES})

target_include_directories(Winmm PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR})

target_link_libraries(Winmm PRIVATE ZLIB::ZLIB)
target_link_libraries(Winmm PRIVATE spdlog::spdlog)
add_compile_definitions(NO_FRIDA_GUM=1)

file(STRINGS "${PROJECT_SOURCE_DIR}/version.txt" MOD_VERSION LIMIT_COUNT 1)

message(STATUS "MOD_VERSION: ${MOD_VERSION}")

target_compile_definitions(Winmm PRIVATE MOD_VERSION="${MOD_VERSION}")
if(ENABLE_STEAM_SUPPORT)
    target_compile_definitions(Winmm PRIVATE ENABLE_STEAM_SUPPORT=1)
    target_include_directories(Winmm PUBLIC ${STEAM_INCLUDE_DIR})
    target_link_libraries(Winmm PRIVATE ${STEAM_LIBRARIES})
endif()

install(TARGETS Winmm RUNTIME DESTINATION .)
