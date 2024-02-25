find_package(libzip CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

set (Winmm_SOURCES
winmm.cpp
winmm_main.cpp
updater.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/inlinehook.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
steam.cpp
PersistentString.cpp
${PROJECT_SOURCE_DIR}/version.txt
)
add_library(Winmm SHARED ${Winmm_SOURCES})

target_include_directories(Winmm PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR})
target_include_directories(Winmm PUBLIC ${STEAM_INCLUDE_DIR})
target_link_libraries(Winmm PRIVATE ${STEAM_LIBRARIES})

target_link_libraries(Winmm PRIVATE ZLIB::ZLIB)
target_link_libraries(Winmm PRIVATE spdlog::spdlog)
add_compile_definitions(NO_FRIDA_GUM=1)

file(STRINGS "${PROJECT_SOURCE_DIR}/version.txt" MOD_VERSION LIMIT_COUNT 1)

message(STATUS "MOD_VERSION: ${MOD_VERSION}")

target_compile_definitions(Winmm PRIVATE MOD_VERSION="${MOD_VERSION}")

install(TARGETS Winmm RUNTIME DESTINATION .)

