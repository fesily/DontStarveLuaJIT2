find_package(libzip CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

option(ENABLE_STEAM_SUPPORT "Enable Steam support" OFF)
option(ENABLE_AUTOINSTALLER "Enable auto installer support" ON)

set (Winmm_SOURCES
winmm.cpp
winmm_main.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/inlinehook.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
PersistentString.cpp
updater.cpp
)
if(ENABLE_STEAM_SUPPORT)
    list(APPEND Winmm_SOURCES steam.cpp)
endif()

add_library(Winmm SHARED ${Winmm_SOURCES})

target_include_directories(Winmm PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR})

target_link_libraries(Winmm PRIVATE ZLIB::ZLIB)
target_link_libraries(Winmm PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(Winmm PRIVATE spdlog::spdlog)
add_compile_definitions(NO_FRIDA_GUM=1)

if(ENABLE_STEAM_SUPPORT)
    target_compile_definitions(Winmm PRIVATE ENABLE_STEAM_SUPPORT=1)
    target_include_directories(Winmm PUBLIC ${STEAM_INCLUDE_DIR})
    target_link_libraries(Winmm PRIVATE ${STEAM_LIBRARIES})
        
    if (ENABLE_AUTOINSTALLER)
        target_compile_definitions(Winmm PRIVATE ENABLE_AUTOINSTALLER=1)
    endif()
endif()

target_include_directories(Winmm PUBLIC ${LUAJIT_INCLUDE_DIR})
target_link_libraries(Winmm PRIVATE ${LUAJIT_LIBRARIES})
install(TARGETS Winmm RUNTIME DESTINATION .)
