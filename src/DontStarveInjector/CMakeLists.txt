option(ENABLE_FAKE_API "check inejctor hook lua func" OFF)
option(ENABLE_ONLY_LUA51 "load lua51.dll" OFF)
option(ENABLE_USE_LISTENER "use api listener" OFF)

set (SOURCES
DontStarveInjector.cpp
DontStarveSignature.cpp
lua_fake.cpp
inlinehook.cpp
gameio.cpp
zipfile.cpp
module.cpp
signature.cpp
SignatureJson.cpp
)

find_package(libzip CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

add_library(Injector SHARED ${SOURCES})

target_include_directories(Injector PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_directories(Injector PUBLIC ${FRIDA_GUM_LIBRARY_DIR})
target_link_libraries(Injector PRIVATE ${FRIDA_GUM_LIBRARIES})

target_link_libraries(Injector PRIVATE libzip::zip)
target_link_libraries(Injector PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(Injector PRIVATE spdlog::spdlog)

target_include_directories(Injector PUBLIC ${PROJECT_SOURCE_DIR}/src/steam)
target_link_directories(Injector PUBLIC ${PROJECT_SOURCE_DIR}/src/steam/redistributable_bin/win64)
target_link_libraries(Injector PRIVATE steam_api64)

if (NOT ENABLE_ONLY_LUA51)
    target_include_directories(Injector PUBLIC ${LUAJIT_INCLUDE_DIR})
    target_link_libraries(Injector PRIVATE ${LUAJIT_LIBRARIES})
elseif(ENABLE_FAKE_API)
    target_include_directories(Injector PUBLIC ${LUA_INCLUDE_DIR})
    target_link_directories(Injector PUBLIC ${PROJECT_SOURCE_DIR}/src/lua51/$<IF:$<CONFIG:Debug>,Debug,Release>)
    target_link_libraries(Injector PRIVATE ${LUA_LIBRARIES})
endif()

if (MSVC)
    target_link_options(Injector PUBLIC "/NODEFAULTLIB:LIBCMT")
endif()

if(ENABLE_FAKE_API)
    target_compile_definitions(Injector PUBLIC ENABLE_FAKE_API)
endif()

if(ENABLE_USE_LISTENER)
    target_compile_definitions(Injector PUBLIC ENABLE_USE_LISTENER)
endif()

if(ENABLE_ONLY_LUA51)
    target_compile_definitions(Injector PUBLIC ENABLE_ONLY_LUA51)
endif()

install(TARGETS Injector RUNTIME DESTINATION .)

set (Winmm_SOURCES
winmm.cpp
winmm_main.cpp
updater.cpp
inlinehook.cpp
module.cpp
steam.cpp
PersistentString.cpp
${PROJECT_SOURCE_DIR}/version.txt
)
add_library(Winmm SHARED ${Winmm_SOURCES})

target_include_directories(Winmm PUBLIC ${PROJECT_SOURCE_DIR}/src/steam)
target_link_directories(Winmm PUBLIC ${PROJECT_SOURCE_DIR}/src/steam/redistributable_bin/win64)
target_link_libraries(Winmm PRIVATE steam_api64)

target_link_libraries(Winmm PRIVATE ZLIB::ZLIB)
target_link_libraries(Winmm PRIVATE spdlog::spdlog)

file(STRINGS "${PROJECT_SOURCE_DIR}/version.txt" MOD_VERSION LIMIT_COUNT 1)

target_compile_definitions(Winmm PRIVATE MOD_VERSION="${MOD_VERSION}")

install(TARGETS Winmm RUNTIME DESTINATION .)

