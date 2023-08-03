option(ENABLE_FAKE_API "check inejctor hook lua func" OFF)

set (SOURCES
DontStarveInjector.cpp
winmm.cpp
lua_fake.cpp
inlinehook.cpp
gameio.cpp
zipfile.cpp
module.cpp
signature.cpp
)

find_package(libzip CONFIG REQUIRED)

set(ONLY_LUA51 1)
set(USE_LISTENER 0)

add_library(Winmm SHARED ${SOURCES})

target_include_directories(Winmm PUBLIC ${PROJECT_SOURCE_DIR}/src/frida-gum)
target_link_directories(Winmm PUBLIC ${PROJECT_SOURCE_DIR}/src/frida-gum)
target_link_libraries(Winmm PRIVATE frida-gum)

target_include_directories(Winmm PUBLIC ${PROJECT_SOURCE_DIR}/luajit/src)
target_link_directories(Winmm PUBLIC ${PROJECT_SOURCE_DIR}/luajit/src)
target_link_libraries(Winmm PRIVATE libzip::zip)

target_include_directories(Winmm PUBLIC ${PROJECT_SOURCE_DIR}/src/steam)
target_link_directories(Winmm PUBLIC ${PROJECT_SOURCE_DIR}/src/steam/redistributable_bin/win64)
target_link_libraries(Winmm PRIVATE steam_api64)


if(NOT ONLY_LUA51)
    target_link_libraries(Winmm PRIVATE lua51DS)
endif()

target_compile_definitions(Winmm PUBLIC ONLY_LUA51=${ONLY_LUA51} USE_LISTENER=${USE_LISTENER})

if (MSVC)
    target_link_options(Winmm PUBLIC "/NODEFAULTLIB:LIBCMT")
endif()

if(ENABLE_FAKE_API)
    target_compile_definitions(Winmm PUBLIC ENABLE_FAKE_API)
endif(ENABLE_FAKE_API)

add_dependencies(Winmm create_missfuncs create_Signatures luajit)


install(TARGETS Winmm RUNTIME DESTINATION .)
