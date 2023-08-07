cmake_minimum_required(VERSION 3.15)

cmake_policy(SET CMP0091 NEW)

project(DontStarveLuaJIT VERSION 0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(GAME_NAME "Don't Starve Together")
set(GAME_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
file(REAL_PATH ${GAME_DIR} GAME_DIR)
set(GAME_INSTALL_PREFIX ${GAME_DIR}/bin64)
set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/Mod/bin64/windows/)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/missfunc.h 
    COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/tools/missfunc.py"
    DEPENDS src/missfunc.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

add_custom_target(create_missfuncs DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/missfunc.h)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/Signatures_client.hpp ${CMAKE_CURRENT_SOURCE_DIR}/src/Signatures_server.hpp
    COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/tools/Signature.py"
    DEPENDS src/missfunc.txt src/Signatures_client.txt src/Signatures_server.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

add_custom_target(create_Signatures DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/Signatures_client.hpp)


add_custom_target(make_karta_luamodule 
    COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/tools/make_karta.py"
    DEPENDS src/lua51/Release/lua51.dll
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )


set(LUAJIT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/LuaJIT/src)

set(LUAJIT_SOURCE)

file(GLOB_RECURSE LUAJIT_SOURCE "${LUAJIT_DIR}/*.c")

set(LUAJIT_PRODUCT ${LUAJIT_DIR}/lua51DS.dll)

add_custom_command(OUTPUT ${LUAJIT_PRODUCT}
    COMMAND cmd /K msvcbuild.bat $<$<CONFIG:Debug>:debug>
    WORKING_DIRECTORY ${LUAJIT_DIR}
    DEPENDS ${LUAJIT_SOURCE}
)

add_custom_target(build_luajit DEPENDS ${LUAJIT_PRODUCT})

set(Lua51_output_dir ${PROJECT_SOURCE_DIR}/src/lua51/$<IF:$<CONFIG:Debug>,debug,release>/)

add_custom_command(OUTPUT ${Lua51_output_dir}/lua51.dll ${Lua51_output_dir}/lua51.lib
    COMMAND src/build_lua51.bat Build $<$<CONFIG:Debug>:debug>
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

add_custom_target(build_lua51 DEPENDS ${LUAJIT_PRODUCT})


add_subdirectory("src/DontStarveInjector")
add_subdirectory("tools/Checker")
add_subdirectory("tools/mod_packer")

install(FILES ${LUAJIT_PRODUCT} DESTINATION ${CMAKE_INSTALL_PREFIX})
#install(FILES src/lua51/$<IF:$<CONFIG:Debug>,debug,release>/lua51.dll DESTINATION ${CMAKE_INSTALL_PREFIX})
install(FILES src/lua51/release/lua51.dll DESTINATION ${CMAKE_INSTALL_PREFIX})
install(DIRECTORY ${CMAKE_INSTALL_PREFIX} DESTINATION ${GAME_INSTALL_PREFIX})

