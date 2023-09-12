cmake_minimum_required(VERSION 3.15)

cmake_policy(SET CMP0091 NEW)

project(DontStarveLuaJIT VERSION 0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(GAME_NAME "Don't Starve Together")
set(GAME_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
file(REAL_PATH ${GAME_DIR} GAME_DIR)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(GAME_INSTALL_PREFIX ${GAME_DIR}/bin64)
else()
    set(GAME_INSTALL_PREFIX ${GAME_DIR}/bin)
endif()

set(GAME_INSTALL_PREFIX ${GAME_DIR}/bin64)
set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/Mod/bin64/windows/)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/missfunc.h 
    COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/tools/missfunc.py"
    DEPENDS src/missfunc.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

add_custom_target(create_missfuncs DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/missfunc.h)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/Signatures_client.hpp ${CMAKE_CURRENT_SOURCE_DIR}/src/Signatures_server.hpp
    COMMAND ${CMAKE_COMMAND} -E env GAME_DIR=${GAME_DIR} python "${CMAKE_CURRENT_SOURCE_DIR}/tools/Signature.py" 
    DEPENDS src/missfunc.txt src/Signatures_client.txt src/Signatures_server.txt ${CMAKE_CURRENT_SOURCE_DIR}/tools/Signature.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

add_custom_target(create_Signatures DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/Signatures_client.hpp ${CMAKE_CURRENT_SOURCE_DIR}/src/Signatures_server.hpp)

set(Lua51_output_dir ${PROJECT_SOURCE_DIR}/src/lua51/$<IF:$<CONFIG:Debug>,debug,release>/)

add_custom_command(OUTPUT ${Lua51_output_dir}/lua51.dll ${Lua51_output_dir}/lua51.lib
    COMMAND src/build_lua51.bat Build $<$<CONFIG:Debug>:debug>
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

add_custom_target(build_lua51 DEPENDS ${Lua51_output_dir}/lua51.dll)
add_subdirectory("luajit")
set(LUAJIT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/luajit/src)
set(LUAJIT_LIBRARIES luajit-5.1)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(LUA_LIBRARIES_PREFIX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/x64)
else()
    set(LUA_LIBRARIES_PREFIX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif()

add_subdirectory("src/lua51")
set(LUA_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/lua51/src)
set(LUA_LIBRARIES_PATH ${LUA_LIBRARIES_PREFIX_PATH}/release/lua51.dll)
set(LUA_CONFIG_LIBRARIES_PATH ${LUA_LIBRARIES_PREFIX_PATH}/$<IF:$<CONFIG:Debug>,debug,release>/lua51.dll)
set(LUA_LIBRARIES lua51)

set(FRIDA_GUM_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/src/frida-gum)
set(FRIDA_GUM_LIBRARY_DIR ${FRIDA_GUM_INCLUDE_DIR})
set(FRIDA_GUM_LIBRARIES frida-gum)

add_subdirectory("src/DontStarveInjector")
add_subdirectory("tools/Checker")
add_subdirectory("tools/Creater")

#install(FILES ${LUA_CONFIG_LIBRARIES_PATH} DESTINATION ${CMAKE_INSTALL_PREFIX})
install(FILES ${LUA_LIBRARIES_PATH} DESTINATION ${CMAKE_INSTALL_PREFIX})
install(DIRECTORY ${CMAKE_INSTALL_PREFIX} DESTINATION ${GAME_INSTALL_PREFIX})


add_custom_target(make_karta_luamodule 
    COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/tools/make_karta.py"
    DEPENDS ${LUA_LIBRARIES_PATH}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
