cmake_minimum_required(VERSION 3.15)

cmake_policy(SET CMP0091 NEW)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(GAME_NAME "Don't Starve Together")
#set(GAME_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(GAME_DIR "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Don't Starve Together")
if(WIN32)
    set(GAME_DIR "E:\\SteamLibrary\\steamapps\\common\\Don't Starve Together")
else(UNIX AND NOT APPLE)
    set(GAME_DIR "/home/ubuntu/.steam/steam/steamapps/common/Don't Starve Together")
endif()

file(REAL_PATH ${GAME_DIR} GAME_DIR)

set(PYTHON_EXECUTABLE_NAME "python3")
set(VCPKG_TARGET_TRIPLET "x64-linux-static")
if(WIN32)
    set(PLATFORM_NAME "windows")
    set(PYTHON_EXECUTABLE_NAME "python")
    set(VCPKG_TARGET_TRIPLET "x64-windows-static-md")
elseif(UNIX AND NOT APPLE)
    set(PLATFORM_NAME "Linux")
else()
    message(FATAL_ERROR "Not supported platform")
endif()

project(DontStarveLuaJIT VERSION 0.3.9)

set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/Mod)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(GAME_INSTALL_PREFIX ${GAME_DIR}/bin64)
    set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/bin64)
else()
    set(GAME_INSTALL_PREFIX ${GAME_DIR}/bin)
    set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/bin)
endif()

set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/${PLATFORM_NAME})

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/missfunc.h 
    COMMAND ${PYTHON_EXECUTABLE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/tools/missfunc.py"
    DEPENDS src/missfunc.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

add_custom_target(create_missfuncs DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/missfunc.h)

set(lua51_root ${CMAKE_CURRENT_SOURCE_DIR}/src/lua51)
set(Lua51_output_dir ${lua51_root}/$<IF:$<CONFIG:Debug>,debug,release>/)

add_custom_command(OUTPUT ${Lua51_output_dir}/lua51.dll ${Lua51_output_dir}/lua51.lib
    COMMAND ${lua51_root}/build_lua51.bat Build $<$<CONFIG:Debug>:debug>
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

add_custom_target(build_lua51 DEPENDS ${Lua51_output_dir}/lua51${CMAKE_SHARED_LIBRARY_SUFFIX})
add_subdirectory("luajit")
set(LUAJIT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/luajit/src)
set(LUAJIT_LIBRARIES luajit-5.1)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(LUA_LIBRARIES_PREFIX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/x64)
else()
    set(LUA_LIBRARIES_PREFIX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif()

set(LUA_INCLUDE_DIR ${lua51_root}/src)
set(LUA_LIBRARIES_PATH ${CMAKE_INSTALL_PREFIX}/lua51${CMAKE_SHARED_LIBRARY_SUFFIX})
set(LUA_CONFIG_LIBRARIES_PATH ${LUA_LIBRARIES_PREFIX_PATH}/$<IF:$<CONFIG:Debug>,debug,release>/lua51.dll)
set(LUA_LIBRARIES lua51)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(Steam REQUIRED)
find_package(Frida-gum REQUIRED)

set(DONTSTARVEINJECTOR_ROOT ${PROJECT_SOURCE_DIR}/src/DontStarveInjector)
set(DONTSTARVEINJECTOR_UTIL_DIR ${DONTSTARVEINJECTOR_ROOT}/util)


add_subdirectory("src/DontStarveInjector")
if(msvc)
    add_subdirectory("tools/Checker")
endif()
add_subdirectory("tools/Creater")

#install(FILES ${LUA_CONFIG_LIBRARIES_PATH} DESTINATION ${CMAKE_INSTALL_PREFIX}
#install(FILES ${LUA_LIBRARIES_PATH} DESTINATION ${CMAKE_INSTALL_PREFIX})
install(DIRECTORY ${CMAKE_INSTALL_PREFIX}/ DESTINATION ${GAME_INSTALL_PREFIX})


add_custom_target(make_karta_luamodule 
    COMMAND ${PYTHON_EXECUTABLE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/tools/make_karta.py"
    DEPENDS ${LUA_LIBRARIES_PATH}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
