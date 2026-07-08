cmake_minimum_required(VERSION 3.15)

cmake_policy(SET CMP0091 NEW)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(GAME_NAME "Don't Starve Together")
if (WIN32)
    set(GAME_DIR "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Don't Starve Together")
elseif (UNIX AND NOT APPLE)
    set(GAME_DIR "/root/server_dst")
elseif (APPLE)
    set(GAME_DIR "/Users/fesil/Library/Application Support/Steam/steamapps/common/Don't Starve Together/dontstarve_steam.app/Contents")
endif ()
include(cmake/GameDir.cmake OPTIONAL)
enable_testing()
set(FRIDA_GUM_VERSION "17.5.1")
set(VCPKG_INSTALL_OPTION "${VCPKG_INSTALL_OPTION} --x-abi-tools-use-exact-versions")

file(REAL_PATH ${GAME_DIR} GAME_DIR)

set(PYTHON_EXECUTABLE_NAME "python3")
set(VCPKG_TARGET_TRIPLET "x64-linux-release")
if (WIN32)
    set(PLATFORM_NAME "windows")
    set(PYTHON_EXECUTABLE_NAME "python")
    set(VCPKG_OVERLAY_TRIPLETS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/custom-triplets")
    set(VCPKG_TARGET_TRIPLET "x64-windows-custom")
elseif (UNIX AND NOT APPLE)
    set(PLATFORM_NAME "linux")
elseif (UNIX AND APPLE)
    set(PLATFORM_NAME "osx")
    set(VCPKG_TARGET_TRIPLET "x64-osx-release")
else ()
    message(FATAL_ERROR "Not supported platform")
endif ()

project(DontStarveLuaJIT VERSION 2.9.0)

message(STATUS "CMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "VCPKG_TARGET_TRIPLET=${VCPKG_TARGET_TRIPLET}")
message(STATUS "VCPKG_INSTALLED_DIR=${VCPKG_INSTALLED_DIR}")

option(DISABLE_TRACY_FUTURE "disable tray future" ON)

set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/Mod)
set(TARGET_MOD_DIR ${CMAKE_INSTALL_PREFIX})
if (UNIX AND APPLE)
    set(GAME_INSTALL_PREFIX ${GAME_DIR}/MacOs)
    set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/bin64)
else ()
    if (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(GAME_INSTALL_PREFIX ${GAME_DIR}/bin64)
        set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/bin64)
    else ()
        set(GAME_INSTALL_PREFIX ${GAME_DIR}/bin)
        set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/bin)
    endif ()
endif ()

set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/${PLATFORM_NAME})
if (UNIX AND NOT APPLE)
    set(CMAKE_INSTALL_LIBDIR "lib64")
elseif (UNIX AND APPLE)
    set(CMAKE_INSTALL_LIBDIR "../Library")
endif ()
if ($ENV{GITHUB_ACTIONS})
    set(GAME_DIR OFF)
endif ()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,defs")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-Bsymbolic-functions")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-Bsymbolic-functions")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,defs")
elseif (APPLE)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-undefined,error")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-undefined,error")
endif()

# --- LuaJIT variant registry (early setup) ---
# Include the descriptor module and register the LuaJIT variants before any
# consumer (modinfo command, add_subdirectory, etc.) references their target
# names. Registration is descriptor-only: it records target/output/include
# names but does NOT require the targets to exist yet.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/LuajitVariants.cmake)

luajit_register_variant(
    NAME default
    TARGET luajit-5.1
    EXECUTABLE luajit
    INCLUDE_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}/luajit/src
        ${CMAKE_CURRENT_BINARY_DIR}/luajit/variants/default
    OUTPUT_NAME lua51DS
)

luajit_register_variant(
    NAME gengc
    TARGET luajit-5.1-gengc
    EXECUTABLE luajit-gengc
    INCLUDE_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}/luajit/src
        ${CMAKE_CURRENT_BINARY_DIR}/luajit/variants/arenagc
    OUTPUT_NAME lua51DS_gengc
)

# Derive compatibility variables from the registry so downstream consumers
# no longer depend on raw target-name literals.  These are available from
# this point onward — before add_subdirectory(luajit) — because the
# descriptor is just metadata.
luajit_get_variant_property(LUAJIT_INCLUDE_DIR default INCLUDE_DIR)
luajit_get_variant_property(LUAJIT_LIBRARIES  default TARGET)
luajit_get_variant_property(LUAJIT_EXECUTABLE_TARGET default EXECUTABLE)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/missfunc.h
        COMMAND ${PYTHON_EXECUTABLE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/tools/missfunc.py"
        DEPENDS src/missfunc.txt
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(create_missfuncs DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/missfunc.h)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/modinfo.hpp
        COMMAND $<TARGET_FILE:${LUAJIT_EXECUTABLE_TARGET}> "${CMAKE_CURRENT_SOURCE_DIR}/tools/modinfo2cpp.lua"
        DEPENDS ${LUAJIT_EXECUTABLE_TARGET} ${CMAKE_CURRENT_SOURCE_DIR}/Mod/modinfo.lua ${CMAKE_CURRENT_SOURCE_DIR}/tools/modinfo2cpp.lua
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(create_modinfo_hpp DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/modinfo.hpp)

set(lua51_root ${CMAKE_CURRENT_SOURCE_DIR}/src/lua51)
set(Lua51_output_dir ${lua51_root}/$<IF:$<CONFIG:Debug>,debug,release>/)

add_custom_command(OUTPUT ${Lua51_output_dir}/lua51.dll ${Lua51_output_dir}/lua51.lib
        COMMAND ${lua51_root}/build_lua51.bat Build $<$<CONFIG:Debug>:debug>
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(build_lua51 DEPENDS ${Lua51_output_dir}/lua51${CMAKE_SHARED_LIBRARY_SUFFIX})

add_subdirectory("luajit")

# Bridge the reverted inner arenagc targets to the public gengc contract.
if(TARGET luajit-5.1-arenagc)
    set_target_properties(luajit-5.1-arenagc PROPERTIES
        OUTPUT_NAME lua51DS_gengc)
    if(NOT TARGET luajit-5.1-gengc)
        add_custom_target(luajit-5.1-gengc
            DEPENDS luajit-5.1-arenagc)
    endif()

    file(GENERATE
        OUTPUT "${CMAKE_BINARY_DIR}/$<CONFIG>/luajit_gengc_target_file_name.txt"
        CONTENT "$<TARGET_FILE_NAME:luajit-5.1-arenagc>\n")
endif()

if(TARGET luajit-arenagc AND NOT TARGET luajit-gengc)
    add_custom_target(luajit-gengc
        DEPENDS luajit-arenagc)
endif()

# Post-add_subdirectory assertions: verify the registered target and
# executable names actually exist.  This catches descriptor/target drift
# early instead of letting downstream consumers fail with obscure errors.
if(NOT TARGET luajit-5.1)
    message(FATAL_ERROR
        "LuaJIT variant 'default': registered TARGET 'luajit-5.1' "
        "does not exist after add_subdirectory(luajit)")
endif()
if(NOT TARGET luajit)
    message(FATAL_ERROR
        "LuaJIT variant 'default': registered EXECUTABLE 'luajit' "
        "does not exist after add_subdirectory(luajit)")
endif()
if(NOT TARGET luajit-5.1-gengc)
    message(FATAL_ERROR
        "LuaJIT variant 'gengc': registered TARGET 'luajit-5.1-gengc' "
        "does not exist after add_subdirectory(luajit)")
endif()
if(NOT TARGET luajit-gengc)
    message(FATAL_ERROR
        "LuaJIT variant 'gengc': registered EXECUTABLE 'luajit-gengc' "
        "does not exist after add_subdirectory(luajit)")
endif()

# Generate the variant contract file consumed by the characterization test
# (tests/luajit_variant_registry_test.cmake).
luajit_generate_variant_contract(${CMAKE_BINARY_DIR}/luajit_variant_contract.txt)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(LUA_LIBRARIES_PREFIX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/x64)
else ()
    set(LUA_LIBRARIES_PREFIX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif ()

function(download_frida_gum version)
    message(STATUS "Downloading Frida-Gum version ${version}...")
    execute_process(
            COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tools/download_frida_gum.py" "-v=${version}" 
            RESULT_VARIABLE download_result 
            OUTPUT_VARIABLE download_stdout
            ERROR_VARIABLE download_stderr
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    if(download_stdout)
        message("${download_stdout}")
    endif()
    if(download_stderr)
        message(STATUS "${download_stderr}")
    endif()
    if (NOT download_result EQUAL 0)
        message(FATAL_ERROR "Failed to download Frida-Gum. Please check your internet connection or the version specified.")
    else()
        message(STATUS "Frida-Gum downloaded successfully.")
    endif ()
endfunction()
download_frida_gum(${FRIDA_GUM_VERSION})


set(LUA_INCLUDE_DIR ${lua51_root}/src)
if (MSVC)
    set(LUA_LIBRARIES_PATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_SHARED_LIBRARY_PREFIX}lua51${CMAKE_SHARED_LIBRARY_SUFFIX})
    set(LUA_EXECUTABLE_PATH ${CMAKE_INSTALL_PREFIX}/lua51)
elseif (APPLE)
    set(LUA_EXECUTABLE_PATH ${CMAKE_INSTALL_PREFIX}/lua51)
    set(LUA_LIBRARIES_PATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_SHARED_LIBRARY_PREFIX}lua51${CMAKE_SHARED_LIBRARY_SUFFIX})
else ()
    set(LUA_LIBRARIES_PATH ${CMAKE_INSTALL_PREFIX}/lib64/${CMAKE_SHARED_LIBRARY_PREFIX}lua51${CMAKE_SHARED_LIBRARY_SUFFIX})
    set(LUA_EXECUTABLE_PATH ${CMAKE_INSTALL_PREFIX}/lib64/lua51)
endif ()
set(LUA_CONFIG_LIBRARIES_PATH ${LUA_LIBRARIES_PREFIX_PATH}/$<IF:$<CONFIG:Debug>,debug,release>/lua51.dll)
set(LUA_LIBRARIES lua51)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(Steam REQUIRED)
find_package(Frida-gum REQUIRED)
find_package(keystone REQUIRED)

set(DONTSTARVEINJECTOR_ROOT ${PROJECT_SOURCE_DIR}/src/DontStarveInjector)
set(DONTSTARVEINJECTOR_UTIL_DIR ${DONTSTARVEINJECTOR_ROOT}/util)

add_subdirectory("src/lua51original")

add_subdirectory("src/FunctionRelocation")
set(FUNCTION_RELOCATION_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/FunctionRelocation)

add_subdirectory("src/DontStarveInjector")
if (MSVC)
    add_subdirectory("tools/Checker")
endif ()
add_subdirectory("tools/Creater")
add_subdirectory("tools/PersistentString")
add_subdirectory("tests")

if (WIN32)
    add_custom_target(generate_angle_iat_apis
            COMMAND $<TARGET_FILE:angle_iat_api_generator>
            DEPENDS angle_iat_api_generator
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Generate ANGLE IAT API dependency list from game executables"
    )
endif ()

#install(FILES ${LUA_CONFIG_LIBRARIES_PATH} DESTINATION ${CMAKE_INSTALL_PREFIX}
#install(FILES ${LUA_LIBRARIES_PATH} DESTINATION ${CMAKE_INSTALL_PREFIX})
if (GAME_DIR)
    install(DIRECTORY ${CMAKE_INSTALL_PREFIX}/ DESTINATION ${GAME_INSTALL_PREFIX})
endif ()
set(BUILD_CMD ${PYTHON_EXECUTABLE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/tools/update_version.py")
execute_process(COMMAND ${CMAKE_COMMAND} -E env MOD_VERSION=${CMAKE_PROJECT_VERSION} ${BUILD_CMD}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(make_karta_luamodule
        COMMAND ${PYTHON_EXECUTABLE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/tools/make_karta.py"
        DEPENDS ${LUA_LIBRARIES_PATH}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(unzip_script_data
        COMMAND ${PYTHON_EXECUTABLE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/tools/unzip_script_data.py"
        DEPENDS ${LUA_LIBRARIES_PATH}
        WORKING_DIRECTORY ${GAME_DIR}
)
