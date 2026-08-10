cmake_minimum_required(VERSION 3.15)

cmake_policy(SET CMP0091 NEW)
# file(GET_RUNTIME_DEPENDENCIES): normalize paths before regex match (CMake 4.3+)
if(POLICY CMP0207)
    cmake_policy(SET CMP0207 NEW)
endif()

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
set(FRIDA_GUM_VERSION "17.17.0")
set(VCPKG_INSTALL_OPTION "${VCPKG_INSTALL_OPTION} --x-abi-tools-use-exact-versions")

file(REAL_PATH ${GAME_DIR} GAME_DIR)

set(PYTHON_EXECUTABLE_NAME "python3")
set(VCPKG_OVERLAY_TRIPLETS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/custom-triplets")
if (WIN32)
    set(PLATFORM_NAME "windows")
    set(PYTHON_EXECUTABLE_NAME "python")
    set(VCPKG_TARGET_TRIPLET "x64-windows-custom")
elseif (UNIX AND NOT APPLE)
    set(PLATFORM_NAME "linux")
    set(VCPKG_TARGET_TRIPLET "x64-linux-custom")
elseif (UNIX AND APPLE)
    set(PLATFORM_NAME "osx")
    set(VCPKG_TARGET_TRIPLET "x64-osx-custom")
else ()
    message(FATAL_ERROR "Not supported platform")
endif ()

project(DontStarveLuaJIT VERSION 3.0.0)

message(STATUS "CMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "VCPKG_TARGET_TRIPLET=${VCPKG_TARGET_TRIPLET}")
message(STATUS "VCPKG_INSTALLED_DIR=${VCPKG_INSTALLED_DIR}")


# Third-party shared runtimes are staged only under Mod/deps (bootstrap +
# PluginPath AddDllDirectory). Disable vcpkg applocal so link does not dump
# spdlog/fmt/zip/… next to Injector.dll or plugin_*.dll under plugins/.
set(VCPKG_APPLOCAL_DEPS OFF CACHE BOOL
    "Copy vcpkg DLLs next to targets (OFF: stage via Mod/deps only)" FORCE)
option(DISABLE_TRACY_FUTURE "disable tray future" ON)

# Package root = Mod/. All install destinations are relative to this prefix.
#   .                      → Injector.* (all platforms)
#   plugins/               → plugin_*.dll
#   deps/                  → third-party + lua51* + signatures_*.json
#   bin64/<platform>/      → thin shell only (Winmm / InjectorStub)
# Never use absolute DESTINATION with unset vars (install(CODE [[]]) won't expand them → /deps).
set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/Mod CACHE PATH "Mod package root" FORCE)
set(TARGET_MOD_DIR ${CMAKE_INSTALL_PREFIX})
set(DS_MOD_ROOT_ABS ${CMAKE_INSTALL_PREFIX})
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(DS_INSTALL_SHELL_DIR "bin64/${PLATFORM_NAME}")
else ()
    set(DS_INSTALL_SHELL_DIR "bin/${PLATFORM_NAME}")
endif ()
if (UNIX AND APPLE)
    set(GAME_INSTALL_PREFIX ${GAME_DIR}/MacOs)
else ()
    if (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(GAME_INSTALL_PREFIX ${GAME_DIR}/bin64)
    else ()
        set(GAME_INSTALL_PREFIX ${GAME_DIR}/bin)
    endif ()
endif ()
# Keep a cache-visible alias for scripts that still mention platform package dir.
set(DS_INSTALL_SHELL_ABS "${CMAKE_INSTALL_PREFIX}/${DS_INSTALL_SHELL_DIR}")
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

function(setup_frida_gum version)
    message(STATUS "Setting up shared Frida-Gum version ${version}...")
    set(_setup_args "-v=${version}")

    # Platform stage dir (mirrors tools/setup_frida_gum.py map_plat).
    if (WIN32)
        set(_ds_gum_plat "win64")
    elseif (APPLE)
        set(_ds_gum_plat "osx")
    else()
        set(_ds_gum_plat "linux64")
    endif()
    set(_ds_gum_stage "${CMAKE_CURRENT_SOURCE_DIR}/3rd/frida-gum/${_ds_gum_plat}")
    set(_ds_gum_legacy "${CMAKE_CURRENT_SOURCE_DIR}/3rd/frida-gum/_legacy_${_ds_gum_plat}")
    set(_ds_gum_input "${CMAKE_CURRENT_SOURCE_DIR}/3rd/frida-gum-build/input")

    set(_ds_gum_force_meson FALSE)
    if (DEFINED ENV{DS_FRIDA_GUM_FORCE_MESON} AND NOT "$ENV{DS_FRIDA_GUM_FORCE_MESON}" STREQUAL "")
        set(_ds_gum_force_meson TRUE)
    endif()

    set(_ds_gum_skip FALSE)
    if (DEFINED ENV{DS_FRIDA_GUM_SKIP_MESON} AND NOT "$ENV{DS_FRIDA_GUM_SKIP_MESON}" STREQUAL "")
        set(_ds_gum_skip TRUE)
    endif()

    # Auto skip when a valid stage marker already exists, or durable static inputs are present.
    # Full meson only when forced or when no skip inputs exist.
    if (NOT _ds_gum_force_meson)
        if (EXISTS "${_ds_gum_stage}/version-${version}.txt")
            set(_ds_gum_skip TRUE)
            message(STATUS "Frida-Gum: stage marker present; using --skip-meson (set DS_FRIDA_GUM_FORCE_MESON=1 to rebuild via meson)")
        elseif (
            (EXISTS "${_ds_gum_legacy}/frida-gum.lib" OR EXISTS "${_ds_gum_legacy}/libfrida-gum.a")
            AND (EXISTS "${_ds_gum_legacy}/frida-gum.h" OR EXISTS "${_ds_gum_legacy}/include/frida-gum.h")
        )
            set(_ds_gum_skip TRUE)
            message(STATUS "Frida-Gum: durable legacy static archive found; using --skip-meson")
        elseif (
            (EXISTS "${_ds_gum_input}/frida-gum.lib" OR EXISTS "${_ds_gum_input}/libfrida-gum.a")
            AND EXISTS "${_ds_gum_input}/frida-gum.h"
        )
            set(_ds_gum_skip TRUE)
            message(STATUS "Frida-Gum: frida-gum-build/input static archive found; using --skip-meson")
        elseif (
            (EXISTS "${_ds_gum_stage}/frida-gum.lib" OR EXISTS "${_ds_gum_stage}/libfrida-gum.a")
            AND (EXISTS "${_ds_gum_stage}/frida-gum.h")
        )
            # Pre-restage flat legacy under stage root (static, not import lib).
            set(_ds_gum_skip TRUE)
            message(STATUS "Frida-Gum: flat stage static archive found; using --skip-meson")
        endif()
    else()
        message(STATUS "Frida-Gum: DS_FRIDA_GUM_FORCE_MESON set; full meson path")
    endif()

    if (_ds_gum_skip AND NOT _ds_gum_force_meson)
        list(APPEND _setup_args "--skip-meson")
    endif()

    execute_process(
        COMMAND ${PYTHON_EXECUTABLE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/tools/setup_frida_gum.py" ${_setup_args}
        RESULT_VARIABLE setup_result
        OUTPUT_VARIABLE setup_stdout
        ERROR_VARIABLE setup_stderr
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    if (setup_stdout)
        message("${setup_stdout}")
    endif()
    if (setup_stderr)
        message(STATUS "${setup_stderr}")
    endif()
    if (NOT setup_result EQUAL 0)
        message(FATAL_ERROR
            "Failed to set up Frida-Gum. Run: ${PYTHON_EXECUTABLE_NAME} tools/setup_frida_gum.py -v ${version}\n"
            "Or stage with --skip-meson using a durable static archive + header "
            "(3rd/frida-gum/_legacy_<plat>/ or --static-lib), then reconfigure.\n"
            "Set DS_FRIDA_GUM_FORCE_MESON=1 to force a full meson build.")
    else()
        message(STATUS "Frida-Gum setup completed.")
    endif()
endfunction()

function(setup_angle)
    if (NOT WIN32)
        return()
    endif ()
    message(STATUS "Setting up prebuilt ANGLE...")
    set(_angle_setup_args "")
    if ((DEFINED ENV{GITHUB_ACTIONS} AND NOT "$ENV{GITHUB_ACTIONS}" STREQUAL "")
            OR (DEFINED ENV{CI} AND NOT "$ENV{CI}" STREQUAL ""))
        list(APPEND _angle_setup_args "--release-only")
    endif ()
    execute_process(
            COMMAND ${PYTHON_EXECUTABLE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/tools/setup_angle.py" ${_angle_setup_args}
            RESULT_VARIABLE angle_setup_result
            OUTPUT_VARIABLE angle_setup_stdout
            ERROR_VARIABLE angle_setup_stderr
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    if (angle_setup_stdout)
        message("${angle_setup_stdout}")
    endif ()
    if (angle_setup_stderr)
        message(STATUS "${angle_setup_stderr}")
    endif ()
    if (NOT angle_setup_result EQUAL 0)
        message(FATAL_ERROR
                "Failed to set up ANGLE. Run: ${PYTHON_EXECUTABLE_NAME} tools/setup_angle.py\n"
                "Or stage from an existing install with --from-prefix.")
    else ()
        message(STATUS "ANGLE setup completed.")
    endif ()
endfunction()
setup_angle()
setup_frida_gum(${FRIDA_GUM_VERSION})


set(LUA_INCLUDE_DIR ${lua51_root}/src)
if (MSVC)
    set(LUA_LIBRARIES_PATH ${CMAKE_INSTALL_PREFIX}/deps/${CMAKE_SHARED_LIBRARY_PREFIX}lua51${CMAKE_SHARED_LIBRARY_SUFFIX})
    set(LUA_EXECUTABLE_PATH ${CMAKE_INSTALL_PREFIX}/deps/lua51)
elseif (APPLE)
    set(LUA_EXECUTABLE_PATH ${CMAKE_INSTALL_PREFIX}/deps/lua51)
    set(LUA_LIBRARIES_PATH ${CMAKE_INSTALL_PREFIX}/deps/${CMAKE_SHARED_LIBRARY_PREFIX}lua51${CMAKE_SHARED_LIBRARY_SUFFIX})
else ()
    set(LUA_LIBRARIES_PATH ${CMAKE_INSTALL_PREFIX}/deps/${CMAKE_SHARED_LIBRARY_PREFIX}lua51${CMAKE_SHARED_LIBRARY_SUFFIX})
    set(LUA_EXECUTABLE_PATH ${CMAKE_INSTALL_PREFIX}/deps/lua51)
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

# core.vm assets:
#   Mod/deps/              → lua51* VMs + third-party shared runtimes
#   Mod/signatures_*.json  → signature DBs at mod root (all platforms)
# (sibling of plugins/; loadlib resolves deps; SignatureJson resolves mod root).
set(DS_CORE_VM_DEPS_DEST "deps")  # under DS_MOD_ROOT_ABS
if (TARGET liblua)
    # lua51Original already installed by src/lua51original; ensure dest matches.
endif()
# LuaJIT variants (lua51DS / gengc) — install runtime artifacts into Mod/deps.
if (TARGET libluajit OR TARGET luajit)
    # Targets vary by luajit CMake; install known output names from build tree.
endif()
# Signatures: ONLY Mod/signatures_{client,server}.json → install to mod root.
# No bin64/<plat>/ or deps/ fallbacks (Windows/Linux/macOS same).
set(_ds_sig_client "${CMAKE_SOURCE_DIR}/Mod/signatures_client.json")
set(_ds_sig_server "${CMAKE_SOURCE_DIR}/Mod/signatures_server.json")
if (EXISTS "${_ds_sig_client}")
    install(FILES "${_ds_sig_client}" DESTINATION . COMPONENT plugins)
else()
    message(FATAL_ERROR "Mod/signatures_client.json missing — regenerate with signature_updater")
endif()
if (EXISTS "${_ds_sig_server}")
    install(FILES "${_ds_sig_server}" DESTINATION . COMPONENT plugins)
else()
    message(FATAL_ERROR "Mod/signatures_server.json missing — regenerate with signature_updater")
endif()

# Install lua VM shared libs into Mod/deps when targets exist.
foreach(_ds_lua_tgt IN ITEMS liblua lua51DS lua51DS_gengc lua51DS_arenagc)
    if (TARGET ${_ds_lua_tgt})
        install(TARGETS ${_ds_lua_tgt}
            RUNTIME DESTINATION deps COMPONENT plugins
            LIBRARY DESTINATION deps COMPONENT plugins)
    endif()
endforeach()
# Training / stock lua51.dll + multi-config LuaJIT VMs → Mod/deps only.
# IMPORTANT: only stage the *active* install config's VMs into Mod/deps.
# Iterating Debug after RelWithDebInfo previously overwrote release lua51DS.dll
# with a Debug-CRT binary (ucrtbased) → LoadLibrary 0x7E under normal game launch.
if (WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/src/lua51")
    install(CODE "
      set(_ds_deps \"\${CMAKE_INSTALL_PREFIX}/deps\")
      file(MAKE_DIRECTORY \"\${_ds_deps}\")
      # Active multi-config name (Debug / Release / RelWithDebInfo / …)
      set(_ds_cfg \"\${CMAKE_INSTALL_CONFIG_NAME}\")
      if(NOT _ds_cfg)
        set(_ds_cfg RelWithDebInfo)
      endif()
      # Map multi-config → src/lua51 batch folders (debug|release).
      # Prefer matching config, then the other batch, then already-staged Mod/deps.
      set(_ds_lua51_cfg \"release\")
      if(_ds_cfg MATCHES \"^[Dd][Ee][Bb][Uu][Gg]$\")
        set(_ds_lua51_cfg debug)
      endif()
      set(_ds_lua51_src \"\")
      foreach(_cand IN ITEMS
          \"${CMAKE_SOURCE_DIR}/src/lua51/\${_ds_lua51_cfg}/lua51.dll\"
          \"${CMAKE_SOURCE_DIR}/src/lua51/release/lua51.dll\"
          \"${CMAKE_SOURCE_DIR}/src/lua51/debug/lua51.dll\"
          \"${CMAKE_SOURCE_DIR}/Mod/deps/lua51.dll\")
        if(EXISTS \"\${_cand}\")
          set(_ds_lua51_src \"\${_cand}\")
          break()
        endif()
      endforeach()
      if(_ds_lua51_src)
        file(INSTALL \"\${_ds_lua51_src}\" DESTINATION \"\${_ds_deps}\")
        message(STATUS \"ds_mod_deps: installed lua51.dll from \${_ds_lua51_src}\")
      else()
        message(FATAL_ERROR \"ds_mod_deps: lua51.dll not found under src/lua51/{debug,release} or Mod/deps. Build it first (target build_lua51 / src/lua51/build_lua51.bat).\")
      endif()
      # LuaJIT / original VMs for the active config only (no cross-config overwrite).
      foreach(_name IN ITEMS lua51DS.dll lua51DS_gengc.dll lua51Original.dll)
        set(_ds_picked \"\")
        foreach(_root IN ITEMS
            \"${CMAKE_BINARY_DIR}/luajit/\${_ds_cfg}\"
            \"${CMAKE_BINARY_DIR}/src/lua51original/\${_ds_cfg}\")
          if(EXISTS \"\${_root}/\${_name}\")
            set(_ds_picked \"\${_root}/\${_name}\")
            break()
          endif()
        endforeach()
        if(_ds_picked)
          file(INSTALL \"\${_ds_picked}\" DESTINATION \"\${_ds_deps}\")
        endif()
      endforeach()
    " COMPONENT plugins)
endif()


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
# Package staging (CMAKE_INSTALL_PREFIX = Mod/):
#   .                 → Injector.*
#   plugins/          → plugin_*.dll
#   deps/             → third-party + lua51* + signatures_*.json
#   bin64/<plat>/     → thin shell only (Winmm / InjectorStub)
# Live game install: ONLY the inject shell (Winmm / POSIX InjectorStub).
#
# Dual libInjector destinations (shell kept; real never mirrored to game):
#   real → package root libInjector.so|.dylib
#   Linux stub → package lib64/libInjector.so  (game PRELOAD path)
#   macOS stub → package shell/libInjector.dylib
if (GAME_DIR)
    if (WIN32)
        # Explicit shell only — never mirror the whole package into game bin64.
        # Winmm target is defined under src/DontStarveInjector/loader (WIN32).
        install(FILES $<TARGET_FILE:Winmm>
                DESTINATION ${GAME_INSTALL_PREFIX}
                COMPONENT injector_shell)
    elseif (TARGET InjectorStub)
        # Install the already-built stub into the live game tree only.
        # Package-side stub install remains on the InjectorStub target rules
        # (lib64/ or shell/) under CMAKE_INSTALL_PREFIX for mod packaging.
        if (UNIX AND NOT APPLE)
            install(FILES $<TARGET_FILE:InjectorStub>
                    DESTINATION ${GAME_INSTALL_PREFIX}/lib64
                    COMPONENT injector_shell
                    RENAME libInjector.so)
        elseif (APPLE)
            install(FILES $<TARGET_FILE:InjectorStub>
                    DESTINATION ${GAME_INSTALL_PREFIX}
                    COMPONENT injector_shell
                    RENAME libInjector.dylib)
        endif ()
    endif ()
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
