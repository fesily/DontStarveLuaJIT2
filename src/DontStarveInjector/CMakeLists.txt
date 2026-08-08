option(ENABLE_FAKE_API "check inejctor hook lua func" OFF)
option(ENABLE_ONLY_LUA51 "load lua51.dll" OFF)
option(ENABLE_USE_LISTENER "use api listener" OFF)
option(ENABLE_STEAM_SUPPORT "Enable Steam support" ON)

set(SOURCES
        DontStarveInjector.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/inlinehook.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/gum_platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/lua51_object.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/PersistentString.cpp
        config/ConfigSession.cpp
        GameRuntimeApis.cpp
        config/sources/LuajitConfigFile.cpp
        game_info.cpp
        config/InjectorHostConfig.cpp
        core/PluginHost.cpp
        core/PluginServices.cpp
        core/GameInjectorLuaRegistry.cpp
        core/PluginOptionRules.cpp
        config/ConfigSchema.cpp
        config/CascadeEngine.cpp
        config/ConfigResolve.cpp
        config/path/ConfigPaths.cpp
        config/path/ModIdentity.cpp
        config/sources/ModinfoDefaultSource.cpp
        config/sources/LuajitConfigSource.cpp
        config/sources/SaveFileSource.cpp
        config/sources/ModOverridesSource.cpp
        config/sources/EnvOrCmdSource.cpp
        config/sources/SaveParse.cpp
        core/RegisterBuiltinPlugins.cpp
        core/PluginConfigBridge.cpp
        core/DynamicPluginLoader.cpp
        core/PluginPath.cpp
        core/PluginPendingUpdates.cpp
        core/CoreVmBootstrap.cpp
        core/PluginPackModinfo.cpp
)


if (ENABLE_STEAM_SUPPORT)
    list(APPEND SOURCES ${DONTSTARVEINJECTOR_UTIL_DIR}/steam.cpp)
    find_package(Steam REQUIRED)
endif ()

# GameForkSave lives in plugin_save_fork (all platforms). Gum is Frida::Gum shared.

find_package(libzip CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(range-v3 CONFIG REQUIRED)
find_package(Tracy CONFIG REQUIRED)
find_package(mimalloc CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS pfr)
find_package(slikenet CONFIG REQUIRED)

find_path(SOL2_INCLUDE_DIRS "sol/abort.hpp")
find_path(PLF_HIVE_INCLUDE_DIRS "plf_hive.h")

if (WIN32)
    find_package(unofficial-angle REQUIRED MODULE)
endif()

set(CMAKE_SKIP_BUILD_RPATH  FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

add_library(Injector SHARED ${SOURCES})
if (MSVC)
    target_compile_definitions(Injector PRIVATE SUPPORT_PROGRESS)
endif()
target_compile_definitions(Injector PRIVATE MOD_VERSION="${CMAKE_PROJECT_VERSION}")
target_compile_definitions(Injector PRIVATE DONTSTARVEINJECTOR_BUILD)
target_include_directories(Injector PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if (ENABLE_STEAM_SUPPORT)
    target_compile_definitions(Injector PRIVATE ENABLE_STEAM_SUPPORT)
    target_include_directories(Injector PUBLIC ${STEAM_INCLUDE_DIR})
    target_include_directories(Injector PUBLIC ${STEAM_SDK_INCLUDE_DIR})
    target_link_libraries(Injector PRIVATE ${STEAM_LIBRARIES})
    # add_library(GameSteamTest SHARED GameSteamTest.cpp)
    # target_include_directories(GameSteamTest PUBLIC ${STEAM_INCLUDE_DIR})
    # target_include_directories(GameSteamTest PUBLIC ${STEAM_SDK_INCLUDE_DIR})
    # target_link_libraries(GameSteamTest PRIVATE ${STEAM_LIBRARIES})
endif()

if (APPLE)
    # Real Injector is at mod root; deps live at mod/deps → $ORIGIN/deps.
    # Keep lib64 for any legacy shared layout still co-located with the module.
    set_target_properties(Injector PROPERTIES INSTALL_RPATH "$ORIGIN/deps")
    set_target_properties(Injector PROPERTIES BUILD_RPATH "$ORIGIN/deps")
else()
    set_target_properties(Injector PROPERTIES INSTALL_RPATH "$ORIGIN/deps")
    set_target_properties(Injector PROPERTIES BUILD_RPATH "$ORIGIN/deps")
endif()

add_dependencies(Injector create_missfuncs)
add_dependencies(Injector create_modinfo_hpp)

target_include_directories(Injector PRIVATE ${SOL2_INCLUDE_DIRS})
target_include_directories(Injector PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(Injector PRIVATE Frida::Gum)

target_link_libraries(Injector PRIVATE Boost::pfr)
target_link_libraries(Injector PRIVATE libzip::zip)
target_link_libraries(Injector PRIVATE ZLIB::ZLIB)
target_link_libraries(Injector PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(Injector PRIVATE spdlog::spdlog)
target_link_libraries(Injector PRIVATE range-v3::meta range-v3::concepts range-v3::range-v3)
target_link_libraries(Injector PRIVATE SLikeNet)
target_include_directories(Injector PRIVATE ${PLF_HIVE_INCLUDE_DIRS})
#target_link_libraries(Injector PRIVATE $<IF:$<TARGET_EXISTS:mimalloc-static>,mimalloc-static,mimalloc>)
if (NOT DISABLE_TRACY_FUTURE)
    target_link_libraries(Injector PRIVATE Tracy::TracyClient)
else()
    target_compile_definitions(Injector PRIVATE DISABLE_TRACY_FUTURE)
endif()
target_link_libraries(Injector PRIVATE function_relocation)
target_include_directories(Injector PUBLIC ${FUNCTION_RELOCATION_INCLUDE_DIR})

# L0 config cascade (save write-back + stock sol2) uses a dedicated PUC
# Lua 5.1 VM (src/lua51original → liblua_static). Do NOT link game LuaJIT here:
# core.vm owns the game VM; sol in GameLuaModule is GameDbg-specialized and lives
# only in plugin_core_vm.
#
# Headers: PRIVATE lua51original so Injector TUs (sol cascade
# incomplete type) see stock lua.h — not LUAJIT_INCLUDE_DIR (that stays on core.vm).
target_include_directories(Injector PRIVATE
    ${PROJECT_SOURCE_DIR}/src/lua51original/src
    ${CMAKE_BINARY_DIR}/src/lua51original  # generated luaconf.h if needed
)
# Prefer build-tree include for configured luaconf.h
if (TARGET liblua_static)
    # PRIVATE static embed: cascade-only VM. Symbols must not export from Injector
    # (liblua_static is built with hidden visibility on ELF).
    target_link_libraries(Injector PRIVATE liblua_static)
    add_dependencies(Injector liblua_static)
    if (NOT MSVC)
        # Defense in depth: do not re-export static lib symbols from Injector.so
        target_link_options(Injector PRIVATE "-Wl,--exclude-libs,ALL")
    endif()
else()
    message(FATAL_ERROR "liblua_static (src/lua51original) required for L0 config cascade")
endif()

# Optional legacy switches: macros only — do not re-link game JIT into L0.
if (ENABLE_ONLY_LUA51)
    target_compile_definitions(Injector PUBLIC ENABLE_ONLY_LUA51)
endif ()
if (ENABLE_FAKE_API)
    target_compile_definitions(Injector PUBLIC ENABLE_FAKE_API)
    target_include_directories(Injector PRIVATE ${LUA_INCLUDE_DIR})
endif ()
if (ENABLE_USE_LISTENER)
    target_compile_definitions(Injector PUBLIC ENABLE_USE_LISTENER)
endif ()

if (MSVC)
    target_link_options(Injector PUBLIC "/NODEFAULTLIB:LIBCMT")
endif ()

# Package layout (mod-local Injector bootstrap):
# - Real Injector installs to Mod root (all platforms): Mod root (.)/
#   e.g. Mod/Injector.dll, Mod/libInjector.so, Mod/libInjector.dylib
# - Thin shell only under bin64/<plat>/ under Mod:
#     Windows: Winmm.dll
#     Linux:   lib64/libInjector.so stub (game PRELOAD)
#     macOS:   shell/libInjector.dylib stub
# - plugins → Mod/plugins; deps → Mod/deps
# - game bin64 never receives real Injector / plugins / deps
install(TARGETS Injector
    RUNTIME DESTINATION . COMPONENT injector
    LIBRARY DESTINATION . COMPONENT injector)

if (DEFINED FRIDA_GUM_RUNTIME)
    install(FILES "${FRIDA_GUM_RUNTIME}" DESTINATION deps COMPONENT deps)
endif()

add_subdirectory(loader/bootstrap)

# POSIX game-side shell (libInjector.so/.dylib). Windows uses Winmm.
# Thin shell only: injector_bootstrap + libdl. No vcpkg/third-party shared libs.
# OUTPUT_NAME Injector → libInjector.*; dual destinations:
#   real Injector → package root (mod bin64)
#   stub          → lib64/ (Linux) or shell/ (macOS)
if (NOT WIN32)
    add_library(InjectorStub SHARED
        ${DONTSTARVEINJECTOR_ROOT}/loader/injector_stub.cpp)
    target_link_libraries(InjectorStub PRIVATE injector_bootstrap ${CMAKE_DL_LIBS})
    target_include_directories(InjectorStub PRIVATE ${DONTSTARVEINJECTOR_ROOT})
    target_compile_features(InjectorStub PRIVATE cxx_std_23)
    set_target_properties(InjectorStub PROPERTIES
        OUTPUT_NAME "Injector"
        PREFIX "lib"
        # Keep build-tree stub separate from real Injector output dir.
        LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/stub"
    )
    if (UNIX AND NOT APPLE)
        # Game PRELOAD path is bin64/lib64; package mirror under bin64/<plat>/lib64
        install(TARGETS InjectorStub LIBRARY DESTINATION "${DS_INSTALL_SHELL_DIR}/lib64" COMPONENT injector_shell)
    else()
        # macOS: do not install stub next to real libInjector.dylib at package root.
        install(TARGETS InjectorStub LIBRARY DESTINATION "${DS_INSTALL_SHELL_DIR}/shell" COMPONENT injector_shell)
    endif()
endif()

if (WIN32)
    add_subdirectory(loader)
endif ()

add_subdirectory(util)

# Dynamic plugin modules (Phase B). Build-tree output under Injector/plugins/<name>/;
# install to Mod/plugins/<name>/.
# Each plugin owns plugins/<name>/CMakeLists.txt; this file only defines the
# shared helper and orchestrates add_subdirectory.
#
# Install / package policy:
# - plugin package → plugins/<name>/  (DLL + optional modinfo/modmain/scripts)
# - shared runtimes + lua51* + signatures → deps/
# - Injector → Mod root (.); shell → bin64/<platform> under Mod
# - GAME_INSTALL_PREFIX: shell only; never plugin packages into game bin64
function(ds_add_dynamic_plugin name)
    add_library(${name} MODULE ${ARGN})
    # Plugin dir (CMAKE_CURRENT_SOURCE_DIR when called from plugins/<name>/)
    # plus Injector root so "config/InjectorHostConfig.hpp", "util/...", "core/..." resolve.
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${DONTSTARVEINJECTOR_ROOT}
        ${DONTSTARVEINJECTOR_UTIL_DIR})
    target_compile_features(${name} PRIVATE cxx_std_23)
    target_link_libraries(${name} PRIVATE Injector)
    # Multi-config generators (Ninja Multi-Config / VS) need per-config props;
    # bare RUNTIME_OUTPUT_DIRECTORY alone can leave stale flat plugins/plugin_*.dll.
    set_target_properties(${name} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${name}"
        RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        ARCHIVE_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        LIBRARY_OUTPUT_DIRECTORY_DEBUG "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        LIBRARY_OUTPUT_DIRECTORY_RELEASE "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        LIBRARY_OUTPUT_DIRECTORY_RELWITHDEBINFO "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        LIBRARY_OUTPUT_DIRECTORY_MINSIZEREL "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        ARCHIVE_OUTPUT_DIRECTORY_DEBUG "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        ARCHIVE_OUTPUT_DIRECTORY_RELEASE "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
        ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL "$<TARGET_FILE_DIR:Injector>/plugins/${name}"
    )
    # Package-local only (COMPONENT plugins). Not part of game bin64 deploy.
    # MODULE targets cannot take RUNTIME_DEPENDENCY_SET; third-party shared
    # ports are staged into Mod/deps via install(CODE)+GET_RUNTIME_DEPENDENCIES
    # below. VCPKG_APPLOCAL_DEPS is OFF so nothing is dumped next to plugin_*.
    install(TARGETS ${name}
        RUNTIME DESTINATION plugins/${name} COMPONENT plugins
        LIBRARY DESTINATION plugins/${name} COMPONENT plugins
        ARCHIVE DESTINATION plugins/${name} COMPONENT plugins)

    # Package Lua (optional files present in the plugin source dir)
    set(_pkg_lua_files "")
    foreach(_f IN ITEMS modinfo.lua modmain.lua)
        if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_f}")
            list(APPEND _pkg_lua_files "${CMAKE_CURRENT_SOURCE_DIR}/${_f}")
        endif()
    endforeach()
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/scripts")
        install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/scripts"
            DESTINATION plugins/${name}
            COMPONENT plugins
            FILES_MATCHING PATTERN "*.lua")
    endif()
    if (_pkg_lua_files)
        install(FILES ${_pkg_lua_files}
            DESTINATION plugins/${name}
            COMPONENT plugins)
    endif()
endfunction()


# Always-on / cross-platform plugins. Gum only for plugins that call gum/cs.
add_subdirectory(plugins/plugin_dummy)
add_subdirectory(plugins/plugin_save_fork)
add_subdirectory(plugins/plugin_core_vm)
target_link_libraries(plugin_core_vm PRIVATE Frida::Gum)
add_subdirectory(plugins/plugin_manager)

# Gum plugins link Frida::Gum shared directly (no Injector re-export; selective).
# Keep WIN32 gate until POSIX shared stage is verified in-tree.
if (WIN32)
    add_subdirectory(plugins/plugin_network_rpc)
    add_subdirectory(plugins/plugin_network_sim)
    add_subdirectory(plugins/plugin_sim_lagcomp)
    add_subdirectory(plugins/plugin_render_vbpool)
    add_subdirectory(plugins/plugin_render_angle)
    add_subdirectory(plugins/plugin_debug_profiler)
    add_subdirectory(plugins/plugin_fps_render)
    add_subdirectory(plugins/plugin_network_tick)
    # Gum-using plugins only — not dummy / manager / save_fork.
    foreach(_ds_gum_plugin IN ITEMS
            plugin_network_rpc
            plugin_network_sim
            plugin_sim_lagcomp
            plugin_render_vbpool
            plugin_render_angle
            plugin_debug_profiler
            plugin_fps_render
            plugin_network_tick)
        target_link_libraries(${_ds_gum_plugin} PRIVATE Frida::Gum)
    endforeach()
else()
    message(WARNING
        "Skipping gum-using dynamic plugins (network.rpc / network.sim / sim.lagcomp / render.vbpool / render.angle / debug.profiler / fps.render / network.tick): "
        "shared gum stage not available or unverified on Linux/macOS. "
        "Plugins link Frida::Gum directly once the stage is ready.")
endif()

# ---------------------------------------------------------------------------
# Shared runtimes → Mod/deps (sibling of Mod/plugins; NOT under bin64/<plat>/)
# ---------------------------------------------------------------------------
# Package: deps/
# Game bin64 never receives these (shell-only GAME_INSTALL_PREFIX rules).
#
# Debug install is first-class for local debugging: `cmake --install --config Debug`
# must stage debug vcpkg runtimes (spdlogd/fmtd/zlibd1/…) into the same Mod/deps
# next to release names. Seeds use $<TARGET_FILE:…> so GET_RUNTIME_DEPENDENCIES
# walks the installed config; search dirs include vcpkg debug/bin.
#
# Use install(CODE)+file(GET_RUNTIME_DEPENDENCIES) so PE/ELF imports that
# CMake TARGET_RUNTIME_DLLS misses (e.g. zlib1.dll via FindZLIB) still stage.
# function_relocation installs to the same Mod/deps.
# Exclude package-owned modules (Injector, plugins, lua51*) and OS/system libs.

set(_ds_mod_deps_search_dirs "")
if (DEFINED VCPKG_INSTALLED_DIR AND DEFINED VCPKG_TARGET_TRIPLET)
    if (WIN32)
        list(APPEND _ds_mod_deps_search_dirs
            "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin"
            "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/bin"
        )
    else()
        list(APPEND _ds_mod_deps_search_dirs
            "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib"
            "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/lib"
            "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin"
            "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/bin"
        )
    endif()
endif()
if (DEFINED FRIDA_GUM_LIBRARY_DIR)
    list(APPEND _ds_mod_deps_search_dirs "${FRIDA_GUM_LIBRARY_DIR}")
endif()
if (DEFINED FRIDA_GUM_RUNTIME)
    get_filename_component(_ds_frida_gum_bin "${FRIDA_GUM_RUNTIME}" DIRECTORY)
    list(APPEND _ds_mod_deps_search_dirs "${_ds_frida_gum_bin}")
elseif (DEFINED _FRIDA_GUM_ROOT)
    list(APPEND _ds_mod_deps_search_dirs "${_FRIDA_GUM_ROOT}/bin")
endif()
string(REPLACE ";" "\\;" _ds_mod_deps_search_dirs_code "${_ds_mod_deps_search_dirs}")

if (WIN32)
    set(_ds_mod_deps_pre_exclude
        "api-ms-.*"
        "ext-ms-.*"
        "hvsifiletrust.*"
        "pdmutilities.*"
    )
    set(_ds_mod_deps_post_exclude
        ".*[\\\\/][Ss]ystem32[\\\\/].*"
        ".*[\\\\/][Ss]ysWOW64[\\\\/].*"
        ".*[\\\\/]Windows[\\\\/]WinSxS[\\\\/].*"
        ".*[\\\\/]MSVC[\\\\/].*"
        "ucrtbase.*\\.dll"
        "vcruntime.*\\.dll"
        "msvcp.*\\.dll"
        "concrt.*\\.dll"
        "msvc.*\\.dll"
        # Package-owned (bin64 / plugins), not third-party deps/
        ".*[\\\\/]Injector\\.dll"
        ".*[\\\\/]Winmm\\.dll"
        ".*[\\\\/]plugin_.*\\.dll"
        ".*[\\\\/]lua51.*\\.dll"
        # Game / OS surface
        ".*[\\\\/]steam_api64\\.dll"
        ".*[\\\\/]steam_api\\.dll"
        ".*[\\\\/]vulkan-1\\.dll"
        ".*[\\\\/]d3d9\\.dll"
        ".*[\\\\/]d3d11\\.dll"
        ".*[\\\\/]dxgi\\.dll"
    )
else()
    set(_ds_mod_deps_pre_exclude
        "^/lib"
        "^/usr/lib"
        "^/lib64"
        "^/usr/lib64"
    )
    set(_ds_mod_deps_post_exclude
        ".*/ld-linux.*\\.so.*"
        ".*/libc\\.so.*"
        ".*/libm\\.so.*"
        ".*/libdl\\.so.*"
        ".*/libpthread\\.so.*"
        ".*/librt\\.so.*"
        ".*/libresolv\\.so.*"
        ".*/libgcc_s\\.so.*"
        ".*/libstdc\\+\\+\\.so.*"
        ".*/libsteam_api\\.so.*"
        ".*/libInjector\\.so.*"
        ".*/plugin_.*\\.so.*"
        ".*/liblua51.*\\.so.*"
    )
endif()
string(REPLACE ";" "\\;" _ds_mod_deps_pre_exclude_code "${_ds_mod_deps_pre_exclude}")
string(REPLACE ";" "\\;" _ds_mod_deps_post_exclude_code "${_ds_mod_deps_post_exclude}")

# Seeds: Injector + AlwaysOn / hard-import plugin MODULEs + optional reloc SHARED.
# Prefer seeding plugin targets (not just imported Tracy/SLikeNet) so
# GET_RUNTIME_DEPENDENCIES walks their PE imports (TracyClient, zip, …).
# Injector alone is insufficient: DISABLE_TRACY_FUTURE can drop Tracy from L0
# while plugin_debug_profiler still hard-imports TracyClient.dll.
set(_ds_mod_deps_seed_targets Injector)
foreach(_ds_seed_plugin IN ITEMS
        plugin_core_vm
        plugin_debug_profiler
        plugin_manager
        plugin_fps_render
        plugin_network_tick
        plugin_network_rpc
        plugin_render_angle
        plugin_dummy)
    if (TARGET ${_ds_seed_plugin})
        list(APPEND _ds_mod_deps_seed_targets ${_ds_seed_plugin})
    endif()
endforeach()
if (WIN32 AND TARGET function_relocation)
    get_target_property(_ds_fr_type function_relocation TYPE)
    if (_ds_fr_type STREQUAL "SHARED_LIBRARY")
        list(APPEND _ds_mod_deps_seed_targets function_relocation)
    endif()
endif()
set(_ds_mod_deps_seed_genex "")
foreach(_ds_seed_tgt IN LISTS _ds_mod_deps_seed_targets)
    string(APPEND _ds_mod_deps_seed_genex " \"$<TARGET_FILE:${_ds_seed_tgt}>\"")
endforeach()
string(STRIP "${_ds_mod_deps_seed_genex}" _ds_mod_deps_seed_genex)

install(CODE "
    if(POLICY CMP0207)
        cmake_policy(SET CMP0207 NEW)
    endif()
    set(_ds_seeds ${_ds_mod_deps_seed_genex})
    set(_ds_dirs \"${_ds_mod_deps_search_dirs_code}\")
    list(APPEND _ds_dirs \"\$<TARGET_FILE_DIR:Injector>\")
    list(REMOVE_DUPLICATES _ds_dirs)
    set(_ds_out \"\${CMAKE_INSTALL_PREFIX}/deps\")
    file(MAKE_DIRECTORY \"\${_ds_out}\")
    set(_ds_pre_exclude ${_ds_mod_deps_pre_exclude_code})
    set(_ds_post_exclude ${_ds_mod_deps_post_exclude_code})
    file(GET_RUNTIME_DEPENDENCIES
        LIBRARIES \${_ds_seeds}
        DIRECTORIES \${_ds_dirs}
        RESOLVED_DEPENDENCIES_VAR _ds_resolved
        UNRESOLVED_DEPENDENCIES_VAR _ds_unresolved
        CONFLICTING_DEPENDENCIES_PREFIX _ds_conflict
        PRE_EXCLUDE_REGEXES \${_ds_pre_exclude}
        POST_EXCLUDE_REGEXES \${_ds_post_exclude}
    )
    # Conflicts: applocal copies next to Injector vs vcpkg_installed — prefer vcpkg.
    foreach(_ds_name IN LISTS _ds_conflict_FILENAMES)
        set(_ds_pick \"\")
        foreach(_ds_path IN LISTS _ds_conflict_\${_ds_name})
            if(_ds_path MATCHES \"vcpkg_installed\")
                set(_ds_pick \"\${_ds_path}\")
                break()
            endif()
            if(NOT _ds_pick)
                set(_ds_pick \"\${_ds_path}\")
            endif()
        endforeach()
        if(_ds_pick)
            list(APPEND _ds_resolved \"\${_ds_pick}\")
        endif()
    endforeach()
    list(REMOVE_DUPLICATES _ds_resolved)
    foreach(_ds_dep IN LISTS _ds_resolved)
        get_filename_component(_ds_name \"\${_ds_dep}\" NAME)
        if(_ds_name MATCHES \"^(Injector|libInjector|plugin_.*|lua51.*|Winmm)(\\\\.(dll|so|dylib)).*\")
            continue()
        endif()
        file(INSTALL \"\${_ds_dep}\" DESTINATION \"\${_ds_out}\" FOLLOW_SYMLINK_CHAIN)
    endforeach()
    if(_ds_unresolved)
        message(STATUS \"ds_mod_deps: unresolved (non-fatal): \${_ds_unresolved}\")
    endif()
" COMPONENT deps)

# Windows build-tree smoke: stage into $<TARGET_FILE_DIR:Injector>/deps without
# cmake --install. Mirrors package layout for local DS_LUAJIT_PLUGIN_DIR runs.
if (WIN32)
    set(_ds_stage_script "${CMAKE_CURRENT_BINARY_DIR}/stage_mod_deps.cmake")
    file(WRITE "${_ds_stage_script}" [=[
if(POLICY CMP0207)
  cmake_policy(SET CMP0207 NEW)
endif()
if(NOT DEFINED DS_SEEDS OR NOT DEFINED DS_OUT OR NOT DEFINED DS_DIRS)
  message(FATAL_ERROR "stage_mod_deps.cmake: DS_SEEDS, DS_OUT, DS_DIRS required")
endif()
file(MAKE_DIRECTORY "${DS_OUT}")
file(GET_RUNTIME_DEPENDENCIES
  LIBRARIES ${DS_SEEDS}
  DIRECTORIES ${DS_DIRS}
  RESOLVED_DEPENDENCIES_VAR _resolved
  UNRESOLVED_DEPENDENCIES_VAR _unresolved
  CONFLICTING_DEPENDENCIES_PREFIX _conflict
  PRE_EXCLUDE_REGEXES
    "api-ms-.*"
    "ext-ms-.*"
  POST_EXCLUDE_REGEXES
    ".*[\\\\/][Ss]ystem32[\\\\/].*"
    ".*[\\\\/][Ss]ysWOW64[\\\\/].*"
    ".*[\\\\/]Windows[\\\\/]WinSxS[\\\\/].*"
    ".*[\\\\/]MSVC[\\\\/].*"
    "ucrtbase.*\\.dll"
    "vcruntime.*\\.dll"
    "msvcp.*\\.dll"
    "concrt.*\\.dll"
    "msvc.*\\.dll"
    ".*[\\\\/]steam_api64\\.dll"
    ".*[\\\\/]steam_api\\.dll"
    ".*[\\\\/]vulkan-1\\.dll"
    ".*[\\\\/]d3d9\\.dll"
    ".*[\\\\/]d3d11\\.dll"
    ".*[\\\\/]dxgi\\.dll"
)
# Conflicts: applocal next to Injector vs vcpkg_installed — prefer vcpkg.
foreach(_name IN LISTS _conflict_FILENAMES)
  set(_pick "")
  foreach(_path IN LISTS _conflict_${_name})
    if(_path MATCHES "vcpkg_installed")
      set(_pick "${_path}")
      break()
    endif()
    if(NOT _pick)
      set(_pick "${_path}")
    endif()
  endforeach()
  if(_pick)
    list(APPEND _resolved "${_pick}")
  endif()
endforeach()
list(REMOVE_DUPLICATES _resolved)
foreach(_dep IN LISTS _resolved)
  get_filename_component(_name "${_dep}" NAME)
  if(_name MATCHES "^(Injector|Winmm|plugin_.*|lua51.*)\\.dll$")
    continue()
  endif()
  execute_process(COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${_dep}" "${DS_OUT}/${_name}")
endforeach()
]=])
    # Reuse install seed target list for build-tree stage (same import graph).
    set(_ds_stage_mod_deps_depends ${_ds_mod_deps_seed_targets})
    set(_ds_stage_seeds "")
    foreach(_ds_seed_tgt IN LISTS _ds_mod_deps_seed_targets)
        if (_ds_stage_seeds)
            set(_ds_stage_seeds "${_ds_stage_seeds};$<TARGET_FILE:${_ds_seed_tgt}>")
        else()
            set(_ds_stage_seeds "$<TARGET_FILE:${_ds_seed_tgt}>")
        endif()
    endforeach()
    add_custom_target(stage_mod_deps ALL
        COMMAND ${CMAKE_COMMAND}
            -D "DS_SEEDS=${_ds_stage_seeds}"
            -D "DS_OUT=$<TARGET_FILE_DIR:Injector>/deps"
            -D "DS_DIRS=${_ds_mod_deps_search_dirs};$<TARGET_FILE_DIR:Injector>"
            -P "${_ds_stage_script}"
        DEPENDS ${_ds_stage_mod_deps_depends}
        COMMENT "Stage shared runtimes into build-tree deps/"
        VERBATIM
    )
endif()






