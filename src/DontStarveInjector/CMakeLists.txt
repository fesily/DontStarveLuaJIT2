option(ENABLE_FAKE_API "check inejctor hook lua func" OFF)
option(ENABLE_ONLY_LUA51 "load lua51.dll" OFF)
option(ENABLE_USE_LISTENER "use api listener" OFF)
option(ENABLE_STEAM_SUPPORT "Enable Steam support" ON)

set(SOURCES
        DontStarveInjector.cpp
        DontStarveSignature.cpp
        lua_fake.cpp
        gameio.cpp
        SignatureJson.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/inlinehook.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/zipfile.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/gum_platform.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/lua_io2.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/lua51_object.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/PersistentString.cpp
        gameModConfig.cpp
        luajit_config.cpp
        game_info.cpp
        GameLua.cpp
        GameLuaModule.cpp
        GameSteam.cpp
        GameSignature.cpp
        GameNetwork.cpp
        config.cpp
        GameLuaInjectFramework.c
        lua_debugger_helper.cpp
        core/PluginHost.cpp
        core/PluginOptionRules.cpp
        core/RegisterBuiltinPlugins.cpp
        core/PluginConfigBridge.cpp
        core/DynamicPluginLoader.cpp
)


if (ENABLE_STEAM_SUPPORT)
    list(APPEND SOURCES ${DONTSTARVEINJECTOR_UTIL_DIR}/steam.cpp)
    find_package(Steam REQUIRED)
endif ()

if (NOT MSVC)
    list(APPEND SOURCES
        GameForkSave.cpp
    )
else()
    list(APPEND SOURCES
        GameForkSave.cpp
        Progress.cpp
        #profiler.cpp
        GameLua.def
        GameRenderHook.cpp
        GameNetworkSim.cpp
        GameSimHook.cpp
    )
endif()

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
    set_target_properties(Injector PROPERTIES INSTALL_RPATH "\$ORIGIN/../lib64")
    set_target_properties(Injector PROPERTIES BUILD_RPATH "\$ORIGIN/../lib64")
else()
    set_target_properties(Injector PROPERTIES INSTALL_RPATH "./lib64:\$ORIGIN/lib64")
    set_target_properties(Injector PROPERTIES BUILD_RPATH "./lib64:\$ORIGIN/lib64")
endif()

add_dependencies(Injector create_missfuncs)
add_dependencies(Injector create_modinfo_hpp)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/GameLuaInjectFramework.c
        COMMAND ${PYTHON_EXECUTABLE_NAME} "../../tools/lua2c.py" "${CMAKE_CURRENT_SOURCE_DIR}/GameLuaInjectFramework.lua" "${CMAKE_CURRENT_SOURCE_DIR}/GameLuaInjectFramework.c"
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/GameLuaInjectFramework.lua
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(GameLuaInjectFramework DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/GameLuaInjectFramework.c)
add_dependencies(Injector GameLuaInjectFramework)

target_include_directories(Injector PRIVATE ${SOL2_INCLUDE_DIRS})
target_include_directories(Injector PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(Injector PRIVATE ${FRIDA_GUM_LIBRARIES})

target_link_libraries(Injector PRIVATE Boost::pfr)
target_link_libraries(Injector PRIVATE libzip::zip)
target_link_libraries(Injector PRIVATE ZLIB::ZLIB)
target_link_libraries(Injector PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(Injector PRIVATE spdlog::spdlog)
target_link_libraries(Injector PRIVATE range-v3::meta range-v3::concepts range-v3::range-v3)
target_link_libraries(Injector PRIVATE SLikeNet)
# GameRenderHook (still in Injector until M-R2) needs GLES headers only — no ANGLE .lib.
if (WIN32)
    target_include_directories(Injector PRIVATE "${PROJECT_SOURCE_DIR}/3rd/angle/win64/include")
endif()
target_include_directories(Injector PRIVATE ${PLF_HIVE_INCLUDE_DIRS})
#target_link_libraries(Injector PRIVATE $<IF:$<TARGET_EXISTS:mimalloc-static>,mimalloc-static,mimalloc>)
if (NOT DISABLE_TRACY_FUTURE)
    target_link_libraries(Injector PRIVATE Tracy::TracyClient)
else()
    target_compile_definitions(Injector PRIVATE DISABLE_TRACY_FUTURE)
endif()
target_link_libraries(Injector PRIVATE function_relocation)
target_include_directories(Injector PUBLIC ${FUNCTION_RELOCATION_INCLUDE_DIR})

if (NOT ENABLE_ONLY_LUA51)
    target_include_directories(Injector PUBLIC ${LUAJIT_INCLUDE_DIR})
    add_dependencies(Injector ${LUAJIT_LIBRARIES})
    #target_link_libraries(Injector PRIVATE ${LUAJIT_LIBRARIES})
elseif (ENABLE_FAKE_API)
    target_include_directories(Injector PUBLIC ${LUA_INCLUDE_DIR})
    target_link_directories(Injector PUBLIC ${PROJECT_SOURCE_DIR}/src/lua51/$<IF:$<CONFIG:Debug>,Debug,Release>)
    add_dependencies(Injector ${LUA_LIBRARIES})
    #target_link_libraries(Injector PRIVATE ${LUA_LIBRARIES})
else ()
    target_include_directories(Injector PUBLIC ${LUA_INCLUDE_DIR})
    add_dependencies(Injector liblua)
    #target_link_libraries(Injector PRIVATE liblua)
endif ()

if (MSVC)
    target_link_options(Injector PUBLIC "/NODEFAULTLIB:LIBCMT")
endif ()

if (ENABLE_FAKE_API)
    target_compile_definitions(Injector PUBLIC ENABLE_FAKE_API)
endif ()

if (ENABLE_USE_LISTENER)
    target_compile_definitions(Injector PUBLIC ENABLE_USE_LISTENER)
endif ()

if (ENABLE_ONLY_LUA51)
    target_compile_definitions(Injector PUBLIC ENABLE_ONLY_LUA51)
endif ()

install(TARGETS Injector RUNTIME DESTINATION .)

if (WIN32)
    add_subdirectory(loader)
endif ()

add_subdirectory(util)

# Dynamic plugin modules (Phase B). Output next to Injector under plugins/.
function(ds_add_dynamic_plugin name)
    add_library(${name} MODULE ${ARGN})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_features(${name} PRIVATE cxx_std_23)
    target_link_libraries(${name} PRIVATE Injector)
    set_target_properties(${name} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${name}"
        RUNTIME_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins"
        LIBRARY_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins"
        ARCHIVE_OUTPUT_DIRECTORY "$<TARGET_FILE_DIR:Injector>/plugins"
    )
endfunction()

ds_add_dynamic_plugin(plugin_dummy
    plugins/plugin_dummy/plugin_dummy.cpp)
ds_add_dynamic_plugin(plugin_network_rpc
    plugins/plugin_network_rpc/plugin_network_rpc.cpp)
ds_add_dynamic_plugin(plugin_render_vbpool
    plugins/plugin_render_vbpool/plugin_render_vbpool.cpp)
ds_add_dynamic_plugin(plugin_render_angle
    plugins/plugin_render_angle/plugin_render_angle.cpp
    GameOpenGl.cpp)
if (WIN32)
    # ANGLE + OpenGL implementation live only in this module (Path A M-R1).
    target_link_libraries(plugin_render_angle PRIVATE
        unofficial::angle::libGLESv2
        unofficial::angle::libEGL
        spdlog::spdlog
        function_relocation)
    target_compile_definitions(plugin_render_angle PRIVATE
        GUM_STATIC=1
        SPDLOG_COMPILED_LIB
        SPDLOG_FMT_EXTERNAL)
    target_include_directories(plugin_render_angle PRIVATE
        ${PROJECT_SOURCE_DIR}/3rd
        ${PROJECT_SOURCE_DIR}/3rd/frida-gum/win64
        ${FUNCTION_RELOCATION_INCLUDE_DIR})
endif()


