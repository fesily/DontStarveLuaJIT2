# plugin_manager — optional package manager (runtime optional if deleted).
# No Frida Gum; always built cross-platform. Soft absence when DLL removed.
ds_add_dynamic_plugin(plugin_manager
    plugin_manager.cpp
    PluginManagerApi.cpp
    PluginPinConfig.cpp
    PluginLocalInventory.cpp
    PluginHttp.cpp
    PluginHash.cpp
    PluginZipExtract.cpp
    PluginApply.cpp)
target_link_libraries(plugin_manager PRIVATE
    nlohmann_json::nlohmann_json
    libzip::zip)
if (WIN32)
    target_link_libraries(plugin_manager PRIVATE winhttp)
else()
    # Optional curl when available via vcpkg; otherwise http_get returns "http unsupported".
    find_package(CURL QUIET)
    if (CURL_FOUND)
        target_link_libraries(plugin_manager PRIVATE CURL::libcurl)
        target_compile_definitions(plugin_manager PRIVATE DS_PLUGIN_MANAGER_HAS_CURL=1)
    endif()
endif()
target_include_directories(plugin_manager PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})
