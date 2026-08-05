# plugin_manager — optional package manager (runtime optional if deleted).
# No Frida Gum; always built cross-platform. Soft absence when DLL removed.
ds_add_dynamic_plugin(plugin_manager
    plugin_manager.cpp
    PluginManagerApi.cpp
    PluginPinConfig.cpp
    PluginLocalInventory.cpp)
target_link_libraries(plugin_manager PRIVATE
    nlohmann_json::nlohmann_json)
target_include_directories(plugin_manager PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})
