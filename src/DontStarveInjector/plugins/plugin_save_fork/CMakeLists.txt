# save.fork — no Frida Gum; all platforms (Win clone + Linux fork).
ds_add_dynamic_plugin(plugin_save_fork
    plugin_save_fork.cpp
    GameForkSave.cpp)
target_link_libraries(plugin_save_fork PRIVATE
    spdlog::spdlog)
target_compile_definitions(plugin_save_fork PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_save_fork PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
