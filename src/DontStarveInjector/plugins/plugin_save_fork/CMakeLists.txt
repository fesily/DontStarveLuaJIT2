# save.fork — no Frida Gum; all platforms (Win clone + Linux fork).
ds_add_dynamic_plugin(plugin_save_fork
    plugin_save_fork.cpp
    GameForkSave.cpp)
target_link_libraries(plugin_save_fork PRIVATE
    spdlog::spdlog)
target_link_options(plugin_save_fork PRIVATE
    "/NODEFAULTLIB:frida-gum.lib")
target_compile_definitions(plugin_save_fork PRIVATE
    GUM_STATIC=1)
target_compile_definitions(plugin_save_fork PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_save_fork PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(plugin_save_fork PRIVATE
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})

target_include_directories(plugin_save_fork PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io
    ${LUAJIT_INCLUDE_DIR})
