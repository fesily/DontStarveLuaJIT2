# Sun-driven DynamicShadow (Tier A scaffold).
ds_add_dynamic_plugin(plugin_render_shadow
    plugin_render_shadow.cpp
    SunModel.cpp
    GenerateVBHook.cpp)
target_link_libraries(plugin_render_shadow PRIVATE
    spdlog::spdlog
    function_relocation)
target_compile_definitions(plugin_render_shadow PRIVATE
    SPDLOG_COMPILED_LIB
    SPDLOG_FMT_EXTERNAL)
target_include_directories(plugin_render_shadow PRIVATE
    ${PROJECT_SOURCE_DIR}/3rd
    ${PROJECT_SOURCE_DIR}/3rd/angle/win64/include
    ${FRIDA_GUM_INCLUDE_DIR}
    ${FUNCTION_RELOCATION_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(plugin_render_shadow PRIVATE
    ${SOL2_INCLUDE_DIRS}
    ${DONTSTARVEINJECTOR_ROOT}
    ${LUAJIT_INCLUDE_DIR})

target_include_directories(plugin_render_shadow PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector/plugins/plugin_core_vm/io
    ${LUAJIT_INCLUDE_DIR})
