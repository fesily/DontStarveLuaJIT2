# Sun-driven DynamicShadow (Tier A scaffold).
ds_add_dynamic_plugin(plugin_render_shadow
    plugin_render_shadow.cpp
    SunModel.cpp
    GenerateVBHook.cpp
    SilhouetteBatch.cpp
    SilhouetteMath.cpp
    AnimDrawHook.cpp
    BuildBin.cpp)

add_custom_command(TARGET plugin_render_shadow POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:plugin_render_shadow>/shaders"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/shaders/sil.ksh"
            "$<TARGET_FILE_DIR:plugin_render_shadow>/shaders/sil.ksh")



target_link_libraries(plugin_render_shadow PRIVATE
    spdlog::spdlog
    function_relocation
    libzip::zip
    ZLIB::ZLIB)

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
