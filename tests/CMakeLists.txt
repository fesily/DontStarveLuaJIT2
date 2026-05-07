if (WIN32)
    add_library(lua51_sync_strfmt_pushfstring_module MODULE
        lua51_sync/strfmt_pushfstring_module.c)
    add_custom_target(lua51_sync_artifacts
        DEPENDS lua luajit lua51_sync_strfmt_pushfstring_module)
    set_target_properties(lua51_sync_strfmt_pushfstring_module PROPERTIES
        PREFIX ""
        OUTPUT_NAME "strfmt_pushfstring_module")
    foreach (cfg Debug Release RelWithDebInfo MinSizeRel)
        string(TOUPPER "${cfg}" cfg_upper)
        set_target_properties(lua51_sync_strfmt_pushfstring_module PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY_${cfg_upper} "${CMAKE_CURRENT_BINARY_DIR}/lua51_sync/${cfg}"
            LIBRARY_OUTPUT_DIRECTORY_${cfg_upper} "${CMAKE_CURRENT_BINARY_DIR}/lua51_sync/${cfg}")
    endforeach ()

    add_test(
        NAME lua51_sync
        COMMAND ${CMAKE_COMMAND} -E env
            LUA51_SYNC_BUILD_DIR=${CMAKE_BINARY_DIR}
            LUA51_SYNC_CONFIG=$<CONFIG>
            ${PYTHON_EXECUTABLE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/lua51_sync/run.py
    )
    set_tests_properties(lua51_sync PROPERTIES
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif ()

add_executable(test_buffer_name_pool
    ${CMAKE_CURRENT_SOURCE_DIR}/test_buffer_name_pool.cpp)
target_include_directories(test_buffer_name_pool PRIVATE
    ${CMAKE_SOURCE_DIR}/src/DontStarveInjector)
target_compile_features(test_buffer_name_pool PRIVATE cxx_std_17)
add_test(NAME BufferNamePool COMMAND test_buffer_name_pool)
