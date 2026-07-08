if(NOT DEFINED LUAJIT_GENGC_TARGET_FILE_NAME_FILE)
    message(FATAL_ERROR "FAIL: LUAJIT_GENGC_TARGET_FILE_NAME_FILE is not set")
endif()

if(NOT EXISTS "${LUAJIT_GENGC_TARGET_FILE_NAME_FILE}")
    message(FATAL_ERROR
        "FAIL: gengc target file name marker not found: ${LUAJIT_GENGC_TARGET_FILE_NAME_FILE}")
endif()

file(READ "${LUAJIT_GENGC_TARGET_FILE_NAME_FILE}" _target_file_name)
string(STRIP "${_target_file_name}" _target_file_name)

if(NOT _target_file_name MATCHES "lua51DS_gengc")
    message(FATAL_ERROR
        "FAIL: expected gengc runtime artifact name to contain 'lua51DS_gengc', got '${_target_file_name}'")
endif()

if(_target_file_name MATCHES "arenagc")
    message(FATAL_ERROR
        "FAIL: gengc runtime artifact name must not contain 'arenagc', got '${_target_file_name}'")
endif()

message(STATUS "PASS: gengc runtime artifact name verified as '${_target_file_name}'")
