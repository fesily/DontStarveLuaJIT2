
find_package(doctest CONFIG REQUIRED)

add_executable(test_util
    main.cpp
)
target_link_libraries(test_util PRIVATE doctest::doctest)
target_compile_definitions(test_util PRIVATE
    SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)

add_test(NAME test_all COMMAND test_util --duration=true)
