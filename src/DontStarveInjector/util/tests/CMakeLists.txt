
find_package(doctest CONFIG REQUIRED)

add_executable(test_util
    main.cpp
    path_text.cpp
    owner_dirs.cpp
    ../../config/path/OwnerDirs.cpp
)
target_include_directories(test_util PRIVATE ${DONTSTARVEINJECTOR_ROOT})
target_link_libraries(test_util PRIVATE doctest::doctest)
target_compile_definitions(test_util PRIVATE
    SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)

add_test(NAME test_all COMMAND test_util --duration=true)
