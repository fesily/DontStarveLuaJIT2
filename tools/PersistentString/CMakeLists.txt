
add_executable(UnPersistentFile
    ${DONTSTARVEINJECTOR_UTIL_DIR}/PersistentString.cpp
    main.cpp
)

target_include_directories(UnPersistentFile PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR})
target_include_directories(UnPersistentFile PUBLIC ${CMAKE_SOURCE_DIR}/src)
find_package(ZLIB REQUIRED)
target_link_libraries(UnPersistentFile PRIVATE ZLIB::ZLIB)