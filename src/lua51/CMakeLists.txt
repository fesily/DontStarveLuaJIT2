
file(GLOB_RECURSE LUA51_SOURCE "src/l*.c")

list(REMOVE_ITEM LUA51_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/luac.c")

add_executable(lua51 ${LUA51_SOURCE} src/print.c)
target_compile_definitions(lua51 PUBLIC BUILD_AS_EXE)
