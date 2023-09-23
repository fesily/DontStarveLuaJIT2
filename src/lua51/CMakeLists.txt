
cmake_minimum_required(VERSION 2.8)

file(GLOB_RECURSE LUA51_SOURCE "src/l*.c")

list(REMOVE_ITEM LUA51_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/luac.c")

list(REMOVE_ITEM LUA51_SOURCE "*lua.c")

add_library(lua51 SHARED ${LUA51_SOURCE})
target_link_libraries(lua51 PRIVATE m dl)
