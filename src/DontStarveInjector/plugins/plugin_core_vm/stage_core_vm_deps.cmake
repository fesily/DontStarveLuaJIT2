# Stage lua51* + signatures_*.json into plugins/deps next to plugin_core_vm.
# Missing sources are skipped (copy_if_different would error).
if(NOT DEFINED DS_OUT)
  message(FATAL_ERROR "stage_core_vm_deps.cmake: DS_OUT required")
endif()
file(MAKE_DIRECTORY "${DS_OUT}")

function(ds_copy_if_exists src dst)
  if(EXISTS "${src}")
    file(COPY "${src}" DESTINATION "${dst}")
  endif()
endfunction()

# Signatures (repo package tree)
foreach(_sig IN ITEMS signatures_client.json signatures_server.json)
  foreach(_root IN ITEMS
      "${CMAKE_SOURCE_DIR}/Mod/bin64/windows"
      "${CMAKE_SOURCE_DIR}/Mod/bin64"
      "${CMAKE_BINARY_DIR}")
    if(EXISTS "${_root}/${_sig}")
      file(COPY "${_root}/${_sig}" DESTINATION "${DS_OUT}")
      break()
    endif()
  endforeach()
endforeach()

# Lua VMs
foreach(_name IN ITEMS lua51.dll lua51DS.dll lua51DS_gengc.dll lua51Original.dll
                       liblua51.so liblua51DS.so liblua51DS_gengc.so liblua51Original.so
                       liblua51.dylib liblua51DS.dylib liblua51DS_gengc.dylib liblua51Original.dylib)
  foreach(_root IN ITEMS
      "${CMAKE_BINARY_DIR}/luajit/${DS_CFG}"
      "${CMAKE_BINARY_DIR}/luajit/RelWithDebInfo"
      "${CMAKE_BINARY_DIR}/luajit/Release"
      "${CMAKE_BINARY_DIR}/luajit/Debug"
      "${CMAKE_BINARY_DIR}/src/lua51original/${DS_CFG}"
      "${CMAKE_BINARY_DIR}/src/lua51original/RelWithDebInfo"
      "${CMAKE_BINARY_DIR}/src/lua51original/Release"
      "${CMAKE_BINARY_DIR}/src/lua51original/Debug"
      "${CMAKE_SOURCE_DIR}/src/lua51/release"
      "${CMAKE_SOURCE_DIR}/src/lua51/debug"
      "${CMAKE_SOURCE_DIR}/Mod/bin64/windows"
      "${CMAKE_SOURCE_DIR}/Mod/bin64")
    if(EXISTS "${_root}/${_name}")
      file(COPY "${_root}/${_name}" DESTINATION "${DS_OUT}")
      break()
    endif()
  endforeach()
endforeach()
