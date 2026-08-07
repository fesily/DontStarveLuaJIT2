# Stage lua51* + signatures_*.json into Injector/deps (build-tree analog of Mod/deps).
# Missing sources are skipped (copy_if_different would error).
if(NOT DEFINED DS_OUT)
  message(FATAL_ERROR "stage_core_vm_deps.cmake: DS_OUT required")
endif()
file(MAKE_DIRECTORY "${DS_OUT}")

# Prefer the active build config only. Falling through Debug after RelWithDebInfo
# previously staged Debug-CRT lua51DS.dll into a Rel package (LoadLibrary 0x7E).
if(NOT DEFINED DS_CFG OR DS_CFG STREQUAL "")
  set(DS_CFG RelWithDebInfo)
endif()

# Signatures (repo package tree + already-staged deps)
foreach(_sig IN ITEMS signatures_client.json signatures_server.json)
  foreach(_root IN ITEMS
      "${CMAKE_SOURCE_DIR}/Mod/deps"
      "${CMAKE_SOURCE_DIR}/Mod/bin64/linux"
      "${CMAKE_SOURCE_DIR}/Mod/bin64/osx"
      "${CMAKE_BINARY_DIR}")
    if(EXISTS "${_root}/${_sig}")
      file(COPY "${_root}/${_sig}" DESTINATION "${DS_OUT}")
      break()
    endif()
  endforeach()
endforeach()

# Lua VMs — only the active config, then safe non-Debug fallbacks for Rel builds.
foreach(_name IN ITEMS lua51.dll lua51DS.dll lua51DS_gengc.dll lua51Original.dll
                       liblua51.so liblua51DS.so liblua51DS_gengc.so liblua51Original.so
                       liblua51.dylib liblua51DS.dylib liblua51DS_gengc.dylib liblua51Original.dylib)
  set(_picked "")
  foreach(_root IN ITEMS
      "${CMAKE_BINARY_DIR}/luajit/${DS_CFG}"
      "${CMAKE_BINARY_DIR}/src/lua51original/${DS_CFG}")
    if(EXISTS "${_root}/${_name}")
      set(_picked "${_root}/${_name}")
      break()
    endif()
  endforeach()
  # Non-Debug installs may fall back to RelWithDebInfo/Release only (never Debug).
  if(NOT _picked AND NOT DS_CFG MATCHES "^[Dd][Ee][Bb][Uu][Gg]$")
    foreach(_root IN ITEMS
        "${CMAKE_BINARY_DIR}/luajit/RelWithDebInfo"
        "${CMAKE_BINARY_DIR}/luajit/Release"
        "${CMAKE_BINARY_DIR}/src/lua51original/RelWithDebInfo"
        "${CMAKE_BINARY_DIR}/src/lua51original/Release"
        "${CMAKE_SOURCE_DIR}/src/lua51/release")
      if(EXISTS "${_root}/${_name}")
        set(_picked "${_root}/${_name}")
        break()
      endif()
    endforeach()
  endif()
  # Debug installs may fall back to debug tree only.
  if(NOT _picked AND DS_CFG MATCHES "^[Dd][Ee][Bb][Uu][Gg]$")
    foreach(_root IN ITEMS
        "${CMAKE_BINARY_DIR}/luajit/Debug"
        "${CMAKE_BINARY_DIR}/src/lua51original/Debug"
        "${CMAKE_SOURCE_DIR}/src/lua51/debug")
      if(EXISTS "${_root}/${_name}")
        set(_picked "${_root}/${_name}")
        break()
      endif()
    endforeach()
  endif()
  if(_picked)
    file(COPY "${_picked}" DESTINATION "${DS_OUT}")
  endif()
endforeach()
