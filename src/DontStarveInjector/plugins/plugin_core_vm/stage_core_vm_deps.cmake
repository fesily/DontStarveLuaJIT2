# Stage lua51* into Injector/deps (build-tree analog of Mod/deps).
# Signatures: only verified present at Mod/ root (not staged into deps).
# Required -D vars: DS_OUT, DS_CFG, DS_SOURCE_DIR, DS_BINARY_DIR
# (Do NOT use CMAKE_SOURCE_DIR in -P scripts — CMake overwrites it with CWD.)
if(NOT DEFINED DS_OUT)
  message(FATAL_ERROR "stage_core_vm_deps.cmake: DS_OUT required")
endif()
if(NOT DEFINED DS_SOURCE_DIR OR DS_SOURCE_DIR STREQUAL "")
  message(FATAL_ERROR "stage_core_vm_deps.cmake: DS_SOURCE_DIR required")
endif()
if(NOT DEFINED DS_BINARY_DIR OR DS_BINARY_DIR STREQUAL "")
  message(FATAL_ERROR "stage_core_vm_deps.cmake: DS_BINARY_DIR required")
endif()
file(MAKE_DIRECTORY "${DS_OUT}")

# Prefer the active build config only. Falling through Debug after RelWithDebInfo
# previously staged Debug-CRT lua51DS.dll into a Rel package (LoadLibrary 0x7E).
if(NOT DEFINED DS_CFG OR DS_CFG STREQUAL "")
  set(DS_CFG RelWithDebInfo)
endif()

# Signatures: ONLY Mod/signatures_*.json (all platforms). No bin64/<plat>/, no deps/.
# Runtime SignatureJson reads <mod>/signatures_*.json; install ships from Mod/.
foreach(_sig IN ITEMS signatures_client.json signatures_server.json)
  set(_src "${DS_SOURCE_DIR}/Mod/${_sig}")
  if(NOT EXISTS "${_src}")
    message(FATAL_ERROR
      "stage_core_vm_deps: ${_sig} not found at ${_src}. "
      "Regenerate with signature_updater (writes Mod/signatures_*.json).")
  endif()
endforeach()

# Map multi-config → src/lua51 batch folder (debug|release).
# Training PE only — not the game LuaJIT VM. Prefer matching config, then the
# other batch, then already-staged Mod/deps (so Debug builds work after a
# release-only build_lua51).
set(_ds_lua51_cfg "release")
if(DS_CFG MATCHES "^[Dd][Ee][Bb][Uu][Gg]$")
  set(_ds_lua51_cfg "debug")
endif()

set(_ds_lua51_src "")
foreach(_cand IN ITEMS
    "${DS_SOURCE_DIR}/src/lua51/${_ds_lua51_cfg}/lua51.dll"
    "${DS_SOURCE_DIR}/src/lua51/release/lua51.dll"
    "${DS_SOURCE_DIR}/src/lua51/debug/lua51.dll"
    "${DS_SOURCE_DIR}/Mod/deps/lua51.dll")
  if(EXISTS "${_cand}")
    set(_ds_lua51_src "${_cand}")
    break()
  endif()
endforeach()
if(_ds_lua51_src)
  if(NOT _ds_lua51_src STREQUAL "${DS_SOURCE_DIR}/src/lua51/${_ds_lua51_cfg}/lua51.dll")
    message(STATUS
      "stage_core_vm_deps: using fallback lua51.dll '${_ds_lua51_src}' "
      "(wanted src/lua51/${_ds_lua51_cfg}/lua51.dll)")
  endif()
  file(COPY "${_ds_lua51_src}" DESTINATION "${DS_OUT}")
else()
  message(FATAL_ERROR
    "stage_core_vm_deps: lua51.dll not found under src/lua51/{debug,release} "
    "or Mod/deps. Build it first (target build_lua51 / src/lua51/build_lua51.bat).")
endif()

# LuaJIT / original VMs — active config build outputs only (no package fallbacks).
foreach(_name IN ITEMS lua51DS.dll lua51DS_gengc.dll lua51Original.dll
                       liblua51DS.so liblua51DS_gengc.so liblua51Original.so
                       liblua51DS.dylib liblua51DS_gengc.dylib liblua51Original.dylib)
  set(_picked "")
  foreach(_root IN ITEMS
      "${DS_BINARY_DIR}/luajit/${DS_CFG}"
      "${DS_BINARY_DIR}/src/lua51original/${DS_CFG}")
    if(EXISTS "${_root}/${_name}")
      set(_picked "${_root}/${_name}")
      break()
    endif()
  endforeach()
  # Non-Debug may fall back to RelWithDebInfo/Release build trees only (never Debug CRT).
  if(NOT _picked AND NOT DS_CFG MATCHES "^[Dd][Ee][Bb][Uu][Gg]$")
    foreach(_root IN ITEMS
        "${DS_BINARY_DIR}/luajit/RelWithDebInfo"
        "${DS_BINARY_DIR}/luajit/Release"
        "${DS_BINARY_DIR}/src/lua51original/RelWithDebInfo"
        "${DS_BINARY_DIR}/src/lua51original/Release")
      if(EXISTS "${_root}/${_name}")
        set(_picked "${_root}/${_name}")
        break()
      endif()
    endforeach()
  endif()
  if(NOT _picked AND DS_CFG MATCHES "^[Dd][Ee][Bb][Uu][Gg]$")
    foreach(_root IN ITEMS
        "${DS_BINARY_DIR}/luajit/Debug"
        "${DS_BINARY_DIR}/src/lua51original/Debug")
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
