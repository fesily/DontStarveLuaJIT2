# Locate Keystone assembler (vcpkg or system).
# vcpkg keystone ships pkg-config only (no keystoneConfig.cmake).
#
# Multi-config (Ninja Multi-Config): MUST expose per-config IMPORTED locations.
# Linking a single absolute path (e.g. always debug/lib) against multi-config
# targets like libdwarf::dwarf produces CMake RPATH cycle warnings:
#   lib vs debug/lib — "Cannot generate a safe runtime search path".

if (DEFINED VCPKG_INSTALLED_DIR AND DEFINED VCPKG_TARGET_TRIPLET)
    set(_KEYSTONE_VCPKG_ROOT "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
else()
    set(_KEYSTONE_VCPKG_ROOT "")
endif()

set(_KEYSTONE_RELEASE_LIB "")
set(_KEYSTONE_DEBUG_LIB "")
set(_KEYSTONE_INCLUDE "")

if (_KEYSTONE_VCPKG_ROOT AND EXISTS "${_KEYSTONE_VCPKG_ROOT}/include/keystone/keystone.h")
    set(_KEYSTONE_INCLUDE "${_KEYSTONE_VCPKG_ROOT}/include")

    # Prefer shared; fall back to static basenames used by MSVC/static triplets.
    foreach(_cand IN ITEMS
            "${_KEYSTONE_VCPKG_ROOT}/lib/libkeystone.so"
            "${_KEYSTONE_VCPKG_ROOT}/lib/keystone.lib"
            "${_KEYSTONE_VCPKG_ROOT}/lib/libkeystone.a"
            "${_KEYSTONE_VCPKG_ROOT}/lib/keystone.dll.lib")
        if (EXISTS "${_cand}")
            set(_KEYSTONE_RELEASE_LIB "${_cand}")
            break()
        endif()
    endforeach()

    foreach(_cand IN ITEMS
            "${_KEYSTONE_VCPKG_ROOT}/debug/lib/libkeystone.so"
            "${_KEYSTONE_VCPKG_ROOT}/debug/lib/keystone.lib"
            "${_KEYSTONE_VCPKG_ROOT}/debug/lib/libkeystone.a"
            "${_KEYSTONE_VCPKG_ROOT}/debug/lib/keystone.dll.lib")
        if (EXISTS "${_cand}")
            set(_KEYSTONE_DEBUG_LIB "${_cand}")
            break()
        endif()
    endforeach()

    # Static/single-layout triplets may only install under lib/.
    if (NOT _KEYSTONE_DEBUG_LIB)
        set(_KEYSTONE_DEBUG_LIB "${_KEYSTONE_RELEASE_LIB}")
    endif()
    if (NOT _KEYSTONE_RELEASE_LIB)
        set(_KEYSTONE_RELEASE_LIB "${_KEYSTONE_DEBUG_LIB}")
    endif()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(keystone REQUIRED IMPORTED_TARGET keystone)
    # PkgConfig may only give one location; still expose KEYSTONE_* for callers.
    if (TARGET PkgConfig::keystone AND NOT TARGET keystone::keystone)
        add_library(keystone::keystone ALIAS PkgConfig::keystone)
    endif()
    if (keystone_INCLUDE_DIRS)
        set(_KEYSTONE_INCLUDE "${keystone_INCLUDE_DIRS}")
    endif()
    if (keystone_LINK_LIBRARIES)
        list(GET keystone_LINK_LIBRARIES 0 _KEYSTONE_RELEASE_LIB)
        set(_KEYSTONE_DEBUG_LIB "${_KEYSTONE_RELEASE_LIB}")
    endif()
endif()

if (_KEYSTONE_INCLUDE)
    set(KEYSTONE_INCLUDE_DIR "${_KEYSTONE_INCLUDE}" CACHE PATH "Keystone include directory" FORCE)
endif()

# Legacy variable: prefer release path (single-config / scripts).
if (_KEYSTONE_RELEASE_LIB)
    set(KEYSTONE_LIBRARIES "${_KEYSTONE_RELEASE_LIB}" CACHE FILEPATH "Keystone library (release)" FORCE)
elseif (_KEYSTONE_DEBUG_LIB)
    set(KEYSTONE_LIBRARIES "${_KEYSTONE_DEBUG_LIB}" CACHE FILEPATH "Keystone library" FORCE)
endif()

# Proper multi-config imported target (preferred link interface).
if (_KEYSTONE_RELEASE_LIB AND NOT TARGET keystone::keystone)
    get_filename_component(_keystone_ext "${_KEYSTONE_RELEASE_LIB}" EXT)
    if (_keystone_ext MATCHES "\\.(a|lib)$")
        add_library(keystone::keystone STATIC IMPORTED)
    else()
        add_library(keystone::keystone SHARED IMPORTED)
    endif()

    set_target_properties(keystone::keystone PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${KEYSTONE_INCLUDE_DIR}"
        IMPORTED_LOCATION "${_KEYSTONE_RELEASE_LIB}"
        IMPORTED_LOCATION_RELEASE "${_KEYSTONE_RELEASE_LIB}"
        IMPORTED_LOCATION_RELWITHDEBINFO "${_KEYSTONE_RELEASE_LIB}"
        IMPORTED_LOCATION_MINSIZEREL "${_KEYSTONE_RELEASE_LIB}"
        IMPORTED_LOCATION_DEBUG "${_KEYSTONE_DEBUG_LIB}"
        MAP_IMPORTED_CONFIG_RELWITHDEBINFO "RelWithDebInfo;Release"
        MAP_IMPORTED_CONFIG_MINSIZEREL "MinSizeRel;Release"
    )

    # SONAME for ELF shared libs helps CMake RPATH bookkeeping.
    if (_KEYSTONE_RELEASE_LIB MATCHES "\\.so")
        set_target_properties(keystone::keystone PROPERTIES
            IMPORTED_SONAME "libkeystone.so.0"
            IMPORTED_SONAME_RELEASE "libkeystone.so.0"
            IMPORTED_SONAME_RELWITHDEBINFO "libkeystone.so.0"
            IMPORTED_SONAME_MINSIZEREL "libkeystone.so.0"
            IMPORTED_SONAME_DEBUG "libkeystone.so.0"
        )
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(keystone DEFAULT_MSG
    KEYSTONE_LIBRARIES KEYSTONE_INCLUDE_DIR)

unset(_KEYSTONE_VCPKG_ROOT)
unset(_KEYSTONE_RELEASE_LIB)
unset(_KEYSTONE_DEBUG_LIB)
unset(_KEYSTONE_INCLUDE)
unset(_keystone_ext)
unset(_cand)
