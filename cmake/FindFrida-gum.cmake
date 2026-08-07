if (WIN32)
    set(_FRIDA_GUM_PLAT "win64")
elseif (APPLE)
    set(_FRIDA_GUM_PLAT "osx")
else()
    set(_FRIDA_GUM_PLAT "linux64")
endif()

set(_FRIDA_GUM_ROOT "${PROJECT_SOURCE_DIR}/3rd/frida-gum/${_FRIDA_GUM_PLAT}")

find_path(FRIDA_GUM_INCLUDE_DIR
    NAMES frida-gum.h
    PATHS
        "${_FRIDA_GUM_ROOT}/include"
        "${_FRIDA_GUM_ROOT}"
    NO_DEFAULT_PATH
    REQUIRED)

if (WIN32)
    find_library(FRIDA_GUM_LIBRARIES
        NAMES frida-gum
        PATHS "${_FRIDA_GUM_ROOT}/lib"
        NO_DEFAULT_PATH
        REQUIRED)
    find_file(FRIDA_GUM_RUNTIME
        NAMES frida-gum.dll
        PATHS "${_FRIDA_GUM_ROOT}/bin" "${_FRIDA_GUM_ROOT}/lib"
        NO_DEFAULT_PATH
        REQUIRED)
else()
    find_library(FRIDA_GUM_LIBRARIES
        NAMES frida-gum
        PATHS "${_FRIDA_GUM_ROOT}/lib"
        NO_DEFAULT_PATH
        REQUIRED)
    set(FRIDA_GUM_RUNTIME "${FRIDA_GUM_LIBRARIES}")
endif()

get_filename_component(FRIDA_GUM_LIBRARY_DIR "${FRIDA_GUM_LIBRARIES}" DIRECTORY)

if (NOT TARGET Frida::Gum)
    add_library(Frida::Gum SHARED IMPORTED GLOBAL)
    set_target_properties(Frida::Gum PROPERTIES
        IMPORTED_LOCATION "${FRIDA_GUM_RUNTIME}"
        INTERFACE_INCLUDE_DIRECTORIES "${FRIDA_GUM_INCLUDE_DIR}"
    )
    if (WIN32)
        set_target_properties(Frida::Gum PROPERTIES
            IMPORTED_IMPLIB "${FRIDA_GUM_LIBRARIES}"
        )
    endif()
endif()

# Shared consumers: do NOT define GUM_STATIC (dllimport on Windows).

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Frida-gum DEFAULT_MSG
    FRIDA_GUM_LIBRARIES FRIDA_GUM_INCLUDE_DIR FRIDA_GUM_RUNTIME)
