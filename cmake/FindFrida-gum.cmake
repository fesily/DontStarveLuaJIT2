if (WIN32)
    Set(FRIDA_GUM_LIBRARIES_PREFIX "win64")
elseif(APPLE)
    Set(FRIDA_GUM_LIBRARIES_PREFIX "osx")
else()
    Set(FRIDA_GUM_LIBRARIES_PREFIX "linux64")
endif()

find_path(FRIDA_GUM_INCLUDE_DIR 
    NAMES frida-gum.h 
    PATHS ${PROJECT_SOURCE_DIR}/3rd/frida-gum/${FRIDA_GUM_LIBRARIES_PREFIX}
    REQUIRED)

find_library(FRIDA_GUM_LIBRARIES
    NAMES frida-gum.lib libfrida-gum.a
    PATHS ${PROJECT_SOURCE_DIR}/3rd/frida-gum/${FRIDA_GUM_LIBRARIES_PREFIX}
    REQUIRED)

get_filename_component(FRIDA_GUM_LIBRARY_DIR "${FRIDA_GUM_LIBRARIES}" DIRECTORY)

add_compile_definitions(GUM_STATIC=1)

include(FindPackageHandleStandardArgs)
# Check if the library has been found
find_package_handle_standard_args(Frida-gum DEFAULT_MSG
    FRIDA_GUM_LIBRARIES FRIDA_GUM_INCLUDE_DIR FRIDA_GUM_LIBRARY_DIR)
