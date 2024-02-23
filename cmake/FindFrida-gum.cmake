if (WIN32)
    Set(FRIDA_GUM_LIBRARIES_PREFIX "windows")
else()
    Set(FRIDA_GUM_LIBRARIES_PREFIX "linux")
endif()

find_path(FRIDA_GUM_INCLUDE_DIR 
    NAMES frida-gum.h 
    PATHS ${PROJECT_SOURCE_DIR}/3rd/frida-gum/${FRIDA_GUM_LIBRARIES_PREFIX}
    REQUIRED)

find_library(FRIDA_GUM_LIBRARIES
    NAMES frida-gum libfrida-gum
    PATHS ${PROJECT_SOURCE_DIR}/3rd/frida-gum/${FRIDA_GUM_LIBRARIES_PREFIX}
    REQUIRED)

include(FindPackageHandleStandardArgs)
# Check if the library has been found
find_package_handle_standard_args(Frida-gum DEFAULT_MSG
    FRIDA_GUM_LIBRARIES FRIDA_GUM_INCLUDE_DIR)
