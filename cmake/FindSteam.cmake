
# Search for the library in the following locations:
# 1. In the system's default paths
# 2. In additional paths specified by the user (e.g., CMAKE_PREFIX_PATH)

set (STEAM_SDK_INCLUDE_DIR PATHS ${PROJECT_SOURCE_DIR}/3rd)
find_path(STEAM_INCLUDE_DIR 
    NAMES steam_api.h 
    PATHS ${PROJECT_SOURCE_DIR}/3rd/steam
    REQUIRED)

if (WIN32)
    Set(STEAM_LIBRARIES_PREFIX "win64")
elseif(APPLE)
    Set(STEAM_LIBRARIES_PREFIX "osx")
else()
    Set(STEAM_LIBRARIES_PREFIX "linux64")
endif()
find_library(STEAM_LIBRARIES
    NAMES steam_api64 steam_api
    PATH_SUFFIXES ${STEAM_LIBRARIES_PREFIX}
    PATHS ${PROJECT_SOURCE_DIR}/3rd/steam/redistributable_bin
    REQUIRED)

include(FindPackageHandleStandardArgs)
# Check if the library has been found
find_package_handle_standard_args(Steam DEFAULT_MSG
    STEAM_LIBRARIES STEAM_INCLUDE_DIR STEAM_SDK_INCLUDE_DIR)

# Optionally, you can define additional variables here, such as version information

if(STEAM_FOUND)
    # Optionally, you can set additional variables here, such as version information
    # For example:
    # find_package_version(<库名> <库名>_VERSION)
    # set(<库名>_VERSION_STRING "${<库名>_VERSION_MAJOR}.${<库名>_VERSION_MINOR}.${<库名>_VERSION_PATCH}")
endif()
