if (MSVC)
	set(INSTALLED_ROOT "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
	set(keystone_LIBRARY_DIRS "${INSTALLED_ROOT}/lib")
    set(keystone_INCLUDE_DIRS "${INSTALLED_ROOT}/include")
else()
	find_package(PkgConfig REQUIRED)
	pkg_check_modules(keystone REQUIRED keystone)
endif()


find_path(FRIDA_GUM_INCLUDE_DIR 
    NAMES frida-gum.h 
    PATHS "${INSTALLED_ROOT}/include" 
    REQUIRED)

# Custom dynamic triplets ship libkeystone.so; MSVC/static host builds may use
# keystone.lib / libkeystone.a. Accept all common basenames.
find_library(KEYSTONE_LIBRARIES
    NAMES keystone keystone.lib libkeystone.a libkeystone.so
    PATHS ${keystone_LIBRARY_DIRS}
    REQUIRED)

	
include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(keystone DEFAULT_MSG
    KEYSTONE_LIBRARIES keystone_LIBRARY_DIRS keystone_INCLUDE_DIRS)
