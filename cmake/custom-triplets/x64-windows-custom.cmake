# custom-triplets/x64-windows-custom.cmake

set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

# Keep CI installs release-only to avoid building both variants there.
if ((DEFINED ENV{GITHUB_ACTIONS} AND NOT "$ENV{GITHUB_ACTIONS}" STREQUAL "")
	OR (DEFINED ENV{CI} AND NOT "$ENV{CI}" STREQUAL ""))
	set(VCPKG_BUILD_TYPE release)
endif ()