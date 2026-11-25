vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO microsoft/mimalloc
    REF "v${VERSION}"
    SHA512 55262050f63868e3029cd929a74d312dc0f34b606534b1d0b3735eecc8eed68aae97523a50228b4ac4044e1e03192f2909440e3a27607e2d364607ac0bda828f
    HEAD_REF master
    PATCHES
        pkgconfig-cxx.diff
)

# This overlay port exists so the injector can link mimalloc *statically* while
# the shared triplets from cmake/custom-triplets set
# VCPKG_LIBRARY_LINKAGE=dynamic. It must run before any linkage test below so
# that the static build shape (and the unmodified mimalloc.h) is guaranteed:
# with VCPKG_LIBRARY_LINKAGE=dynamic the port rewrites mimalloc.h to
# __declspec(dllimport) and static consumers then fail with LNK2019 __imp_mi_*.
vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

set(MI_PLATFORM_OPTIONS "")
if(NOT VCPKG_TARGET_IS_WINDOWS)
    # Mod/libInjector.so is dlopen()ed from the loader stub; the default
    # -ftls-model=initial-exec would consume the static TLS surplus of glibc.
    list(APPEND MI_PLATFORM_OPTIONS -DMI_LOCAL_DYNAMIC_TLS=ON)
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DMI_OVERRIDE=OFF
        -DMI_SECURE=OFF
        -DMI_BUILD_STATIC=ON
        -DMI_BUILD_SHARED=OFF
        -DMI_USE_CXX=ON
        -DMI_BUILD_OBJECT=OFF
        -DMI_BUILD_TESTS=OFF
        -DMI_INSTALL_TOPLEVEL=ON
        ${MI_PLATFORM_OPTIONS}
    OPTIONS_DEBUG
        -DMI_DEBUG_FULL=ON
    OPTIONS_RELEASE
        -DMI_DEBUG_FULL=OFF
)

vcpkg_cmake_install()

vcpkg_copy_pdbs()

file(COPY
    "${CMAKE_CURRENT_LIST_DIR}/vcpkg-cmake-wrapper.cmake"
    "${CMAKE_CURRENT_LIST_DIR}/usage"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
)
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/mimalloc)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")

vcpkg_fixup_pkgconfig()

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
