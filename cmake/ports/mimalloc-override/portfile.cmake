# Separate from cmake/ports/mimalloc on purpose:
# - the Injector keeps the MI_OVERRIDE=OFF archive for its mi_* shim on Windows;
# - the POSIX preload stub must define malloc/free/operator new themselves.
# Building both variants in one port would change the symbols that every consumer
# sees, so this port installs only the override archive under a distinct name and
# deliberately drops the duplicate headers/CMake package.
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO microsoft/mimalloc
    REF "v${VERSION}"
    SHA512 55262050f63868e3029cd929a74d312dc0f34b606534b1d0b3735eecc8eed68aae97523a50228b4ac4044e1e03192f2909440e3a27607e2d364607ac0bda828f
    HEAD_REF master
    PATCHES
        pkgconfig-cxx.diff
)

vcpkg_check_linkage(ONLY_STATIC_LIBRARY)
# Headers are intentionally dropped: the MI_OVERRIDE=OFF package owns them.
set(VCPKG_POLICY_EMPTY_INCLUDE_FOLDER enabled)

set(MI_PLATFORM_OPTIONS "")
if(VCPKG_TARGET_IS_OSX)
    # A plain forwarding malloc in a DYLD_INSERT_LIBRARIES image is not enough:
    # macOS needs the __DATA,__interpose table (and the default malloc zone) so
    # the inserted stub replaces libSystem's allocator after dyld binds. The
    # static target normally omits MI_SHARED_LIB_EXPORT, which gates that table;
    # add it explicitly. C compilation matches mimalloc's own recommendation for
    # the interposing build (MI_USE_CXX=OFF).
    list(APPEND MI_PLATFORM_OPTIONS
        -DMI_OSX_ZONE=ON
        -DMI_OSX_INTERPOSE=ON
        -DMI_USE_CXX=OFF
        -DMI_LOCAL_DYNAMIC_TLS=ON
        "-DCMAKE_C_FLAGS=-DMI_SHARED_LIB -DMI_SHARED_LIB_EXPORT")
else()
    # The preload stub is loaded by ld.so at process start, but the real Injector
    # is dlopen()ed afterwards. Keep the TLS model compatible with that path.
    list(APPEND MI_PLATFORM_OPTIONS
        -DMI_USE_CXX=ON
        -DMI_LOCAL_DYNAMIC_TLS=ON)
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DMI_OVERRIDE=ON
        -DMI_SECURE=OFF
        -DMI_BUILD_STATIC=ON
        -DMI_BUILD_SHARED=OFF
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

# The archive is the only artifact this port owns. Keeping mimalloc's headers and
# `share/mimalloc` config would collide with the MI_OVERRIDE=OFF package.
foreach(_prefix "${CURRENT_PACKAGES_DIR}" "${CURRENT_PACKAGES_DIR}/debug")
    if(EXISTS "${_prefix}/lib/libmimalloc.a")
        file(RENAME "${_prefix}/lib/libmimalloc.a" "${_prefix}/lib/libmimalloc-override.a")
    endif()
    file(REMOVE_RECURSE
        "${_prefix}/include"
        "${_prefix}/share"
        "${_prefix}/lib/cmake"
        "${_prefix}/lib/pkgconfig")
endforeach()

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
