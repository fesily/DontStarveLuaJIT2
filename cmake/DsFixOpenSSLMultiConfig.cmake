# Fix vcpkg OpenSSL IMPORTED targets for multi-config generators (Ninja Multi-Config).
#
# On Linux, OpenSSLConfig.cmake chains to FindOpenSSL MODULE which leaves a
# single IMPORTED_LOCATION under debug/lib (from pkg-config / find_library order).
# Consumers like SLikeNet link OpenSSL::SSL/Crypto; multi-config libzip/zlib live
# in both lib/ and debug/lib → CMake RPATH "cycle in the constraint graph".
#
# Call after find_package(slikenet) (or any package that find_dependency(OpenSSL)).

function(ds_fix_openssl_multiconfig)
    if (NOT DEFINED VCPKG_INSTALLED_DIR OR NOT DEFINED VCPKG_TARGET_TRIPLET)
        return()
    endif()
    if (MSVC)
        return()
    endif()

    set(_root "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
    set(_lib "${_root}/lib")
    set(_dlib "${_root}/debug/lib")

    foreach(_pair IN ITEMS "OpenSSL::Crypto|libcrypto" "OpenSSL::SSL|libssl")
        string(REPLACE "|" ";" _parts "${_pair}")
        list(GET _parts 0 _tgt)
        list(GET _parts 1 _base)

        if (NOT TARGET "${_tgt}")
            continue()
        endif()

        set(_rel "")
        set(_dbg "")
        foreach(_cand IN ITEMS
            "${_lib}/${_base}.so"
            "${_lib}/lib${_base}.so"
            "${_lib}/${_base}.a"
            "${_lib}/lib${_base}.a")
            if (NOT _rel AND EXISTS "${_cand}")
                set(_rel "${_cand}")
            endif()
        endforeach()
        foreach(_cand IN ITEMS
            "${_dlib}/${_base}.so"
            "${_dlib}/lib${_base}.so"
            "${_dlib}/${_base}.a"
            "${_dlib}/lib${_base}.a")
            if (NOT _dbg AND EXISTS "${_cand}")
                set(_dbg "${_cand}")
            endif()
        endforeach()

        if (NOT _rel)
            continue()
        endif()
        if (NOT _dbg)
            set(_dbg "${_rel}")
        endif()

        get_filename_component(_soname "${_rel}" NAME)
        # Prefer SONAME with version when present (libcrypto.so.3 / libssl.so.3).
        if (EXISTS "${_lib}/${_base}.so.3")
            set(_soname "${_base}.so.3")
            set(_rel "${_lib}/${_base}.so.3")
        endif()
        if (EXISTS "${_dlib}/${_base}.so.3")
            set(_dbg "${_dlib}/${_base}.so.3")
        elseif (EXISTS "${_dlib}/${_soname}")
            set(_dbg "${_dlib}/${_soname}")
        endif()

        set_target_properties("${_tgt}" PROPERTIES
            IMPORTED_CONFIGURATIONS "RELEASE;RELWITHDEBINFO;MINSIZEREL;DEBUG"
            IMPORTED_LOCATION "${_rel}"
            IMPORTED_LOCATION_RELEASE "${_rel}"
            IMPORTED_LOCATION_RELWITHDEBINFO "${_rel}"
            IMPORTED_LOCATION_MINSIZEREL "${_rel}"
            IMPORTED_LOCATION_DEBUG "${_dbg}"
            IMPORTED_SONAME_RELEASE "${_soname}"
            IMPORTED_SONAME_RELWITHDEBINFO "${_soname}"
            IMPORTED_SONAME_MINSIZEREL "${_soname}"
            IMPORTED_SONAME_DEBUG "${_soname}"
            MAP_IMPORTED_CONFIG_RELWITHDEBINFO "RELEASE"
            MAP_IMPORTED_CONFIG_MINSIZEREL "RELEASE")
    endforeach()

    # Keep cache vars on release so later find_package(OpenSSL) / messages stay consistent.
    if (EXISTS "${_lib}/libcrypto.so")
        set(OPENSSL_CRYPTO_LIBRARY "${_lib}/libcrypto.so" CACHE FILEPATH "OpenSSL crypto lib" FORCE)
    endif()
    if (EXISTS "${_lib}/libssl.so")
        set(OPENSSL_SSL_LIBRARY "${_lib}/libssl.so" CACHE FILEPATH "OpenSSL ssl lib" FORCE)
    endif()
endfunction()
