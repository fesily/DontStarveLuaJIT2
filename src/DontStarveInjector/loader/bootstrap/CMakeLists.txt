add_library(injector_bootstrap STATIC
    InjectorBootstrap.cpp
)

target_include_directories(injector_bootstrap PUBLIC
    ${DONTSTARVEINJECTOR_ROOT}
)

target_compile_features(injector_bootstrap PUBLIC cxx_std_23)

set_target_properties(injector_bootstrap PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    # The shell (this library's only consumer) is PRELOADed next to the real Injector, and
    # both include the same bootstrap headers. Keep this module's namespace-scope constants
    # to itself: a STB_GNU_UNIQUE object would otherwise be unified with the real module's
    # (possibly newer, larger) copy by the dynamic linker, which reads the wrong object.
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(injector_bootstrap PRIVATE -fno-gnu-unique)
endif()

if (WIN32)
    target_link_libraries(injector_bootstrap PUBLIC shell32)
endif ()
