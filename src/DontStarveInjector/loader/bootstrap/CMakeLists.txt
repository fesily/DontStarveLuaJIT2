add_library(injector_bootstrap STATIC
    InjectorBootstrap.cpp
)

target_include_directories(injector_bootstrap PUBLIC
    ${DONTSTARVEINJECTOR_ROOT}
)

target_compile_features(injector_bootstrap PUBLIC cxx_std_23)

if (WIN32)
    target_link_libraries(injector_bootstrap PUBLIC shell32)
endif ()
