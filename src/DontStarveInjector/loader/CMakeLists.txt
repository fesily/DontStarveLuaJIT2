# Thin Windows inject shell only. Must NOT dynamically link third-party
# runtimes (spdlog/fmt/json/luajit/…). Real work lives in Injector.dll
# loaded via injector_bootstrap.

set(Winmm_SOURCES
        winmm.cpp
        winmm_main.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/inlinehook.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
)

add_library(Winmm SHARED ${Winmm_SOURCES})

target_include_directories(Winmm PRIVATE
    ${DONTSTARVEINJECTOR_UTIL_DIR}
    ${DONTSTARVEINJECTOR_ROOT}
)

target_link_libraries(Winmm PRIVATE injector_bootstrap)
# module.cpp / platform.cpp are compiled into this shell — not imported from Injector.
target_compile_definitions(Winmm PRIVATE NO_FRIDA_GUM=1 DS_PLUGIN_HOST_STATIC)

# Shell must stay CRT-only + system libs. No vcpkg shared runtimes.
install(TARGETS Winmm RUNTIME DESTINATION "${DS_INSTALL_SHELL_DIR}" COMPONENT injector_shell)
