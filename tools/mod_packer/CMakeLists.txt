cmake_minimum_required(VERSION 3.15)

set (SOURCES
main.cpp
)

add_executable(mod_packer ${SOURCES})
file(TO_NATIVE_PATH "${CMAKE_INSTALL_PREFIX}" INSTALLDIR)
string(REPLACE "\\" "\\\\" INSTALLDIR ${INSTALLDIR})
file(TO_NATIVE_PATH "${PROJECT_SOURCE_DIR}/Mod" TARGETDIR)
string(REPLACE "\\" "\\\\" TARGETDIR ${TARGETDIR})
target_compile_definitions(mod_packer PUBLIC INSTALLDIR="${INSTALLDIR}" TARGETDIR="${TARGETDIR}")
