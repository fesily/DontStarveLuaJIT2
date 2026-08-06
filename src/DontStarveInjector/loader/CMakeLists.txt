find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)


set(Winmm_SOURCES
        winmm.cpp
        winmm_main.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/inlinehook.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/module.cpp
        ${DONTSTARVEINJECTOR_UTIL_DIR}/platform.cpp
        ../config/sources/LuajitConfigFile.cpp
)

add_library(Winmm SHARED ${Winmm_SOURCES})

target_include_directories(Winmm PUBLIC ${DONTSTARVEINJECTOR_UTIL_DIR} ${DONTSTARVEINJECTOR_ROOT})

target_link_libraries(Winmm PRIVATE injector_bootstrap spdlog::spdlog nlohmann_json::nlohmann_json)
target_compile_definitions(Winmm PRIVATE NO_FRIDA_GUM=1)

target_include_directories(Winmm PUBLIC ${LUAJIT_INCLUDE_DIR})
target_link_libraries(Winmm PRIVATE ${LUAJIT_LIBRARIES})
install(TARGETS Winmm RUNTIME DESTINATION . COMPONENT injector_shell)
