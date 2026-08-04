
find_package(pe-parse CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

set(SOURCE
        Signature.cpp
        ModuleSections.cpp
        MemorySignature.cpp
        KartaConfig.cpp
        ctx.cpp
        disasm.h
        ScanCtx.cpp
        ExectuableSignature.cpp
)

find_package(spdlog CONFIG REQUIRED)
find_package(libdwarf CONFIG REQUIRED)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(function_relocation STATIC ${SOURCE})

# Gum symbols are provided by the final link unit:
# - Injector.dll links frida-gum statically and re-exports gum_* (FridaGum.def)
# - plugins import gum_* from Injector — do NOT link frida-gum here or a second
#   Gum copy gets pulled into every consumer of this static lib.
target_include_directories(function_relocation PUBLIC ${FRIDA_GUM_INCLUDE_DIR})
target_link_libraries(function_relocation PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(function_relocation PRIVATE spdlog::spdlog)
if (MSVC)
    target_link_libraries(function_relocation PRIVATE pe-parse::pe-parse)
else()
    target_link_libraries(function_relocation PRIVATE ${KEYSTONE_LIBRARIES})
    target_link_libraries(function_relocation PRIVATE libdwarf::dwarf)
endif ()