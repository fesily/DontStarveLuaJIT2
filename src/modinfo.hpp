#pragma once
#include <string_view>
#include <string>
template <typename T, size_t N>
struct ModConfigurationOption {
    std::string_view name;
    T default_value;
    T options[N];
};
namespace ModConfigurationOptions {
using namespace std::string_view_literals;

ModConfigurationOption<std::string_view,1> SECTION_1 = {"SECTION_1", ""sv, {""sv}};
ModConfigurationOption<double,11> DisableForceFullGC = {"DisableForceFullGC", 1, {0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512}};
ModConfigurationOption<bool,2> EnableFrameGC = {"EnableFrameGC", true, {true, false}};
ModConfigurationOption<double,9> TargetRenderFPS = {"TargetRenderFPS", 60, {60, 30, 60, 90, 120, 144, 165, 200, 240}};
ModConfigurationOption<bool,2> AlwaysEnableMod = {"AlwaysEnableMod", true, {true, false}};
ModConfigurationOption<bool,2> NetworkOpt = {"NetworkOpt", true, {true, false}};
ModConfigurationOption<bool,2> NetworkOptEntity = {"NetworkOptEntity", true, {true, false}};
ModConfigurationOption<std::string_view,1> SECTION_2 = {"SECTION_2", ""sv, {""sv}};
ModConfigurationOption<bool,2> EnabledJIT = {"EnabledJIT", true, {true, false}};
ModConfigurationOption<std::string_view,2> LuaVmType = {"LuaVmType", "jit"sv, {"jit"sv, "game"sv}};
ModConfigurationOption<bool,2> SlowTailCall = {"SlowTailCall", true, {true, false}};
ModConfigurationOption<bool,2> AutoDetectEncryptedMod = {"AutoDetectEncryptedMod", true, {true, false}};
ModConfigurationOption<std::string_view,1> SECTION_3 = {"SECTION_3", ""sv, {""sv}};
ModConfigurationOption<std::string_view,4> AngleBackend = {"AngleBackend", "Auto"sv, {"auto"sv, "vulkan"sv, "d3d11"sv, "d3d9"sv}};
ModConfigurationOption<std::string_view,1> SECTION_4 = {"SECTION_4", ""sv, {""sv}};
ModConfigurationOption<std::string_view,3> EnableProfiler = {"EnableProfiler", "off"sv, {"off"sv, "fzvp"sv, "Gz"sv}};
ModConfigurationOption<std::string_view,2> EnableTracy = {"EnableTracy", "off"sv, {"off"sv, "on"sv}};
};

