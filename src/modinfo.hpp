#pragma once
#include <string_view>
#include <string>
template <typename T, size_t N>
struct ModConfigurationOption {
    std::string_view name;
    T default_value;
    T options[N];
};
struct ModConfigurationOptions {

ModConfigurationOption<bool,2> EnabledJIT = {"EnabledJIT", true, {true, false}};
ModConfigurationOption<double,11> DisableForceFullGC = {"DisableForceFullGC", 1, {0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512}};
ModConfigurationOption<double,6> EnableFrameGC = {"EnableFrameGC", 1, {0, 1, 2, 3, 4, 5}};
ModConfigurationOption<double,7> TargetLogicFPS = {"TargetLogicFPS", 30, {30, 45, 60, 75, 90, 105, 120}};
ModConfigurationOption<double,9> TargetRenderFPS = {"TargetRenderFPS", 60, {60, 30, 60, 90, 120, 144, 165, 200, 240}};
ModConfigurationOption<double,17> ClientNetWorkTick = {"ClientNetWorkTick", 10, {10, 15, 20, 25, 30, 32, 35, 40, 45, 50, 55, 60, 64, 75, 90, 115, 120}};
ModConfigurationOption<std::string,3> EnableProfiler = {"EnableProfiler", "off", {"off", "fzvp", "Gz"}};
ModConfigurationOption<std::string,2> EnableTracy = {"EnableTracy", "off", {"off", "on"}};
};

