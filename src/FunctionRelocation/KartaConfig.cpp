//
// Created by fesil on 2024/3/13.
//

#include "KartaConfig.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <ranges>
#include <algorithm>

namespace function_relocation::Karta {
    inline void from_json(const nlohmann::json &nlohmann_json_j, Function &nlohmann_json_t) {
        nlohmann_json_j.at("Function Name").get_to(nlohmann_json_t.functionName);
        nlohmann_json_j.at("Instruction Count").get_to(nlohmann_json_t.instructionCount);
        nlohmann_json_j.at("Stack Frame Size").get_to(nlohmann_json_t.stackFrameSize);
        nlohmann_json_j.at("isStatic").get_to(nlohmann_json_t.isStatic);
        nlohmann_json_j.at("Numeric Consts").get_to(nlohmann_json_t.numberConsts);
        nlohmann_json_j.at("Strings").get_to(nlohmann_json_t.strings);
        nlohmann_json_j.at("Calls").get_to(nlohmann_json_t.calls);
        nlohmann_json_j.at("Code Block Sizes").get_to(nlohmann_json_t.codeBlockSizes);
        nlohmann_json_j.at("Call Order").get_to(nlohmann_json_t.callOrder);
        nlohmann_json_j.at("Unknown Functions").get_to(nlohmann_json_t.externalFunctions);
        nlohmann_json_j.at("Unknown Consts").get_to(nlohmann_json_t.externalConsts);
    };

    inline void from_json(const nlohmann::json &nlohmann_json_j, Config &nlohmann_json_t) {
        std::vector<size_t> anchors;
        nlohmann_json_j.at("Anchors (Src Index)").get_to(anchors);
        nlohmann_json_j.at("Files").get_to(nlohmann_json_t.files);
        for (const auto index: anchors) {
            auto func = nlohmann_json_t.functions.at(index);
            nlohmann_json_t.anchor_functions[func->functionName] = func;
        }
    };

    std::optional<Config> read_from(const char *path) {
        std::ifstream sf(path);
        if (!sf.is_open())
            return std::nullopt;
        nlohmann::json j;
        sf >> j;
        auto conf = j.get<Config>();
        for (const auto &functions: conf.files | std::views::values) {
            for (const auto &func: functions) {
                conf.functions.emplace_back(&func);
            }
        }
        return conf;
    }


    const Function *Config::get_file(const char *functionName) {
        for (const auto &file: files) {
            for (const auto &func: file.second) {
                if (func.functionName == functionName)
                    return &func;
            }
        }
        return nullptr;
    }

    // 1. 判断是否可以通过 锚点 直接定位出来
    // 2  通过已知函数 定位
    const Function *Config::get_anchor(const Function *target) {
        if (anchor_functions.contains(target->functionName))
            return target;
        for (const auto &call: target->calls) {

        }
        if (std::ranges::all_of(target->calls, [this](auto &call) { return known_functions.contains(call); }))
            return target;
        
        return nullptr;
    }
}
