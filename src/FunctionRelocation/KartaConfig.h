//
// Created by fesil on 2024/3/13.
//

#ifndef DONTSTARVELUAJIT_KARTACONFIG_H
#define DONTSTARVELUAJIT_KARTACONFIG_H

#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <optional>
#include <span>
#include <set>

namespace Karta {
    struct Function {
        std::string functionName;
        size_t instructionCount;
        size_t stackFrameSize;
        bool isStatic;
        std::vector<int64_t> numberConsts;
        std::vector<std::string> strings;
        std::vector<std::string> calls;
        std::vector<size_t> codeBlockSizes;
        std::vector<std::string> callOrder;
        std::vector<std::string> externalFunctions;
        std::vector<std::string> externalConsts;
    };

    struct Config {
        std::map<std::string, std::vector<Function>> files;
        std::vector<const Function *> functions;
        std::map<std::string, const Function *> anchor_functions;
        std::set<std::string> known_functions;

        const Function *get_file(const char *functionName);

        const Function *get_anchor(const Function *target);
    };

    std::optional<Config> read_from(const char *path);
}

#endif //DONTSTARVELUAJIT_KARTACONFIG_H
