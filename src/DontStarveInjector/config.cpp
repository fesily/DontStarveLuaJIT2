#include "config.hpp"
#include <stdio.h>
#include <string>
#include "util/platform.hpp"

InjectorConfig &InjectorConfig::instance() {
    static InjectorConfig instance;
    return instance;
}

InjectorConfig::EnvOrCmdOptFlag::operator bool() const {
    if (getenv(key) != nullptr) return true;
    static auto cmd = get_cmd();
    return cmd.contains('-' + std::string{key});
}