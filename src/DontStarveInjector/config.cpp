#include "config.hpp"
#include <stdio.h>
#include "util/platform.hpp"

InjectorConfig &InjectorConfig::instance() {
    static InjectorConfig instance;
    return instance;
}

InjectorConfig::EnvOrCmdOptFlag::operator bool() const {
    if (getenv(key) != nullptr) return true;
    return get_cmd().contains('-' + std::string{key});
}