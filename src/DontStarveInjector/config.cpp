#include "config.hpp"
#include <stdio.h>
#include <string>
#include "util/platform.hpp"

#include <frida-gum.h>

InjectorConfig *InjectorConfig::instance() {
    static InjectorConfig instance;
    return &instance;
}

InjectorConfig::EnvOrCmdOptFlag::operator bool() const {
    if (has_cached) return flag;
    if (getenv(key) != nullptr) return true;
    static auto cmd = get_cmd();
    flag = cmd.contains('-' + std::string{key});
    has_cached = true;
    return flag;
}

InjectorConfig::EnvOrCmdOptValue::operator const char*() const {
    if (has_cached) return value;
    const char *env_value = getenv(key);
    if (env_value != nullptr) {
        strncpy_s(value, env_value, sizeof(value) - 1);
        has_cached = true;
        return value;
    }
    value[0] = '\0';
    static auto cmds = get_cmds();
    for (size_t i = 1; i < cmds.size(); i++) {
        auto cmd = std::string_view{cmds[i]};
        if (cmd.starts_with('-' + std::string{key} + '=') || cmd.starts_with("--" + std::string{key} + '=')) {
            auto pos = cmd.find('=');
            auto val = cmd.substr(pos + 1);
            strncpy_s(value, val.data(), std::min(val.size(), sizeof(value) - 1));
            has_cached = true;
            return value;
        } else if (cmd == '-' + std::string{key} || cmd == "--" + std::string{key}) {
            if (i + 1 < cmds.size()) {
                i++;
                auto val = std::string_view{cmds[i]};
                if (val.starts_with('-') || val.starts_with("--")) {
                    break;
                }
                strncpy_s(value, val.data(), std::min(val.size(), sizeof(value) - 1));
                has_cached = true;
                return value;
            }
        }
    }
    return nullptr;
}

InjectorCtx::InjectorCtx()
    : config(*InjectorConfig::instance()) {
    
}

GumInterceptor *InjectorCtx::GetGumInterceptor() {
    if (interceptor == nullptr) {
        interceptor = gum_interceptor_obtain();
    }
    return interceptor;
}

InjectorCtx *InjectorCtx::instance() {
    static InjectorCtx instance;
    return &instance;
}