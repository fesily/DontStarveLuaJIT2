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

static const char * getEnvOrCmdValue(const char *key, char *value, size_t value_size) {
    const char *env_value = getenv(key);
    if (env_value != nullptr) {
        strncpy(value, env_value, value_size - 1);
        return value;
    }
    static auto cmds = get_cmds();
    for (size_t i = 1; i < cmds.size(); i++) {
        auto cmd = std::string_view{cmds[i]};
        if (cmd.starts_with('-' + std::string{key} + '=') || cmd.starts_with("--" + std::string{key} + '=')) {
            auto pos = cmd.find('=');
            auto val = cmd.substr(pos + 1);
            strncpy(value, val.data(), std::min(val.size(), value_size - 1));
            return value;
        } else if (cmd == '-' + std::string{key} || cmd == "--" + std::string{key}) {
            if (i + 1 < cmds.size()) {
                i++;
                auto val = std::string_view{cmds[i]};
                if (val.starts_with('-') || val.starts_with("--")) {
                    break;
                }
                strncpy(value, val.data(), std::min(val.size(), value_size - 1));
                return value;
            }
        }
    }
    value[0] = '\0';
    return value;
}

InjectorConfig::EnvOrCmdOptValue::operator const char*() const {
    if (has_cached) return value;

    getEnvOrCmdValue(key, value, sizeof(value));
    has_cached = true;
    return value;
}

template<typename T, T default_value>
InjectorConfig::EnvOrCmdOptIntValue<T, default_value>::operator T() const {
    if (has_cached) return value;
    char buf[64] = {};
    getEnvOrCmdValue(key, buf, sizeof(buf));
    char *endptr = buf + strlen(buf);
    if (endptr == buf) {
        has_cached = true;
        return value;
    }
    value = static_cast<T>(std::strtoll(buf, endptr, 0));
    if (*endptr != '\0') {
        value = default_value;
    }
    has_cached = true;
    return value;
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