#include "config/InjectorHostConfig.hpp"
#include <algorithm>
#include <cstring>
#include <stdio.h>
#include <string>
#include "util/PathText.hpp"
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

namespace {

// Environment variables and command-line tokens are UTF-8 text, the single
// interchange form for every string that later becomes a path (see util/PathText).
// On Windows `getenv` reads the ANSI environment, which silently mangles — and on
// a CP936 machine can never represent — a value the user really wrote; `_wgetenv`
// plus a UTF-8 conversion is total.
std::string env_utf8(const char *key) {
#if defined(_WIN32)
    const std::wstring wkey{key, key + std::char_traits<char>::length(key)};
    const wchar_t *wide = ::_wgetenv(wkey.c_str());
    if (wide == nullptr) {
        return {};
    }
    return ds::util::path_to_utf8(std::filesystem::path{wide});
#else
    const char *env_value = getenv(key);
    return env_value != nullptr ? std::string{env_value} : std::string{};
#endif
}

void copy_value(std::string_view text, char *value, size_t value_size) {
    const auto count = std::min(text.size(), value_size - 1);
    std::memcpy(value, text.data(), count);
    value[count] = '\0';
}

} // namespace

const char * InjectorConfig::getEnvOrCmdValue(const char *key, char *value, size_t value_size) {
    if (value_size == 0) {
        return value;
    }
    if (const auto env_value = env_utf8(key); !env_value.empty()) {
        copy_value(env_value, value, value_size);
        return value;
    }
    static auto cmds = get_cmds();
    for (size_t i = 1; i < cmds.size(); i++) {
        auto cmd = std::string_view{cmds[i]};
        if (cmd.starts_with('-' + std::string{key} + '=') || cmd.starts_with("--" + std::string{key} + '=')) {
            auto pos = cmd.find('=');
            copy_value(cmd.substr(pos + 1), value, value_size);
            return value;
        } else if (cmd == '-' + std::string{key} || cmd == "--" + std::string{key}) {
            if (i + 1 < cmds.size()) {
                i++;
                auto val = std::string_view{cmds[i]};
                if (val.starts_with('-') || val.starts_with("--")) {
                    break;
                }
                copy_value(val, value, value_size);
                return value;
            }
        }
    }
    value[0] = '\0';
    return value;
}

InjectorConfig::EnvOrCmdOptValue::operator const char*() const {
    if (has_cached) return value;

    InjectorConfig::getEnvOrCmdValue(key, value, sizeof(value));
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