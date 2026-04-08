#pragma once
#include <string_view>

#define GAME_LUA_TYPE_ENUM(_) \
    _(jit)                 \
    _(game)                \
    _(_51)                 \
    _(jit_gen)             \
    _(unknown)

enum class GameLuaType {
#define DEFINE_ENUM(name) name,
    GAME_LUA_TYPE_ENUM(DEFINE_ENUM) 
#undef DEFINE_ENUM
};

inline std::string_view GameLuaTypeToString(GameLuaType type)
{
    switch (type) {
#define CASE_ENUM_TO_STRING(name) \
    case GameLuaType::name:       \
        return std::string_view{#name};
        GAME_LUA_TYPE_ENUM(CASE_ENUM_TO_STRING)
#undef CASE_ENUM_TO_STRING
    default:
        return "unknown";
    }
}

inline GameLuaType GameLuaTypeFromString(const std::string_view &str)
{
    #define IF_STRING_TO_ENUM(name) \
        if (str == std::string_view{#name})           \
            return GameLuaType::name;
    GAME_LUA_TYPE_ENUM(IF_STRING_TO_ENUM)
    #undef IF_STRING_TO_ENUM
    using namespace std::string_view_literals;
    if (str == "51"sv)
        return GameLuaType::_51;
    if (str == "5.1"sv)
        return GameLuaType::_51;
    if (str == "lua51"sv)
        return GameLuaType::_51;
    return GameLuaType::jit; // default
}

inline GameLuaType GameLuaTypeFromInt(int type)
{
    switch (type) {
#define CASE_INT_TO_ENUM(name) \
    case static_cast<int>(GameLuaType::name): \
        return GameLuaType::name;
        GAME_LUA_TYPE_ENUM(CASE_INT_TO_ENUM)
#undef CASE_INT_TO_ENUM
    default:
        return GameLuaType::jit; // default
    }
}
