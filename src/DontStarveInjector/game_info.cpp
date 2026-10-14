#include "game_info.hpp"
#ifdef __linux__
#include "GameInfoArguments.hpp"
#include "util/platform.hpp"
#endif

std::optional<GameInfo> readGameInfo() {
#ifdef __linux__
    const auto arguments = get_cmds();
    if (arguments.empty()) return std::nullopt;
    return game_info_from_arguments(arguments);
#else
    return std::nullopt;
#endif
}
