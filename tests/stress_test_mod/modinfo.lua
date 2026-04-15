---@diagnostic disable: lowercase-global
name = "DST Stress Test Bot"
description = "Headless stress test bot for DontStarveLuaJIT2. Auto-joins server and spawns character without UI interaction."
author = "fesil"
version = "0.1.0"

api_version = 10

dst_compatible = true

client_only_mod = true
server_only_mod = false
all_clients_require_mod = false

priority = 1e10

icon_atlas = nil
icon = nil

configuration_options = {
    {
        name = "auto_spawn_character",
        label = "Auto Spawn Character",
        hover = "Character prefab to auto-spawn as",
        options = {
            { description = "Wilson", data = "wilson" },
            { description = "Willow", data = "willow" },
            { description = "Wolfgang", data = "wolfgang" },
            { description = "Wendy", data = "wendy" },
            { description = "WX-78", data = "wx78" },
            { description = "Wickerbottom", data = "wickerbottom" },
            { description = "Woodie", data = "woodie" },
            { description = "Wes", data = "wes" },
            { description = "Random", data = "random" },
        },
        default = "random",
    },
    {
        name = "auto_spawn_delay",
        label = "Auto Spawn Delay (seconds)",
        hover = "Delay before sending spawn request after world load",
        options = {
            { description = "0s", data = 0 },
            { description = "1s", data = 1 },
            { description = "2s", data = 2 },
            { description = "5s", data = 5 },
        },
        default = 1,
    },
}
