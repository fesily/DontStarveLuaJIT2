-- GAME_INIT runs immediately before the framework's one-time jit.off().
local mode = startup_jit_mode
local j = jit
local profile
if j then
    profile = require("jit.profile")
    if profile.etw then
        profile.etw(startup_etw == true)
    elseif startup_etw then
        error("native ETW symbol interface unavailable")
    end
end
local early
function DSPerfStartup(stage)
    local enabled = j and j.status() or false
    local row = "[ds_perf] STARTUP stage=" .. stage .. " jit=" .. tostring(enabled)
        .. " etw=" .. tostring(profile and profile.etw and profile.etw() or false)
    if stage == "BEFORE_MAIN" then
        early = row
        return
    end
    if early then
        print(early .. " replayed=true")
        early = nil
    end
    print(row)
end
if j then
    local original_off = j.off
    j.off = function(...)
        j.off = original_off
        original_off(...)
        if mode == "on" then j.on() end
        DSPerfStartup("BEFORE_MAIN")
    end
else
    DSPerfStartup("BEFORE_MAIN")
end
