-- L-G probe: write marker files for automated dedicated harness.
-- Marker directory comes from global LG_MARKER_DIR if set by harness inject, else unsafedata/lg_probe.

local _G = GLOBAL

local function marker_dir()
    local dir = _G.rawget(_G, "LG_MARKER_DIR")
    if type(dir) == "string" and #dir > 0 then
        return dir
    end
    return "unsafedata/lg_probe"
end

local function write_marker(name, body)
    local dir = marker_dir()
    -- best-effort mkdir via TheSim if available
    if TheSim and TheSim.GetUserPrefPath then
        -- keep relative; DST often resolves under data/
    end
    local path = dir .. "/" .. name
    local ok, err = pcall(function()
        local fp = io.open(path, "w")
        if not fp then
            -- try creating via simple path under current cwd
            fp = io.open(name, "w")
            if fp then
                path = name
            end
        end
        if not fp then
            error("cannot open marker " .. path)
        end
        fp:write(body or "1")
        fp:close()
    end)
    if ok then
        print("[lg_probe] marker " .. name .. " -> " .. path)
    else
        print("[lg_probe] marker fail " .. name .. ": " .. tostring(err))
    end
end

local function check_inject()
    local gi = _G.rawget(_G, "GameInjector")
    if gi ~= nil then
        write_marker("LG_INJECT_OK", "GameInjector")
        return true
    end
    write_marker("LG_INJECT_MISSING", "GameInjector nil")
    return false
end

AddGamePostInit(function()
    write_marker("LG_MOD_LOADED", "probe_modmain")
    local inject_ok = check_inject()
    -- M0: empty plugin host is OK if inject present; production host may report later.
    if inject_ok then
        write_marker("LG_PLUGINS_OK", "inject_present")
    end
end)

AddSimPostInit(function()
    write_marker("LG_WORLD_READY", "sim_post_init")

    local paused = false
    if TheNet and TheNet.SetServerPaused then
        TheNet:SetServerPaused(true)
        if TheNet.GetServerPaused then
            paused = TheNet:GetServerPaused() and true or false
        else
            paused = true
        end
    elseif _G.c_pause then
        -- fallback if present
        pcall(_G.c_pause)
        paused = true
    end

    if paused then
        write_marker("LG_SIM_PAUSED", "paused")
    else
        write_marker("LG_SIM_PAUSE_FAILED", "could_not_pause")
    end
end)
