local source, destination, available_json = ...
local available = {}
for id in available_json:gmatch("%d+") do
    available["workshop-" .. id] = true
end
local mods = assert(loadfile(source))()
local disabled = {}
for name, settings in pairs(mods) do
    if settings.enabled and (not available[name] or name == "workshop-3444078585") then
        settings.enabled = false
        disabled[#disabled + 1] = name
    end
end
-- Native bootstrap reads this row even when the Lua mod is disabled.
if mods["workshop-3444078585"] then
    mods["workshop-3444078585"].configuration_options = {
        DisableJITWhenServer = false,
        AlwaysEnableMod = false,
        EnableProfiler = "off",
        EnableTracy = "off",
    }
end
local function serialize(value)
    if type(value) == "table" then
        local rows = {}
        for key, item in pairs(value) do
            rows[#rows + 1] = "[" .. serialize(key) .. "]=" .. serialize(item)
        end
        table.sort(rows)
        return "{" .. table.concat(rows, ",") .. "}"
    elseif type(value) == "string" then
        return string.format("%q", value)
    else
        return tostring(value)
    end
end
local out = assert(io.open(destination, "wb"))
out:write("return ", serialize(mods), "\n")
out:close()
for _, name in ipairs(disabled) do print("DISABLED " .. name) end
