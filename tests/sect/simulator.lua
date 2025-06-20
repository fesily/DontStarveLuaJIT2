local arg = {...}
TheSim = {}
kleiloadlua = newproxy(function(...)
    print("kleiloadlua", ...)
    return function(...)
        print("kleiloadlua1", ...)
    end
end)

function ModInfoname(name)
    print("ModInfoname:", name)
    return "ModInfoname"
end

MODS_ROOT = "../mods/"
ModManager = {}
local  modname = "workshop-2847908822"

local env =
{
    -- lua
    pairs = pairs,
    ipairs = ipairs,
    print = print,
    math = math,
    table = table,
    type = type,
    string = string,
    tostring = tostring,
    require = require,
    Class = Class,

    -- runtime
    TUNING = TUNING,

    -- worldgen
    LEVELCATEGORY = LEVELCATEGORY,
    GROUND = GROUND,
    WORLD_TILES = WORLD_TILES,
    LOCKS = LOCKS,
    KEYS = KEYS,
    LEVELTYPE = LEVELTYPE,

    -- utility
    GLOBAL = _G,
    modname = modname,
    MODROOT = MODS_ROOT .. modname .. "/",
}
env.modimport = function(modulename)
    print("modimport: "..env.MODROOT..modulename)
    if string.sub(modulename, #modulename-3,#modulename) ~= ".lua" then
        modulename = modulename..".lua"
    end
    local result = kleiloadlua(env.MODROOT..modulename)
    if result == nil then
        error("Error in modimport: "..modulename.." not found!")
    elseif type(result) == "string" then
        error("Error in modimport: "..ModInfoname(modname).." importing "..modulename.."!\n"..result)
    else
        setfenv(result, env.env)
        result()
    end
end

env.env = env
local real_ROOT = "tests/2847908822/"
local old_io_open = io.open
local currentfilename = "modmain12345.lua"
io.open1 = old_io_open
local loadstring1 = loadstring
---@param filename string
io.open = newproxy(function(filename, mode)
    print("io.open:", filename, mode)
    filename = filename:gsub("%.%.%/mods%/workshop%-2847908822/", real_ROOT)
    print("io.open:", filename, mode)
    if (filename:find(currentfilename, 1, true)) then
        return old_io_open(real_ROOT.. "modmain.lua", mode)
    end
    return old_io_open(filename, mode)
end)

local old_debug_getinfo = debug.getinfo
debug.getinfo1 = newproxy(function(f, what)
    print("debug.getinfo:", f, what)
    if (type(f) == 'number') then
        f = f + 2
    end
    local info = old_debug_getinfo(f, 'Sf')
    if info.source and info.source:find(currentfilename, 1, true) then
        info.source = MODS_ROOT .. "modmain.lua"
    else
        print("debug.getinfo:", f, what, "source:", info.source)
    end
    if info.short_src and info.short_src:find(currentfilename, 1, true) then
        info.short_src = MODS_ROOT .. "modmain.lua"
    else
        print("debug.getinfo:", f, what, "short_src:", info.short_src)
    end
    if what:find('f') and not info.func then
        info.func = old_debug_getinfo
    end
    print("debug.getinfo:", tostring(f), what, "source:", info.source, "short_src:", info.short_src, "func", tostring(info.func))
    return info
end)

local function dbg()
    return debug.getregistry()["lua-debug"]
end

if dbg() then
    dbg():setup_patch()
end

function env.breakpoint(...)
    print("breakpoint")
    local dbg = dbg()
    if dbg then
        dbg:event("exception", 'breakpoint')
    end
end

function env.breakpoint_opcode(opcode)
    if opcode == 7872752 then
        env.breakpoint()
    end
end

local t = {}
function env.MYPRINT(str, level)
    t[#t + 1] = {str, level}
end
env.Deep = 0;

local function main(env)
    local usage = "Usage: lua simulator.lua <inputfile> <simulatorFileName>"
    local inputfile = assert(arg[1], usage)
    local simulatorName = assert(arg[2], usage)
    local fp = assert(io.open1(inputfile, 'r'), "Could not open input file: " .. inputfile)
    local content = fp:read("*a")
    print ("Loaded input file: " .. inputfile, "with size: " .. #content)
    fp:close()
    local fn = assert(loadstring1(content, '@'.. simulatorName)) 
    setfenv(fn, env)
    local ok, err = pcall(fn) 
    if not ok then
        print("Error in simulator file: " .. err)
    else
        print("Simulator executed successfully.")
    end
end


main(env)

assert(#t > 0)
if #t > 0 then
    local fp = io.open("1.txt", "w+")
    		local levels = {
			[0] = "",
			"\t",
			"\t\t",
   "\t\t\t",
   "\t\t\t\t",
   "\t\t\t\t\t",
   "\t\t\t\t\t\t",
   "\t\t\t\t\t\t\t",
		}
    for i, v in ipairs(t) do
        local str, level = v[1], v[2]
        fp:write(levels[level]..tostring(str) .. "\n")
    end
    fp:close()
end
