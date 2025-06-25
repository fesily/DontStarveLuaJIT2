-- @module checks
-- Argument type checking API for Lua 5.1 functions

local checks = {}
local checkers = {}

-- Store checkers table globally
_G.checkers = checkers
setmetatable(checkers, { __index = function() return nil end })

-- Helper function to check if actualType matches any expected types
local function matches(actualType, expectedTypes)
    if actualType == expectedTypes then return true end
    
    for type in string.gmatch(expectedTypes, "[^|]+") do
        if actualType == type then return true end
    end
    return false
end

-- Generate and throw an error
local function error(level, narg, expected, got)
    local ar = debug.getinfo(level + 1, "n")
    local where = debug.getinfo(level + 2, "Sl").short_src .. ":" .. debug.getinfo(level + 2, "Sl").currentline
    error(string.format("%s: bad argument #%d to %s (%s expected, got %s)",
        where, narg, ar.name or "?", expected, got), 0)
end

--- Checks function arguments against expected types
-- @param ... Either a level number followed by type strings, or just type strings
-- @return nothing on success, throws error on failure
function checks(...)
    local args = {...}
    local level = 1
    local start = 1
    
    -- Check if first argument is a level number
    if type(args[1]) == "number" then
        level = args[1]
        start = 2
    end
    
    -- Get info about the calling function
    local ar = debug.getinfo(level, "u")
    if not ar then
        error("checks() must be called within a Lua function", 2)
    end
    
    -- Check each argument
    local i = 1
    while true do
        local expectedType = args[start + i - 1]
        if not expectedType then break end
        
        -- Get the actual argument value using debug.getlocal
        local name, val = debug.getlocal(level + 1, i)
        if not name then break end -- No more locals to check
        
        local actualType = type(val)
        
        -- Handle optional types
        if string.sub(expectedType, 1, 1) == "?" then
            if expectedType == "?" or val == nil then
                i = i + 1
                break
            end
            expectedType = string.sub(expectedType, 2, -1)
        end
        
        -- Check basic type match
        if matches(actualType, expectedType) then
            i = i + 1
            break
        end
        
        -- Check metatable __type
        local mt = getmetatable(val)
        if mt and mt.__type and matches(mt.__type, expectedType) then
            i = i + 1
            break
        end
        
        -- Check custom type checkers
        local found = false
        for t in string.gmatch(expectedType, "[^|]+") do
            if checkers[t] then
                if checkers[t](val) then
                    found = true
                    break
                end
            end
        end
        if found then 
            i = i + 1
            break
        end
        
        -- No match found, throw error
        error(level, i, expectedType, actualType)
        
        i = i + 1
    end
end

-- Export the checks function
_G.checks = checks

return checks