
GLOABL = _G

local fn = assert(loadfile("tests/sect/fengxuemy.lua"))
local env = {}
env.env = env
function debug.sethook(...)
    
end
function io.open(filename, mode)
    assert(false)
end
setfenv(fn, setmetatable(env, {__index = _G}))
fn()