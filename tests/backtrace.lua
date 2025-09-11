local function LJ_DS_tailcall(___tailcall, ...)
    return ___tailcall(...)
end

local function Check()
    local info = debug.getinfo(1, "nSlt")
    assert(info.name == "" and info.namewhat == "")
    local info2 = debug.getinfo(2, 'nSlt')
    assert(info2.istailcall)
    local message = debug.traceback()
    assert(message:find("(tail call):?", 1, true))
    assert(not message:find("___tailcall", 1, true))
end

local function A()
    return Check()
end

A()
