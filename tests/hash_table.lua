local RPC_HANDLERS = {
    LeftClick = function()
    end,

    RightClick = function()
    end,

    ActionButton = function()
    end,

    AttackButton = function()
    end,

    InspectButton = function()
    end,

    ResurrectButton = function()
    end,

    ControllerActionButton = function()
    end,
}
local t = {}
local i = 1
for k, v in pairs(RPC_HANDLERS) do
    t[i] = k
    i = i + 1
end
i = nil


local RPC_HANDLERS2 =
{
}

RPC_HANDLERS2.LeftClick = function()
end

RPC_HANDLERS2.RightClick = function()
end

RPC_HANDLERS2.ActionButton = function()
end

RPC_HANDLERS2.AttackButton = function()
end

RPC_HANDLERS2.InspectButton = function()
end

RPC_HANDLERS2.ResurrectButton = function()
end

RPC_HANDLERS2.ControllerActionButton = function()
end

local t1 = {}
local i = 1
for k, v in pairs(RPC_HANDLERS2) do
    t1[i] = k
    i = i + 1
end
i = nil

assert(#t1 == #t)
for index, value in ipairs(t) do
    assert(value == t1[index], table.concat({value,t1[index]},"-"))
end
