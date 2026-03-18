local RPC_HANDLERS = {
    LeftClick = 1,
    RightClick = 2,
    ActionButton = 3,
    AttackButton = 4,
    InspectButton = 5,
    ResurrectButton = 6,
    ControllerActionButton = 7,
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
RPC_HANDLERS2.LeftClick = 1
RPC_HANDLERS2.RightClick = 2
RPC_HANDLERS2.ActionButton = 3
RPC_HANDLERS2.AttackButton = 4
RPC_HANDLERS2.InspectButton = 5
RPC_HANDLERS2.ResurrectButton = 6
RPC_HANDLERS2.ControllerActionButton = 7

local t1 = {}
local i = 1
for k, v in pairs(RPC_HANDLERS2) do
    t1[i] = k
    i = i + 1
end
i = nil

assert(#t1 == #t)
for index, value in ipairs(t) do
    assert(value == t1[index], table.concat({index,value,t1[index]},"-"))
end
