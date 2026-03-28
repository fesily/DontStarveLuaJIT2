local keys = {
    "LeftClick",
    "RightClick",
    "ActionButton",
    "AttackButton",
    "InspectButton",
    "ResurrectButton",
    "ControllerActionButton",
}

local function emit(tag, t)
    local order = {}
    for key in pairs(t) do
        order[#order + 1] = key
    end
    io.write(tag, "\t", table.concat(order, ","), "\n")
end

local function build_literal()
    local fields = {}
    for index = 1, #keys do
        fields[index] = string.format("[%q]=%d", keys[index], index)
    end
    return assert(loadstring("return {" .. table.concat(fields, ",") .. "}"))()
end

local function build_assign()
    local t = {}
    for index = 1, #keys do
        t[keys[index]] = index
    end
    return t
end

emit("literal", build_literal())
emit("assign", build_assign())