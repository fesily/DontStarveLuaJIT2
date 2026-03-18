local masks = {1, 3, 7, 15, 31}

local corpus = {
    "a",
    "aa",
    "aaa",
    "ab",
    "ba",
    "LeftClick",
    "RightClick",
    "ActionButton",
    "AttackButton",
    "InspectButton",
    "ResurrectButton",
    "ControllerActionButton",
    "_G",
    "package.loaded",
    "math.mod",
    "string.dump",
    "abcdefghijklmnopqrstuvwx",
    "abcdefghijklmnopqrstuvwy",
    "0123456789abcdefghijklmnopqrstuvwxyz",
    "repeat:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "repeat:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
    "collision-probe-1",
    "collision-probe-2",
    "collision-probe-3",
}

local case_list = {
    {
        name = "rpc",
        keys = {
            "LeftClick",
            "RightClick",
            "ActionButton",
            "AttackButton",
            "InspectButton",
            "ResurrectButton",
            "ControllerActionButton",
        },
    },
    {
        name = "lengths",
        keys = {
            "a",
            "aa",
            "aaa",
            "ab",
            "ba",
            "abcdefghijklmnopqrstuvwx",
            "abcdefghijklmnopqrstuvwy",
            "0123456789abcdefghijklmnopqrstuvwxyz",
        },
    },
    {
        name = "compat",
        keys = {
            "_G",
            "package.loaded",
            "math.mod",
            "string.dump",
            "collision-probe-1",
            "collision-probe-2",
            "collision-probe-3",
            "repeat:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "repeat:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
        },
    },
}

local function bxor32(left, right)
    local result = 0
    local bit_value = 1

    while left > 0 or right > 0 do
        local left_bit = left % 2
        local right_bit = right % 2
        if left_bit ~= right_bit then
            result = result + bit_value
        end
        left = math.floor(left / 2)
        right = math.floor(right / 2)
        bit_value = bit_value * 2
    end

    return result
end

local function lua51_hash(str)
    local len = #str
    local hash = len
    local step = math.floor(len / 32) + 1

    for index = len, step, -step do
        local byte = string.byte(str, index)
        hash = bxor32(hash, (hash * 32 + math.floor(hash / 4) + byte) % 4294967296)
    end

    return hash % 4294967296
end

local function qlist(list)
    local out = {}
    for index = 1, #list do
        out[index] = string.format("%q", list[index])
    end
    return table.concat(out, ",")
end

local function emit_hashes()
    for index = 1, #corpus do
        local str = corpus[index]
        local hash = lua51_hash(str)
        local buckets = {}
        for bucket_index = 1, #masks do
            buckets[bucket_index] = tostring(hash % (masks[bucket_index] + 1))
        end
        io.write(
            "HASH\t",
            tostring(index),
            "\t",
            string.format("%q", str),
            "\t",
            tostring(hash),
            "\t",
            table.concat(buckets, ","),
            "\n"
        )
    end
end

local function build_literal(keys)
    local fields = {}
    for index = 1, #keys do
        fields[index] = string.format("[%q]=%d", keys[index], index)
    end
    local chunk = assert(loadstring("return {" .. table.concat(fields, ",") .. "}"))
    return chunk()
end

local function build_assign(keys)
    local t = {}
    for index = 1, #keys do
        t[keys[index]] = index
    end
    return t
end

local function build_reverse_assign(keys)
    local t = {}
    for index = #keys, 1, -1 do
        t[keys[index]] = index
    end
    return t
end

local function build_reinsert(keys)
    local t = {}
    for index = 1, #keys do
        t[keys[index]] = index
    end
    for index = 1, #keys, 2 do
        local key = keys[index]
        local value = t[key]
        t[key] = nil
        t[key] = value
    end
    return t
end

local function emit_order(case_name, mode_name, t)
    local order = {}
    for key in pairs(t) do
        order[#order + 1] = key
    end
    io.write(
        "ORDER\t",
        case_name,
        "\t",
        mode_name,
        "\t",
        tostring(#order),
        "\t",
        qlist(order),
        "\n"
    )
end

emit_hashes()

for index = 1, #case_list do
    local case = case_list[index]
    emit_order(case.name, "literal", build_literal(case.keys))
    emit_order(case.name, "assign", build_assign(case.keys))
    emit_order(case.name, "reverse_assign", build_reverse_assign(case.keys))
    emit_order(case.name, "reinsert", build_reinsert(case.keys))
end