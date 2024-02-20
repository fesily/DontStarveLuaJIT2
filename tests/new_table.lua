---@param tab table
function table.reverse(tab)
    local size = #tab
    local newTable = {}

    for i, v in ipairs(tab) do
        newTable[size - i + 1] = v
    end

    return newTable
end

function table.reverse1(tab)
    local size = #tab
    local newTable = {}
    for i = 1, size - 1 do
        newTable[i] = tab[size - i + 1]
    end
    newTable[size] = tab[1]
    return newTable
end

local function test(fn)
    local tab = fn { 1, 2, 3, 4, 5 }
    assert(table.concat(tab) == "54321", print(table.concat(tab)))
    assert(tab[1] == 5)
    assert(tab[2] == 4)
    assert(tab[3] == 3)
    assert(tab[4] == 2)
    assert(tab[5] == 1)
end
print("reverse")
test(table.reverse)
print("reverse1")
test(table.reverse1)