local cases = {
    {
        name = "plain_invalid",
        fmt = "%y",
        value = "abc",
    },
    {
        name = "wrapped_invalid",
        fmt = "[%?]",
        value = "abc",
    },
    {
        name = "width_invalid",
        fmt = "%08y",
        value = "abc",
    },
    {
        name = "precision_invalid",
        fmt = "%.2y",
        value = "abc",
    },
    {
        name = "left_invalid",
        fmt = "%-6y",
        value = "abc",
    },
}

local function normalize_error(err)
    return (tostring(err):gsub("^.-: %", "%%"))
end

for index = 1, #cases do
    local case = cases[index]
    local ok, result = pcall(string.format, case.fmt, case.value)
    if ok then
        io.write("OK\t", case.name, "\t", string.format("%q", result), "\n")
    else
        io.write("ERR\t", case.name, "\t", normalize_error(result), "\n")
    end
end