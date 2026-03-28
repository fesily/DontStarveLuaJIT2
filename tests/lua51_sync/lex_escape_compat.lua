local cases = {
    {
        name = "hex_escape_literalized",
        code = "return '\\x41'",
    },
    {
        name = "unicode_escape_literalized",
        code = "return '\\u{41}'",
    },
    {
        name = "z_escape_literalized",
        code = "return '\\zA'",
    },
    {
        name = "decimal_escape_kept",
        code = "return '\\97'",
    },
    {
        name = "newline_escape_kept",
        code = "return '\\n'",
    },
}

local function encode_bytes(str)
    local out = {}
    for index = 1, #str do
        out[index] = tostring(string.byte(str, index))
    end
    return table.concat(out, ",")
end

for index = 1, #cases do
    local case = cases[index]
    local fn, err = loadstring(case.code)
    if not fn then
        io.write("ERR\t", case.name, "\t", tostring(err), "\n")
    else
        local ok, result = pcall(fn)
        if not ok then
            io.write("RUNTIME_ERR\t", case.name, "\t", tostring(result), "\n")
        else
            io.write(
                "OK\t",
                case.name,
                "\t",
                string.format("%q", result),
                "\t",
                encode_bytes(result),
                "\n"
            )
        end
    end
end