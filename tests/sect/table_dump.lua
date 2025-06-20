local function escape_string(s)
    s = s:gsub('\\', '\\\\')
    s = s:gsub('"', '\\"')
    s = s:gsub('\n', '\\n')
    return s
end

local function is_valid_identifier(s)
    if type(s) ~= "string" then return false end
    if not s:match("^[%a_][%w_]*$") then return false end
    local keywords = { "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in",
        "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while" }
    for _, kw in ipairs(keywords) do
        if s == kw then return false end
    end
    return true
end
local table_to_code
local function to_lua_code(value, indent, seen)
    local t = type(value)
    if t == "string" then
        return { '[[' .. escape_string(value) .. ']]' }
    elseif t == "number" or t == "boolean" then
        return { tostring(value) }
    elseif t == "table" then
        return table_to_code(value, indent, seen)
    else
        return { "--[[" .. t .. "]]" }
    end
end

function table_to_code(t, indent, seen)
    if seen[t] then
        return { "--[[cycle detected]]" }
    end
    seen[t] = true
    local lines = {}
    local function add_line(line)
        table.insert(lines, ("  "):rep(indent) .. line)
    end
    add_line("{")
    indent = indent + 1
    local i = 1
    while t[i] ~= nil do
        local value_lines = to_lua_code(t[i], indent, seen)
        for _, line in ipairs(value_lines) do
            add_line(line .. ",")
        end
        i = i + 1
    end
    local dict_keys = {}
    for k in pairs(t) do
        if type(k) ~= "number" or k < 1 or k >= i or math.floor(k) ~= k then
            table.insert(dict_keys, k)
        end
    end
    table.sort(dict_keys, function(a, b)
        return tostring(a) < tostring(b)
    end)
    for _, k in ipairs(dict_keys) do
        local key_str
        if type(k) == "string" and is_valid_identifier(k) then
            key_str = k
        else
            local key_lines = to_lua_code(k, indent, seen)
            key_str = "[" .. table.concat(key_lines, "\n") .. "]"
        end
        local value_lines = to_lua_code(t[k], indent, seen)
        add_line(key_str .. " = " .. value_lines[1])
        for j = 2, #value_lines do
            add_line(value_lines[j])
        end
        add_line(",")
    end
    indent = indent - 1
    add_line("}")
    return lines
end

local function table_to_lua_file(t, filename)
    local seen = {}
    local lines = to_lua_code(t, 0, seen)
    if #lines > 0 then
        lines[1] = "return " .. lines[1]
    end
    local file = io.open(filename, "w")
    file:write(table.concat(lines, "\n"))
    file:close()
end

-- 转换dump多个表, 输入为table, name
local function table_to_lua_file_multiple(filename, ...)
    local seen = {}
    local lines = {}
    for i = 1, select("#", ...) / 2 do
        local index = ((i - 1) * 2) + 1
        local t, name = select(index, ...)
        assert(type(t) == "table", "Expected table at index " .. index)
        assert(type(name) == "string", "Expected string at index " .. (index + 1))
        if not name or not is_valid_identifier(name) then
            error("Invalid name for table " .. index .. ": " .. tostring(name))
        end
        local code_lines = to_lua_code(t, 0, seen)
        if #code_lines > 0 then
            code_lines[1] = name .. " = " .. code_lines[1]
            table.insert(lines, table.concat(code_lines, "\n"))
        end
    end
    local file = io.open(filename, "w")
    file:write("return {\n" .. table.concat(lines, ",\n") .. "\n}\n")
    file:close()
end

return {
    table_to_lua_file = table_to_lua_file,
    to_lua_code = to_lua_code,
    table_to_lua_file_multiple = table_to_lua_file_multiple,
}
