local inputfile = arg[1]
local outputfile = arg[2]
local const_table_file = arg[3]
local const_table_name = arg[4]
local pattern
local execute
if #arg > 4 then
    for i = 5, #arg do
        -- match --pattern -p
        if arg[i] == "--pattern" or arg[i] == "-p" then
            i = i + 1
            if i > #arg then
                print("Missing pattern argument after " .. arg[i - 1])
                return
            end
            pattern = arg[i]
        end
        -- match -e --execute
        if arg[i] == "--execute" or arg[i] == "-e" then
            i = i + 1
            if i > #arg then
                print("Missing execute argument after " .. arg[i - 1])
                return
            end
            execute = arg[i]
        end
    end
end

if not pattern then
    pattern = "("..const_table_name .. "%s*%[(.-)%]"..")"
end

local default_value = "nil"
if not execute then
    execute = ""
else
    default_value= nil
end
if const_table_name == "nil" then
    const_table_name = ''
    print("const file top table")
end

if not inputfile or not outputfile or not const_table_name or not const_table_file then
    print("Usage: lua replace_constants.lua <inputfile> <outputfile> <const_table_file> <const_table_name>")
    print("Example: lua replace_constants.lua input.lua output.lua const_table.lua a")
    return
end

print("Input file: " .. inputfile)
print("Output file: " .. outputfile)
print("Constant table file: " .. const_table_file)
print("Constant table name: " .. const_table_name)
print("Pattern: " .. pattern)
print("Execute expression: " .. execute)


local file = io.open(inputfile, "r")
if not file then
    print("Could not open input file: " .. inputfile)
    return
end
local source_code = file:read("*a")
file:close()
local const_file = io.open(const_table_file, "r")
if not const_file then
    print("Could not open constant table file: " .. const_table_file)
    return
end
local const_table_content = const_file:read("*a")
const_file:close()
local const_table = loadstring(const_table_content)()

local function main()
    -- 匹配 table_name[key] 的模式
    -- 函数：替换源代码中的常量表访问表达式
    local function replace_constants(source, table_name, table)
        -- 替换函数
        local function replacer(original_val, key_str)
            -- 尝试将 key_str 转换为 Lua 值
            local ok, key = pcall(loadstring("return " .. execute .. " " .. key_str))
            if not ok then
                print("\t Error evaluating key: " .. key_str .. ". Using original :", original_val)
                return original_val
            end
            if key then
                local value = table[key]
                if value then
                    -- 如果值是字符串，则返回带引号的字符串
                    if type(value) == "string" then
                        return string.format("%q", value)
                    else
                        return tostring(value)
                    end
                end
            end
            if default_value then
                -- use nil
                print("\t Key '" .. key_str .. "' not found in table '" .. table_name .. "'. Using default_value:"..default_value)
                return default_value
            end
            -- 如果没有找到值，返回原始 key_str
            print("\t Key '" .. key_str .. "' not found in table '" .. table_name .. "'. Returning original key.")
            return original_val
        end

        -- 执行替换
        local result = source:gsub(pattern, replacer)
        return result
    end
    local consttable = const_table_name == '' and const_table or const_table[const_table_name]
    return replace_constants(source_code, const_table_name, consttable)
end
local modified_code = main()
if not modified_code then
    print("Error processing the source code.")
    return
end
local output_file = io.open(outputfile, "w")
if not output_file then
    print("Could not open output file: " .. outputfile)
    return
end
output_file:write(modified_code)
output_file:close()
-- lua tests/sect/fold_const.lua tests/2847908822/modmain2.lua tests/2847908822/modmain3.lua consts.lua a
-- lua tests/sect/fold_const.lua tests/2847908822/modmain3.lua tests/2847908822/modmain4.lua consts.lua c -p "(get%_const%_string%((.-)%))" -e "-11118+"
-- .\builds\ninja-multi-vcpkg\src\lua51original\Debug\lua.exe tests/sect/fold_const.lua .\tests\2847908822\modmain_.lua .\tests\2847908822\modmain_1.lua .\tests\2847908822\const_string_table.decoded.lua "nil" -p "(get%_const%_string%((.-)%))" -e "50983+" 