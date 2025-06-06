local modinfo_path = arg[2] or "Mod/modinfo.lua"
local target_path = arg[3] or "src/modinfo.hpp"

print("Loading modinfo from: " .. modinfo_path)
print("Generating C++ header file at: " .. target_path)
dofile(modinfo_path)


---@class configuration_option
---@field name string
---@field label string
---@field options {description: string, data: any}[]
---@field default any

---@type configuration_option[]
local configuration_options = _G.configuration_options
if not configuration_options then
    print("No configuration options found in modinfo.")
    return
end

local context = [[
#pragma once
#include <string_view>
#include <string>
template <typename T, size_t N>
struct ModConfigurationOption {
    std::string_view name;
    T default_value;
    T options[N];
};
struct ModConfigurationOptions {
]]

for index, configuration_option in ipairs(configuration_options) do
    if type(configuration_option) ~= "table" then
        print("Invalid configuration option at index " .. index .. ": not a table")
        goto continue
    end

    if not configuration_option.name or not configuration_option.label or not configuration_option.options or not configuration_option.default then
        print("Invalid configuration option at index " .. index .. ": missing required fields")
        goto continue
    end

    print("Configuration Option " .. index .. ":")
    print("  Name: " .. configuration_option.name)
    print("  Label: " .. configuration_option.label)
    print("  Default: " .. tostring(configuration_option.default))
    print("  Options:")
    local data_type = type(configuration_option.default)
    assert(data_type == "boolean" or data_type == "number" or data_type == "string",
        "Unsupported data type for default value: " .. data_type)
    local cpp_data_type
    if data_type == "boolean" then
        cpp_data_type = "bool"
    elseif data_type == "number" then
        cpp_data_type = "double" -- Use double for numeric values
    elseif data_type == "string" then
        cpp_data_type = "std::string"
    else
        error("Unsupported data type for default value: " .. data_type)
    end

    local function cast_to_cpp_string(value)
        if type(value) == "boolean" then
            return value and "true" or "false"
        elseif type(value) == "number" then
            return tostring(value)
        elseif type(value) == "string" then
            return string.format("%q", value) -- Use %q to escape strings properly
        else
            error("Unsupported data type for casting: " .. type(value))
        end
    end

    local cpp_data_N = #configuration_option.options
    local cpp_data_Name = configuration_option.name
    assert(cpp_data_N > 0, "No options provided for configuration option: " .. configuration_option.name)
    -- check data_name format is standard cpp variable name
    assert(cpp_data_Name:match("^[a-zA-Z_][a-zA-Z0-9_]*$"), "Invalid C++ variable name: " .. cpp_data_Name)

    local options_string = "{"
    for i, option in ipairs(configuration_option.options) do
        assert(type(option) == "table", "Option must be a table: " .. tostring(option))
        assert(type(option.data) == data_type,
            "Option data type mismatch for " ..
            option.description .. ": expected " .. data_type .. ", got " .. type(option.data))
        assert(option.data ~= nil, "Option must have data: " .. tostring(option))

        options_string = options_string .. cast_to_cpp_string(option.data)
        if (i < #configuration_option.options) then
            options_string = options_string .. ", "
        end
    end
    options_string = options_string .. "}"
    print("  Options String: " .. options_string)
    local option_context = ([[ModConfigurationOption<%s,%d> %s = {"%s", %s, %s};]]):format(cpp_data_type, cpp_data_N,
        cpp_data_Name, cpp_data_Name, cast_to_cpp_string(configuration_option.default), options_string)
    context = context .. "\n" .. option_context
    ::continue::
end

context = context .. "\n};\n\n"

io.open(target_path, "w"):write(context)
print("C++ header file generated successfully.")
