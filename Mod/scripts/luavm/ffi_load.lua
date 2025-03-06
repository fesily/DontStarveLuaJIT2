local ffi = require'ffi'
local platform = jit.os

local function get_library_suffix()
    if platform == "Windows" then
        return { ".dll" }
    elseif platform == "OSX" then
        return { ".dylib", ".so" }
    else
        return { ".so" }
    end
end

local function load_library(lib_name, lib_path, ext_path)
    local suffixes = get_library_suffix()

    local separator = platform == "windows" and "\\" or "/"
    local base_path = lib_path and (lib_path .. separator) or ""

    for _, suffix in ipairs(suffixes) do
        local full_name = base_path .. lib_name .. suffix
        local ok, lib = pcall(ffi.load, full_name)
        if ok then
            return lib, full_name
        end
    end

    if not ext_path and lib_path and platform ~=  'Windows' then
        return load_library(lib_name, lib_path and (lib_path .. separator .. "lib64"), true)        
    end
    error("Failed to load library '" .. lib_name .. "' with any supported suffix on " .. platform)
end

return load_library