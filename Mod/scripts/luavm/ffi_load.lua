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
local loaded_paths
local function load_library(lib_name, lib_path, ext_path)
    local suffixes = get_library_suffix()

    local separator = platform == "windows" and "\\" or "/"
    local base_path = lib_path and (lib_path .. separator) or ""

    for _, suffix in ipairs(suffixes) do
        local full_name = base_path .. lib_name .. suffix
        loaded_paths[#loaded_paths + 1] = full_name
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

local string_gmatch = string.gmatch
local string_match = string.match

local function load_library_ex(lib_name, lib_path)
    loaded_paths = {}
    local ok, lib, full_name = pcall(load_library, lib_name)
    if ok then
        return lib, full_name
    end
    if lib_path then
        ok, lib, full_name = pcall(load_library, lib_name, lib_path)
        if ok then
            return lib, full_name
        end
    end

    for k, _ in string_gmatch(package.fficpath, "[^;]+") do
        local so_path = string_match(k, "(.*/)")
        if so_path then
            ok, lib, full_name = pcall(load_library, lib_name, so_path)
            if ok then
                return lib, full_name
            end
        end
    end
    error("Failed to load library '" .. lib_name .. "' with any supported suffix on " .. platform .. ":\n" .. table.concat(loaded_paths, "\n"))
end


return load_library_ex