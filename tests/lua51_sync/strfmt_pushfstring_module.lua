local module_path = assert(os.getenv("STRFMT_PUSHFSTRING_MODULE"), "missing STRFMT_PUSHFSTRING_MODULE")
local loader = assert(package.loadlib(module_path, "luaopen_strfmt_pushfstring_module"))
local results = assert(loader())

local order = {
    "plain_invalid",
    "wrapped_invalid",
    "width_invalid",
    "precision_invalid",
    "left_invalid",
}

for index = 1, #order do
    local name = order[index]
    io.write("OK\t", name, "\t", string.format("%q", results[name]), "\n")
end