-- 获取命令行参数
local input_file = arg[1]
local output_file = arg[2]

-- 检查是否提供了输入和输出文件路径
if not input_file or not output_file then
    print("Usage: lua script.lua <input_file> <output_file>")
    os.exit(1)
end

-- 加载输入的 Lua 配置文件
local config = dofile(input_file)

-- 提取 enabled=true 的键
local enabled_keys = {}
for key, value in pairs(config) do
    if value.enabled == true then
        table.insert(enabled_keys, key)
    end
end

-- 将结果写入输出文件
local file = io.open(output_file, "w")
if not file then
    print("Error: Could not open output file " .. output_file)
    os.exit(1)
end

-- 写入 enabled_keys 数组
for i, key in ipairs(enabled_keys) do
    file:write("ServerModSetup(\"" .. key .. "\")\n")
end

file:close()
print("Enabled keys written to " .. output_file)

--[[
.\builds\ninja-multi-vcpkg\luajit\Debug\luajit.exe .\tools\modoverrides2modsetup.lua C:\Users\fesil\Documents\Klei\DoNotStarveTogether\Cluster_2\Master\modoverrides.lua dedicated_server_mods_setup.lua
]]
