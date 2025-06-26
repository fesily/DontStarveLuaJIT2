-- =============================================================================
-- Lua 嵌套虚拟机反虚拟化工具 (第三版)
--
-- 核心思想 (根据用户建议重构):
-- 1. 追踪PC序列: 第一次运行，记录下虚拟机调度循环中虚拟程序计数器(PC)的
--    完整执行顺序。
-- 2. 提取与封装: 第二次分析，为每个唯一的PC值，从源文件中提取其对应的代码块，
--    并将其封装成一个独立的、返回下一个PC值的函数 (e.g., `_OPCODE_*()`)。
-- 3. 展开与合成: 第三次生成，创建一个调度表，并根据第一步的PC序列，
--    在一个新的主循环中按顺序调用封装好的函数，从而生成一个无虚拟化、
--    无goto的等效脚本。
-- =============================================================================


-- =============================================================================
-- §1. 配置 (USER MUST EDIT THESE VALUES)
-- =============================================================================
local CONFIG = {
    -- [必填] 需要分析的被混淆的脚本路径
    TARGET_SCRIPT_PATH = "modmain_1234_optimized.lua",

    -- [必填] 输出去虚拟化结果的文件路径
    OUTPUT_PATH = "deobfuscated_output_v3.lua",

    -- [必填] VM 调度循环所在的行号范围。
    -- 通过手动分析 TARGET_SCRIPT_PATH 来确定。
    DISPATCH_LINE_RANGE = {
        start = 30, -- 示例: `while OPCODE do` 所在行
        finish = 700  -- 示例: `end` of the while loop
    },

    -- [必填] 虚拟程序计数器 (PC) 的变量名。
    PC_VARIABLE_NAME = "OPCODE",

    -- [可选，但推荐] VM 调度函数内的局部变量声明行。
    -- 这能确保状态变量（虚拟寄存器）在生成的新函数中是可用的。
    VM_LOCALS_DECLARATION = "local l, z, A, n, B, x, C, o, j, D, E, F, p, G, H",

    -- [可选] 生成的函数接收的参数。
    VM_FUNCTION_ARGS = "f, g, h"
}


-- =============================================================================
-- §2. 阶段一: 动态追踪器 (Tracer)
-- =============================================================================
local Tracer = {}

function Tracer.run()
    print("  -> [阶段 1] 开始追踪 PC 序列...")
    local execution_trace = {}
    local unique_pcs = {}
    local last_captured_pc = nil

    local function hook_function(event, line)
        local info = debug.getinfo(2, "S")
        if not info or info.short_src ~= CONFIG.TARGET_SCRIPT_PATH then return end
        if line < CONFIG.DISPATCH_LINE_RANGE.start or line > CONFIG.DISPATCH_LINE_RANGE.finish then return end

        local i = 1
        while true do
            local name, value = debug.getlocal(2, i)
            if not name then break end
            
            if name == CONFIG.PC_VARIABLE_NAME and value ~= last_captured_pc then
                -- 记录PC执行顺序
                table.insert(execution_trace, value)
                -- 记录唯一的PC值及其首次出现的行号
                if not unique_pcs[value] then
                    unique_pcs[value] = line
                end
                last_captured_pc = value
                break -- 找到PC就够了
            end
            i = i + 1
        end
    end

    local target_chunk, err = loadfile(CONFIG.TARGET_SCRIPT_PATH)
    if not target_chunk then
        print(" !! 错误: 无法加载目标脚本: " .. err)
        return nil, nil
    end

    debug.sethook(hook_function, "l")
    pcall(target_chunk)
    debug.sethook()

    print("  -> [阶段 1] 追踪完成。共记录 " .. #execution_trace .. " 次PC变化，发现 " .. #unique_pcs .. " 个唯一的操作码。")
    return execution_trace, unique_pcs
end

-- =============================================================================
-- §3. 阶段二: 操作码处理器提取器 (HandlerExtractor)
-- =============================================================================
local HandlerExtractor = {}

--- 加载源文件为行数组
function HandlerExtractor.load_source_lines(path)
    local lines = {}
    local file = io.open(path, "r")
    if not file then return nil end
    for line in file:lines() do
        table.insert(lines, line)
    end
    file:close()
    return lines
end

--- 寻找一个代码块的边界 (从'then'到匹配的'end'或'else')
function HandlerExtractor.find_block_bounds(lines, start_line)
    local block_lines = {}
    local nesting = 0
    local in_block = false

    for i = start_line, #lines do
        local line = lines[i]
        
        if string.find(line, "then") then
            nesting = nesting + 1
            if not in_block then
                in_block = true
                -- 从 'then' 之后开始提取
                goto continue
            end
        end

        if in_block then
            -- 检查是否是块的结束
            local is_else, is_end = string.match(line, "^(%s*else)", "^(%s*end)")
            if (is_else or is_end) and nesting == 1 then
                -- 到达了当前块的结尾
                break
            end
            
            table.insert(block_lines, line)

            if is_end then
                 nesting = nesting - 1
            end
        end
        
        ::continue::
    end
    return block_lines
end


function HandlerExtractor.run(unique_pcs, source_lines)
    print("  -> [阶段 2] 开始提取操作码处理器...")
    local handlers = {}
    
    local pc_values = {}
    for pc in pairs(unique_pcs) do
        table.insert(pc_values, pc)
    end
    table.sort(pc_values)

    for _, pc in ipairs(pc_values) do
        local line_num = unique_pcs[pc]
        
        -- 这是一个简化的提取逻辑，它假设每个PC处理器都在一个 if/elseif 块内
        -- 它会向上找到 'if' 或 'elseif'，然后提取整个块
        local search_line = line_num
        local found_header = false
        while search_line > CONFIG.DISPATCH_LINE_RANGE.start do
             local line = source_lines[search_line]
             if string.find(line, "if " .. CONFIG.PC_VARIABLE_NAME) or string.find(line, "else") then
                 -- 找到了块的开头，现在提取从'then'开始的内容
                 local block_content = HandlerExtractor.find_block_bounds(source_lines, search_line)
                 handlers[pc] = block_content
                 found_header = true
                 break
             end
             search_line = search_line - 1
        end
        if not found_header then
            print(" !! 警告: 无法为 PC " .. pc .. " 在行 " .. line_num .. " 附近找到处理器块。")
        end
    end
    print("  -> [阶段 2] 提取完成。")
    return handlers
end


-- =============================================================================
-- §4. 阶段三: 代码生成器 (CodeGenerator)
-- =============================================================================
local CodeGenerator = {}

function CodeGenerator.run(pc_sequence, handlers)
    print("  -> [阶段 3] 开始生成最终代码...")
    local output = {}

    table.insert(output, "-- Generated by Lua De-virtualizer Tool V3 on " .. os.date())
    table.insert(output, "-- This code is based on the user's proposed three-step methodology.\n")

    -- 函数头
    table.insert(output, "local function devirtualized_main(" .. (CONFIG.VM_FUNCTION_ARGS or "") .. ")")
    table.insert(output, "  " .. (CONFIG.VM_LOCALS_DECLARATION or "-- No local variables declared in config"))
    table.insert(output, "\n  -- =========================================================")
    table.insert(output, "  --  Phase 1: Opcode Handler Functions")
    table.insert(output, "  -- =========================================================\n")

    local dispatch_table = {}

    -- 生成所有独立的处理器函数
    for pc, code_lines in pairs(handlers) do
        table.insert(output, "  local function _OPCODE_" .. pc .. "()")
        for _, line in ipairs(code_lines) do
            table.insert(output, "    " .. line)
        end
        -- 每个函数都返回下一个PC值
        table.insert(output, "    return " .. CONFIG.PC_VARIABLE_NAME)
        table.insert(output, "  end\n")
        
        dispatch_table[pc] = "_OPCODE_" .. pc .. "()"
    end

    table.insert(output, "  -- =========================================================")
    table.insert(output, "  --  Phase 2: Dispatch Table")
    table.insert(output, "  -- =========================================================")
    table.insert(output, "  local dispatch_table = {")
    for pc, _ in pairs(handlers) do
        table.insert(output, "    [" .. pc .. "] = _OPCODE_" .. pc .. ",")
    end
    table.insert(output, "  }\n")


    table.insert(output, "  -- =========================================================")
    table.insert(output, "  --  Phase 3: De-virtualized Execution Loop")
    table.insert(output, "  -- =========================================================\n")
    
    -- 从追踪记录中获取初始PC
    local initial_pc = pc_sequence[1]
    table.insert(output, "  local current_pc = " .. initial_pc)
    
    table.insert(output, "  while current_pc do")
    table.insert(output, "    local handler = dispatch_table[current_pc]")
    table.insert(output, "    if handler then")
    table.insert(output, "      current_pc = handler()")
    table.insert(output, "    else")
    table.insert(output, "      print('!! EXECUTION HALT: No handler found for PC: ' .. tostring(current_pc))")
    table.insert(output, "      break")
    table.insert(output, "    end")
    table.insert(output, "  end")
    table.insert(output, "end")
    
    print("  -> [阶段 3] 代码生成完毕。")
    return table.concat(output, "\n")
end

-- =============================================================================
-- §5. 主程序入口
-- =============================================================================
local function main()
    print("==================================================")
    print("启动 Lua 嵌套 VM 反虚拟化工具 (V3)")
    print("==================================================")

    -- 阶段一：追踪
    local pc_sequence, unique_pcs = Tracer.run()
    if not pc_sequence or #pc_sequence == 0 then
        print("\n!! 致命错误: 未能生成执行轨迹。请检查配置。")
        return
    end

    -- 阶段二：提取
    local source_lines = HandlerExtractor.load_source_lines(CONFIG.TARGET_SCRIPT_PATH)
    if not source_lines then
        print("\n!! 致命错误: 无法读取源文件 " .. CONFIG.TARGET_SCRIPT_PATH)
        return
    end
    local handlers = HandlerExtractor.run(unique_pcs, source_lines)

    -- 阶段三：生成
    local deobfuscated_code = CodeGenerator.run(pc_sequence, handlers)
    
    local file, err = io.open(CONFIG.OUTPUT_PATH, "w")
    if file then
        file:write(deobfuscated_code)
        file:close()
        print("\n==================================================")
        print("所有阶段已完成！去虚拟化代码已保存至: " .. CONFIG.OUTPUT_PATH)
        print("==================================================")
    else
        print("\n!! 致命错误: 无法写入输出文件: " .. err)
    end
end

main()
