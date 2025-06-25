--[[
这是一个lua的编译器,用于常量传播和常量折叠的优化。
]]

package.path = package.path .. ';3rd/?.lua;3rd/?/init.lua'

require 'metalua.loader'


local Optimizer = {}

-- ----------------------------------------------------------------------------
-- 1. 格理论与环境 (Lattice Theory & Environment)
-- ----------------------------------------------------------------------------

-- 定义格的特殊值
local TOP = { name = "TOP" }       -- 未定义/未分析
local BOTTOM = { name = "BOTTOM" } -- 非常量 (Not-a-Constant)

-- 会合 (meet) 运算符 (⊓)
-- 合并来自不同控制流路径的信息 [7]
local function meet(v1, v2)
    if v1 == v2 then return v1 end
    if v1 == TOP then return v2 end
    if v2 == TOP then return v1 end
    return BOTTOM -- 任何冲突都会导致非常量
end

-- 深度拷贝一个环境或值
local function deepcopy(orig)
    if orig == TOP or orig == BOTTOM then
        return orig -- 直接返回特殊值
    end
    local orig_type = type(orig)
    if orig_type == 'table' then
        local copy = {}
        for orig_key, orig_value in pairs(orig) do
            copy[deepcopy(orig_key)] = deepcopy(orig_value)
        end
        return copy
    else
        return orig
    end
end

-- 环境/作用域管理器
local EnvManager = {}
EnvManager.__index = EnvManager

function EnvManager:new()
    local o = { scopes = { {} } } -- 作用域栈，从全局作用域开始
    setmetatable(o, self)
    return o
end

function EnvManager:push_scope()
    table.insert(self.scopes, {})
end

function EnvManager:pop_scope()
    table.remove(self.scopes)
end

-- 在环境中声明一个新变量
function EnvManager:declare(name, value)
    if name == nil then
        return
    end
    self.scopes[#self.scopes][name] = value or TOP
end

-- 更新一个已存在变量的值
function EnvManager:update(name, value)
    assert(type(name) == 'string', "Variable name must be a string")
    for i = #self.scopes, 1, -1 do
        if self.scopes[i][name] ~= nil then
            self.scopes[i][name] = value
            return
        end
    end
    -- 如果是全局变量赋值
    self.scopes[1][name] = value
end

-- 查找变量的值
function EnvManager:lookup(name)
    for i = #self.scopes, 1, -1 do
        if self.scopes[i][name] ~= nil then
            return self.scopes[i][name]
        end
    end
    return TOP -- 未找到，视为未定义
end

-- 合并两个环境状态
function EnvManager:merge(env1, env2)
    local merged_env = deepcopy(env1)
    for name, value2 in pairs(env2) do
        local value1 = merged_env[name] or TOP
        merged_env[name] = meet(value1, value2)
    end
    return merged_env
end

-- ----------------------------------------------------------------------------
-- 2. 分析阶段 (Analysis Pass)
-- ----------------------------------------------------------------------------

local AnalysisVisitor = {}
local analyze_node -- 递归函数前向声明

-- 存储每个AST节点的分析结果 (变量环境)
local node_environments = {}

-- 对操作符进行常量折叠
local function fold_op(op, v1, v2)
    if v1 == TOP or v1 == BOTTOM or (v2 ~= nil and (v2 == TOP or v2 == BOTTOM)) then
        return BOTTOM
    end
    local ops = {
        add = function(a, b) return a + b end,
        sub = function(a, b) return a - b end,
        mul = function(a, b) return a * b end,
        div = function(a, b) return a / b end,
        eq = function(a, b) return a == b end,
        lt = function(a, b) return a < b end,
        le = function(a, b) return a <= b end,
        gt = function(a, b) return a > b end,
        ge = function(a, b) return a >= b end,
        ['and'] = function(a, b) return a and b end,
        ['or'] = function(a, b) return a or b end,
        ['not'] = function(a) return not a end,
    }
    if ops[op] then
        return ops[op](v1, v2)
    end
    return BOTTOM -- 不支持的操作符
end

function AnalysisVisitor:visit_block(block, env)
    for _, stat in ipairs(block) do
        analyze_node(stat, env)
    end
end

function AnalysisVisitor:visit_Id(node, env)
    return env:lookup(node[1])
end

function AnalysisVisitor:visit_Number(node, env) return node[1] end

function AnalysisVisitor:visit_String(node, env) return node[1] end

function AnalysisVisitor:visit_True(node, env) return true end

function AnalysisVisitor:visit_False(node, env) return 'false' end

function AnalysisVisitor:visit_Nil(node, env) return 'nil' end

function AnalysisVisitor:visit_Op(node, env)
    local op = node[1]
    local v1 = analyze_node(node[2], env)
    if #node == 3 then -- 二元操作
        local v2 = analyze_node(node[3], env)
        return fold_op(op, v1, v2)
    else -- 一元操作
        return fold_op(op, v1)
    end
end

function AnalysisVisitor:visit_Set(node, env)
    local lhs, rhs = node[1], node[2]
    local values = {}
    for _, expr in ipairs(rhs) do
        table.insert(values, analyze_node(expr, env))
    end

    for i, var_node in ipairs(lhs) do
        if var_node.tag == 'Id' then
            env:update(var_node[1], values[i] or TOP)
        else
            -- 对表索引等复杂赋值，我们保守地假设其状态为 BOTTOM
            -- (这部分可以进一步扩展以支持表内常量传播)
        end
    end
end

function AnalysisVisitor:visit_Local(node, env)
    local names, exprs = node[1], node[2]
    local values = {}
    if exprs then
        for _, expr in ipairs(exprs) do
            local value = analyze_node(expr, env)
            table.insert(values, value)
        end
    end

    for i, name_node in ipairs(names) do
        env:declare(name_node[1], values[i] or TOP)
    end
end

local function node_const_is_false(val)
    return val == 'nil' or val == false or val == 'false'
end

function AnalysisVisitor.cond_false(node, env)
    local val = analyze_node(node, env)
    return node_const_is_false(val)
end

function AnalysisVisitor:visit_If(node, env)
    assert(#node >= 2, "If node must have at least one condition and one branch")
    for i = 1, #node, 2 do
        if i + 1 > #node then
            break -- else分支
        end
        -- 分析主 if 条件
        local skip_then = self:cond_false(node[1], env)
        node_environments[node[i]] = deepcopy(env.scopes) -- 保存条件节点的分析环境

        if not skip_then then
            local env_then = deepcopy(env)
            setmetatable(env_then, EnvManager)
            analyze_node(node[i + 1], env_then)
            env.scopes[#env.scopes] = env:merge(env_then.scopes[#env_then.scopes], env.scopes[#env.scopes])
        end
    end

    if #node % 2 == 1 then
        -- 如果最后一个节点是 else 分支，分析它
        local else_branch = node[#node]
        local env_else = deepcopy(env)
        setmetatable(env_else, EnvManager)
        analyze_node(else_branch, env_else)
        env.scopes[#env.scopes] = env:merge(env.scopes[#env.scopes], env_else.scopes[#env_else.scopes])
    end
end

function AnalysisVisitor:visit_While(node, env)
    local cond, body = node[1], node[2]
    local skip_while = self:cond_false(cond, env) -- 分析条件
    if skip_while then
        -- 如果条件为假，直接跳过循环体
        return BOTTOM
    end

    local env_before_loop = deepcopy(env.scopes[#env.scopes])
    local max_iterations = 10 -- 防止无限循环的保护措施
    local i = 0

    while i < max_iterations do
        i = i + 1
        local env_at_entry = deepcopy(env.scopes[#env.scopes])

        -- 分析循环体
        local env_in_loop = deepcopy(env)
        setmetatable(env_in_loop, EnvManager)
        analyze_node(body, env_in_loop)

        -- 会合循环体结束后的状态与循环前的状态
        local env_after_body = env_in_loop.scopes[#env_in_loop.scopes]
        local new_env_at_entry = env:merge(env_at_entry, env_after_body)

        -- 检查是否达到不动点 [8]
        local changed = false
        for k, v in pairs(new_env_at_entry) do
            if v ~= env_at_entry[k] then
                changed = true
                break
            end
        end

        env.scopes[#env.scopes] = new_env_at_entry
        if not changed then
            break
        end
    end

    -- 循环结束后，会合"进入循环"和"跳过循环"两条路径
    env.scopes[#env.scopes] = env:merge(env.scopes[#env.scopes], env_before_loop)
end

function AnalysisVisitor:visit_Do(node, env)
    env:push_scope()
    analyze_node(node[1], env)
    env:pop_scope()
end

function AnalysisVisitor:visit_Localrec(node, env)
    local name = node[1][1][1]
    env:declare(name, BOTTOM)
    local func = node[2]
    analyze_node(func, env)
end

function AnalysisVisitor:visit_Function(node, env)
    -- 分析函数体
    env:push_scope()
    for _, param in ipairs(node[1]) do
        env:declare(param[1], TOP) -- 假设参数初始为 TOP
    end
    analyze_node(node[2], env)
    env:pop_scope()
    return BOTTOM
end

function AnalysisVisitor:visit_Fornum(node, env)
    assert(#node == 5, "Fornum node must have exactly 5 parts")
    local index = node[1]
    env:declare(index[1], BOTTOM) -- 初始化循环变量为 BOTTOM 不展开循环
    local start_val = analyze_node(node[2], env)
    env:update(index[1], start_val)
    local len_op = node[3]
    analyze_node(len_op, env)
    local step = node[4]
    step = analyze_node(step, env)
    local body = node[5]
    env:push_scope() -- 进入循环体作用域
    analyze_node(body, env)
    env:pop_scope()  -- 退出循环体作用域
    return BOTTOM    -- Fornum 不返回任何值
end

-- 主分析函数
analyze_node = function(node, env)
    if type(node) ~= 'table' then return BOTTOM end

    -- 保存每个节点分析前的环境状态，供转换阶段使用
    node_environments[node] = deepcopy(env.scopes)
    local visitor = node.tag and AnalysisVisitor["visit_" .. node.tag]
    if visitor then
        return visitor(AnalysisVisitor, node, env) or BOTTOM
    else
        -- 对于未处理的节点类型，递归分析其子节点
        for _, child in ipairs(node) do
            if type(child) == 'table' then
                analyze_node(child, env)
            end
        end
        return BOTTOM -- 保守假设
    end
end

-- ----------------------------------------------------------------------------
-- 3. 转换阶段 (Transformation Pass)
-- ----------------------------------------------------------------------------

local TransformVisitor = {}
local transform_node -- 递归函数前向声明

function TransformVisitor:visit_block(block, env)
    local new_block = {}
    for _, stat in ipairs(block) do
        local new_stat = transform_node(stat, env)
        if new_stat then
            if type(new_stat) == 'table' and new_stat.tag == 'Do' and #new_stat[1] > 0 then
                -- 如果 if-pruning 产生了一个 do-block, 将其内容展开
                for _, inner_stat in ipairs(new_stat[1]) do
                    table.insert(new_block, inner_stat)
                end
            else
                table.insert(new_block, new_stat)
            end
        end
    end
    return new_block
end

function TransformVisitor:visit_Id(node, env)
    local value = env:lookup(node[1])
    if value ~= TOP and value ~= BOTTOM then
        if type(value) == 'number' then return { tag = 'Number', value } end
        if type(value) == 'string' then return { tag = 'String', value } end
        if type(value) == 'boolean' then return { tag = value and 'True' or 'False' } end
        if value == nil then return { tag = 'Nil' } end
    end
    return node
end

function TransformVisitor:visit_Op(node, env)
    -- 先尝试对整个表达式进行常量折叠
    local folded_value = analyze_node(node, env)
    if folded_value ~= TOP and folded_value ~= BOTTOM then
        if type(folded_value) == 'number' then return { tag = 'Number', folded_value } end
        if type(folded_value) == 'string' then return { tag = 'String', folded_value } end
        if type(folded_value) == 'boolean' then return { tag = folded_value and 'True' or 'False' } end
        if folded_value == nil then return { tag = 'Nil' } end
    end

    -- 如果不能完全折叠，则对子节点进行转换
    for i = 2, #node do
        node[i] = transform_node(node[i], env)
    end
    return node
end

function TransformVisitor:visit_Set(node, env)
    for i, expr in ipairs(node[2]) do
        node[2][i] = transform_node(expr, env)
    end
    -- 更新环境以反映赋值
    analyze_node(node, env)
    return node
end

function TransformVisitor:visit_Local(node, env)
    if node[2] then
        for i, expr in ipairs(node[2]) do
            node[2][i] = transform_node(expr, env)
        end
    end
    -- 更新环境以反映声明
    analyze_node(node, env)
    return node
end

function TransformVisitor:visit_If(node, env)
    for i = 1, #node, 2 do
        if i + 1 > #node then
            break -- else分支
        end
        -- 使用分析阶段为条件节点保存的环境来重新分析条件
        local original_env = EnvManager:new()
        original_env.scopes = node_environments[node[i]]
        local cond_val = analyze_node(node[i], original_env)

        if cond_val == true or cond_val == 'true' then
            -- 条件为真，只保留 then 分支
            return transform_node(node[i+2], env)
        elseif node_const_is_false(cond_val) then
            node[i] = 'nil'
            node[i+1] = 'nil'
        else
            node[i] = transform_node(node[i], env) -- 转换条件
            node[i + 1] = transform_node(node[i + 1], env) -- 转换 then 分支
        end
    end
    if #node % 2 == 1 then
        -- 如果最后一个节点是 else 分支，转换它
        local else_branch = node[#node]
        node[#node] = transform_node(else_branch, env)
    end
    -- 清理掉被删除的分支
    for i = #node, 1, -1 do
        if node[i] == 'nil' then
            table.remove(node, i)
        end
    end
    if #node == 1 then
        return node[1]
    end
    return node
end

function TransformVisitor:visit_While(node, env)
    node[1] = transform_node(node[1], env)

    -- 进入循环体前，需要将会改变的变量设为 BOTTOM
    local env_in_loop = deepcopy(env)
    setmetatable(env_in_loop, EnvManager)
    analyze_node(node, env_in_loop) -- 用原始节点分析来确定哪些变量会变
    env.scopes[#env.scopes] = env_in_loop.scopes[#env_in_loop.scopes]

    node[2] = transform_node(node[2], env)
    return node
end

function TransformVisitor:visit_Do(node, env)
    env:push_scope()
    local new_body = transform_node(node[1], env)
    env:pop_scope()
    return { tag = 'Do', new_body }
end

function TransformVisitor:visit_Localrec(node, env)
    node[1][1] = transform_node(node[1][1], env)
    local func = node[2]
    node[2] = transform_node(func, env)
    return node
end

function TransformVisitor:visit_Function(node, env)
    -- 分析函数体
    env:push_scope()
    for i, param in ipairs(node[1]) do
        node[1][i] = transform_node(param, env)
    end
    node[2] = transform_node(node[2], env)
    env:pop_scope()
    return node
end

function TransformVisitor:visit_Fornum(node, env)
    assert(#node == 5, "Fornum node must have exactly 5 parts")
    -- node[1] = transform_node(node[1], env) -- 初始化循环变量为 BOTTOM 不展开循环
    -- local start_val = transform_node(node[2], env)
    -- node[2] = start_val
    -- env:update(node[1], start_val)
    -- node[3] = transform_node(node[3], env)
    -- node[4] = transform_node(node[4], env)
    local body = node[5]
    env:push_scope() -- 进入循环体作用域
    node[5] = transform_node(body, env)
    env:pop_scope()  -- 退出循环体作用域
    return node      -- Fornum 不返回任何值
end

-- 主转换函数
transform_node = function(node, env)
    if type(node) ~= 'table' then return node end

    -- 获取为该节点保存的分析时环境
    local analysis_env_scopes = node_environments[node]
    if analysis_env_scopes then
        env.scopes = analysis_env_scopes
    end

    local visitor = node.tag and TransformVisitor["visit_" .. node.tag]
    if visitor then
        return visitor(TransformVisitor, node, env)
    else
        -- 对于未处理的节点类型，递归转换其子节点
        for i, child in ipairs(node) do
            if type(child) == 'table' then
                node[i] = transform_node(child, env)
            end
        end
        return node
    end
end

local function start_transform(ast, env)
    for i, child in ipairs(ast) do
        if type(child) == 'table' then
            ast[i] = transform_node(child, env)
        end
    end
    return ast
end

-- ----------------------------------------------------------------------------
-- 4. 主优化流程
-- ----------------------------------------------------------------------------

function Optimizer.run(path)
    local fp = assert(io.open(path, 'r')) -- 确保文件存在
    local context = fp:read('*a')         -- 读取文件内容
    fp:close()
    -- 1. 解析源代码为 AST
    local mlc = require 'metalua.compiler'.new()
    local ast, err = mlc:src_to_ast(context)
    if not ast then
        return nil, "Parsing error: " .. tostring(err)
    end

    -- 2. 分析阶段
    node_environments = {}
    local analysis_env = EnvManager:new()
    analyze_node(ast, analysis_env)

    -- 3. 转换阶段
    local transform_env = EnvManager:new()
    local optimized_ast = start_transform(ast, transform_env)

    local optimized_code = mlc.ast_to_src(optimized_ast)
    local output = path:gsub('%.lua$', '_optimized.lua')
    local fp = io.open(output, 'w')
    fp:write(optimized_code)
    fp:close()
    return optimized_code
end

local path = arg[1]
assert(path, "Please provide a Lua source file path as an argument.")
if not path:match('%.lua$') then
    error("The provided file must have a .lua extension.")
end
Optimizer.run(path)
