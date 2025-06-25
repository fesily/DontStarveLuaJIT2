
package.path = package.path .. ';3rd/?.lua;3rd/?/init.lua'

require 'metalua.loader'

local mlc = require 'metalua.compiler'.new()
local ast_to_src = require 'metalua.compiler.ast_to_src'.new()
local function compiler_to_file(filepath)
    local ast = mlc:srcfile_to_ast(filepath)
    local src = ast_to_src(ast)
    assert(loadstring(src))
    local output = filepath:gsub('%.mlua$', '.lua')
    io.open(output, 'w'):write(src)
    
end

--compiler_to_file('3rd/metalua/compiler/ast_to_src.mlua')
compiler_to_file('3rd/metalua/treequery.mlua')
--compiler_to_file('3rd/metalua/treequery/walk.mlua')
--compiler_to_file('3rd/metalua/extension/match.mlua')
--compiler_to_file('3rd/metalua/extension/comprehension.mlua')
