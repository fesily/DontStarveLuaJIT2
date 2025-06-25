local checks = require "checks"

local gg = require "metalua.grammar.generator"

local pp = require "metalua.pprint"

local function replace_dots (ast, term)
   local function rec (node)
      for i, child in ipairs (node) do
         if type (child) ~= "table" then
            
         elseif child.tag == "Dots" then
            if term == "ambiguous" then
               error ("You can't use `...' on the right of a match case when it appears " .. "more than once on the left")
            else
               node[i] = term
            end
         elseif child.tag == "Function" then
            return nil
         else
            rec (child)
         end
      end
   end
   return rec (ast)
end

local tmpvar_base = gg.gensym "submatch."[1]

local function next_tmpvar (cfg)
   assert (cfg.ntmp, "No cfg.ntmp imbrication level in the match compiler")
   cfg.ntmp = cfg.ntmp + 1
   return {
      tag = "Id",
      tmpvar_base .. cfg.ntmp
   }
end

local acc_stat = function (x, cfg)
   return table.insert (cfg.code, x)
end

local acc_test = function (x, cfg)
   return acc_stat ({
      tag = "If",
      x,
      { {
         tag = "Goto",
         cfg.on_failure
      } }
   }, cfg)
end

local function acc_assign (lhs, rhs, cfg)
   assert (lhs.tag == "Id")
   cfg.locals[lhs[1]] = true
   acc_stat ({
      tag = "Set",
      { lhs },
      { rhs }
   }, cfg)
end

local literal_tags = {
   String = 1,
   Number = 1,
   True = 1,
   False = 1,
   Nil = 1
}

local function id_pattern_element_builder (pattern, term, cfg)
   assert (pattern.tag == "Id")
   if pattern[1] == "_" then
      cfg.locals._ = true
   elseif cfg.locals[pattern[1]] then
      acc_test ({
         tag = "Op",
         "not",
         {
            tag = "Op",
            "eq",
            term,
            pattern
         }
      }, cfg)
   else
      acc_assign (pattern, term, cfg)
      cfg.locals[pattern[1]] = true
   end
end

local pattern_element_builder

local function table_pattern_element_builder (pattern, term, cfg)
   local seen_dots, len = false, 0
   acc_test ({
      tag = "Op",
      "not",
      {
         tag = "Op",
         "eq",
         {
            tag = "Call",
            {
               tag = "Id",
               "type"
            },
            term
         },
         {
            tag = "String",
            "table"
         }
      }
   }, cfg)
   for i = 1, # pattern do
      local key, sub_pattern
      if pattern[i].tag == "Pair" then
         key, sub_pattern = unpack (pattern[i])
         assert (literal_tags[key.tag], "Invalid key")
      else
         len, key, sub_pattern = len + 1, {
            tag = "Number",
            len + 1
         }, pattern[i]
      end
      assert (not seen_dots, "Wrongly placed `...' ")
      if sub_pattern.tag == "Id" then
         id_pattern_element_builder (sub_pattern, {
            tag = "Index",
            term,
            key
         }, cfg)
         if sub_pattern[1] ~= "_" then
            acc_test ({
               tag = "Op",
               "eq",
               sub_pattern,
               { tag = "Nil" }
            }, cfg)
         end
      elseif sub_pattern.tag == "Dots" then
         seen_dots = true
      else
         local v2 = next_tmpvar (cfg)
         acc_assign (v2, {
            tag = "Index",
            term,
            key
         }, cfg)
         pattern_element_builder (sub_pattern, v2, cfg)
      end
   end
   if seen_dots then
      if cfg.dots_replacement then
         cfg.dots_replacement = "ambiguous"
      else
         cfg.dots_replacement = {
            tag = "Call",
            {
               tag = "Id",
               "select"
            },
            {
               tag = "Number",
               len
            },
            {
               tag = "Call",
               {
                  tag = "Id",
                  "unpack"
               },
               term
            }
         }
      end
   else
      acc_test ({
         tag = "Op",
         "not",
         {
            tag = "Op",
            "eq",
            {
               tag = "Op",
               "len",
               term
            },
            {
               tag = "Number",
               len
            }
         }
      }, cfg)
   end
end

local eq_pattern_element_builder, regexp_pattern_element_builder

function pattern_element_builder (pattern, term, cfg)
   if literal_tags[pattern.tag] then
      acc_test ({
         tag = "Op",
         "not",
         {
            tag = "Op",
            "eq",
            term,
            pattern
         }
      }, cfg)
   elseif "Id" == pattern.tag then
      id_pattern_element_builder (pattern, term, cfg)
   elseif "Op" == pattern.tag and "div" == pattern[1] then
      regexp_pattern_element_builder (pattern, term, cfg)
   elseif "Op" == pattern.tag and "eq" == pattern[1] then
      eq_pattern_element_builder (pattern, term, cfg)
   elseif "Table" == pattern.tag then
      table_pattern_element_builder (pattern, term, cfg)
   else
      error ("Invalid pattern at " .. (tostring (pattern.lineinfo) .. (": " .. pp.tostring (pattern, { hide_hash = true }))))
   end
end

function eq_pattern_element_builder (pattern, term, cfg)
   local _, pat1, pat2 = unpack (pattern)
   local ntmp_save = cfg.ntmp
   pattern_element_builder (pat1, term, cfg)
   cfg.ntmp = ntmp_save
   pattern_element_builder (pat2, term, cfg)
end

local function regexp_pattern_element_builder (pattern, term, cfg)
   local op, regexp, sub_pattern = unpack (pattern)
   assert (op == "div", "Don't know what to do with that op in a pattern")
   assert (regexp.tag == "String", "Left hand side operand for '/' in a pattern must be " .. "a literal string representing a regular expression")
   if sub_pattern.tag == "Table" then
      for _, x in ipairs (sub_pattern) do
         assert (x.tag == "Id" or x.tag == "Dots", "Right hand side operand for '/' in a pattern must be " .. "a list of identifiers")
      end
   else
      assert (sub_pattern.tag == "Id", "Right hand side operand for '/' in a pattern must be " .. "an identifier or a list of identifiers")
   end
   acc_test ({
      tag = "Op",
      "not",
      {
         tag = "Op",
         "eq",
         {
            tag = "Call",
            {
               tag = "Id",
               "type"
            },
            term
         },
         {
            tag = "String",
            "string"
         }
      }
   }, cfg)
   local capt_list = {
      tag = "Table",
      {
         tag = "Call",
         {
            tag = "Index",
            {
               tag = "Id",
               "string"
            },
            {
               tag = "String",
               "strmatch"
            }
         },
         term,
         regexp
      }
   }
   local v2 = next_tmpvar (cfg)
   acc_stat ({
      tag = "Local",
      { v2 },
      { capt_list }
   }, cfg)
   acc_test ({
      tag = "Op",
      "not",
      {
         tag = "Call",
         {
            tag = "Id",
            "next"
         },
         v2
      }
   }, cfg)
   pattern_element_builder (sub_pattern, v2, cfg)
end

local function pattern_seq_builder (pattern_seq, term_seq, cfg)
   if # pattern_seq ~= # term_seq then
      error "Bad seq arity"
   end
   cfg.locals = { }
   for i = 1, # pattern_seq do
      cfg.ntmp = 1
      pattern_element_builder (pattern_seq[i], term_seq[i], cfg)
   end
end

local function case_builder (case, term_seq, cfg)
   local patterns_group, guard, block = unpack (case)
   local on_success = gg.gensym "on_success"[1]
   for i = 1, # patterns_group do
      local pattern_seq = patterns_group[i]
      cfg.on_failure = gg.gensym "match_fail"[1]
      cfg.dots_replacement = false
      pattern_seq_builder (pattern_seq, term_seq, cfg)
      if i < # patterns_group then
         acc_stat ({
            tag = "Goto",
            on_success
         }, cfg)
         acc_stat ({
            tag = "Label",
            cfg.on_failure
         }, cfg)
      end
   end
   acc_stat ({
      tag = "Label",
      on_success
   }, cfg)
   if guard then
      acc_test ({
         tag = "Op",
         "not",
         guard
      }, cfg)
   end
   if cfg.dots_replacement then
      replace_dots (block, cfg.dots_replacement)
   end
   block.tag = "Do"
   acc_stat (block, cfg)
   acc_stat ({
      tag = "Goto",
      cfg.after_success
   }, cfg)
   acc_stat ({
      tag = "Label",
      cfg.on_failure
   }, cfg)
end

local function match_builder (x)
   local term_seq, cases = unpack (x)
   local cfg = {
      code = { tag = "Do" },
      after_success = gg.gensym "_after_success"
   }
   local new_term_seq = { }
   local match_locals
   for i = 1, # term_seq do
      local t = term_seq[i]
      local v = gg.gensym "v"
      if not match_locals then
         match_locals = {
            tag = "Local",
            { v },
            { t }
         }
      else
         table.insert (match_locals[1], v)
         table.insert (match_locals[2], t)
      end
      new_term_seq[i] = v
   end
   term_seq = new_term_seq
   if match_locals then
      acc_stat (match_locals, cfg)
   end
   for i = 1, # cases do
      local case_cfg = {
         after_success = cfg.after_success,
         code = { tag = "Do" }
      }
      case_builder (cases[i], term_seq, case_cfg)
      if next (case_cfg.locals) then
         local case_locals = { }
         table.insert (case_cfg.code, 1, {
            tag = "Local",
            case_locals,
            { }
         })
         for v, _ in pairs (case_cfg.locals) do
            table.insert (case_locals, {
               tag = "Id",
               v
            })
         end
      end
      acc_stat (case_cfg.code, cfg)
   end
   local li = {
      tag = "String",
      tostring (cases.lineinfo)
   }
   acc_stat ({
      tag = "Call",
      {
         tag = "Id",
         "error"
      },
      {
         tag = "Op",
         "concat",
         {
            tag = "String",
            "mismatch at "
         },
         li
      }
   }, cfg)
   acc_stat ({
      tag = "Label",
      cfg.after_success
   }, cfg)
   return cfg.code
end

local function extend (M)
   local _M = gg.future (M)
   checks "metalua.compiler.parser"
   M.lexer:add {
      "match",
      "with",
      "->"
   }
   M.block.terminators:add "|"
   local match_cases_list_parser = gg.list {
      name = "match cases list",
      gg.sequence {
         name = "match case",
         gg.list {
            name = "match case patterns list",
            primary = _M.expr_list,
            separators = "|",
            terminators = {
               "->",
               "if"
            }
         },
         gg.onkeyword {
            "if",
            _M.expr,
            consume = true
         },
         "->",
         _M.block
      },
      separators = "|",
      terminators = "end"
   }
   M.stat:add {
      name = "match statement",
      "match",
      _M.expr_list,
      "with",
      gg.optkeyword "|",
      match_cases_list_parser,
      "end",
      builder = function (x)
         return match_builder {
            x[1],
            x[3]
         }
      end
   }
end

return extend