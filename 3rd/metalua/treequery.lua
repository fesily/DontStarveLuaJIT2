local walk = require "metalua.treequery.walk"

local M = { }

treequery = M

local function mmap_add (mmap, node, x)
   if node == nil then
      return false
   end
   local set = mmap[node]
   if set then
      set[x] = true
   else
      mmap[node] = { [x] = true }
   end
end

local function mmap_remove (mmap, node, x)
   local set = mmap[node]
   if not set then
      return false
   elseif not set[x] then
      return false
   elseif next (set) then
      set[x] = nil
   else
      mmap[node] = nil
   end
   return true
end

local ACTIVE_SCOPE = setmetatable ({ }, { __mode = "k" })

local Q = { }

Q.__index = Q

function M.treequery (root)
   return setmetatable ({
      root = root,
      unsatisfied = 0,
      predicates = { },
      until_up = { },
      from_up = { },
      up_f = false,
      down_f = false,
      filters = { }
   }, Q)
end

local function add_pos_filter (self, position, inverted, inclusive, f, ...)
   if type (f) == "string" then
      f = M.has_tag (f, ...)
   end
   if not inverted then
      self.unsatisfied = self.unsatisfied + 1
   end
   local x = {
      pred = f,
      position = position,
      satisfied = false,
      inverted = inverted or false,
      inclusive = inclusive or false
   }
   table.insert (self.predicates, x)
   return self
end

function Q:if_unknown (f)
   self.unknown_handler = f or (function ()
      return nil
   end)
   return self
end

function Q:after (f, ...)
   return add_pos_filter (self, "after", false, false, f, ...)
end

function Q:not_after (f, ...)
   return add_pos_filter (self, "after", true, false, f, ...)
end

function Q:under (f, ...)
   return add_pos_filter (self, "under", false, false, f, ...)
end

function Q:not_under (f, ...)
   return add_pos_filter (self, "under", true, false, f, ...)
end

function Q:filter (f, ...)
   if type (f) == "string" then
      f = M.has_tag (f, ...)
   end
   table.insert (self.filters, f)
   return self
end

function Q:filter_not (f, ...)
   if type (f) == "string" then
      f = M.has_tag (f, ...)
   end
   table.insert (self.filters, function (...)
      return not f (...)
   end)
   return self
end

function Q:execute ()
   local cfg = { }
   function cfg.down (...)
      ACTIVE_SCOPE[...] = cfg.scope
      local satisfied = self.unsatisfied == 0
      for _, x in ipairs (self.predicates) do
         if not x.satisfied and x.pred (...) then
            x.satisfied = true
            local node, parent = ...
            local inc = (x.inverted and 1) or -1
            if x.position == "under" then
               self.unsatisfied = self.unsatisfied + inc
               mmap_add (self.until_up, node, x)
            elseif x.position == "after" then
               mmap_add (self.from_up, node, x)
               mmap_add (self.until_up, parent, x)
            elseif x.position == "under_or_after" then
               self.satisfied = self.satisfied + inc
               mmap_add (self.until_up, parent, x)
            else
               error "position not understood"
            end
            if x.inclusive then
               satisfied = self.unsatisfied == 0
            end
         end
      end
      if satisfied then
         for _, f in ipairs (self.filters) do
            if not f (...) then
               satisfied = false
               break
            end
         end
         if satisfied and self.down_f then
            self.down_f (...)
         end
      end
   end
   function cfg.up (...)
      local preds = self.until_up[...]
      if preds then
         for x, _ in pairs (preds) do
            local inc = (x.inverted and -1) or 1
            self.unsatisfied = self.unsatisfied + inc
            x.satisfied = false
         end
         self.until_up[...] = nil
      end
      local satisfied = self.unsatisfied == 0
      if satisfied then
         for _, f in ipairs (self.filters) do
            if not f (self, ...) then
               satisfied = false
               break
            end
         end
         if satisfied and self.up_f then
            self.up_f (...)
         end
      end
      local preds = self.from_up[...]
      if preds then
         for p, _ in pairs (preds) do
            local inc = (p.inverted and 1) or -1
            self.unsatisfied = self.unsatisfied + inc
         end
         self.from_up[...] = nil
      end
      ACTIVE_SCOPE[...] = nil
   end
   function cfg.binder (id_node, ...)
      cfg.down (id_node, ...)
      cfg.up (id_node, ...)
   end
   cfg.unknown = self.unknown_handler
   return walk.guess (cfg, self.root)
end

function Q:foreach (down, up)
   if not up and not down then
      error "iterator missing"
   end
   self.up_f = up
   self.down_f = down
   return self:execute ()
end

function Q:list ()
   local acc = { }
   self:foreach (function (x)
      return table.insert (acc, x)
   end)
   return acc
end

function Q:first ()
   local result = { }
   local function f (...)
      result = { ... }
      error ()
   end
   pcall (function ()
      return self:foreach (f)
   end)
   return unpack (result)
end

function Q:__tostring ()
   return "<treequery>"
end

function M.has_tag (...)
   local args = { ... }
   if # args == 1 then
      local tag = ...
      return (function (node)
         return node.tag == tag
      end)
   else
      local tags = { }
      for _, tag in ipairs (args) do
         tags[tag] = true
      end
      return function (node)
         local node_tag = node.tag
         return node_tag and tags[node_tag]
      end
   end
end

M.is_expr = M.has_tag ("Nil", "Dots", "True", "False", "Number", "String", "Function", "Table", "Op", "Paren", "Call", "Invoke", "Id", "Index")

local STAT_TAGS = {
   Do = 1,
   Set = 1,
   While = 1,
   Repeat = 1,
   If = 1,
   Fornum = 1,
   Forin = 1,
   Local = 1,
   Localrec = 1,
   Return = 1,
   Break = 1
}

function M.is_stat (node, parent)
   local tag = node.tag
   if not tag then
      return false
   elseif STAT_TAGS[tag] then
      return true
   elseif tag == "Call" or tag == "Invoke" then
      return parent and parent.tag == nil
   else
      return false
   end
end

function M.is_block (node)
   return node.tag == nil
end

local BINDER_PARENT_TAG = {
   Local = true,
   Localrec = true,
   Forin = true,
   Function = true
}

function M.is_binder (node, parent)
   if node.tag ~= "Id" or not parent then
      return false
   end
   if parent.tag == "Fornum" then
      return parent[1] == node
   end
   if not BINDER_PARENT_TAG[parent.tag] then
      return false
   end
   for _, binder in ipairs (parent[1]) do
      if binder == node then
         return true
      end
   end
   return false
end

function M.binder (occurrence, root)
   local cfg, id_name, result = { }, occurrence[1], { }
   function cfg.occurrence (id)
      if id == occurrence then
         result = cfg.scope:get (id_name)
      end
   end
   walk.guess (cfg, root)
   return unpack (result)
end

function M.is_occurrence_of (binder)
   return function (node, ...)
      local b = M.get_binder (node)
      return b and b == binder
   end
end

function M.get_binder (occurrence, ...)
   if occurrence.tag ~= "Id" then
      return nil
   end
   if M.is_binder (occurrence, ...) then
      return nil
   end
   local scope = ACTIVE_SCOPE[occurrence]
   local binder_hierarchy = scope:get (occurrence[1])
   return unpack (binder_hierarchy or { })
end

function M.parent (n, pred, ...)
   if type (n) ~= "number" then
      n, pred = 2, n
   end
   if type (pred) == "string" then
      pred = M.has_tag (pred, ...)
   end
   return function (self, ...)
      return select (n, ...) and pred (self, select (n, ...))
   end
end

function M.child (n, pred)
   return function (node, ...)
      local child = node[n]
      return child and pred (child, node, ...)
   end
end

function M.is_nth (a, b)
   b = b or a
   return function (self, node, parent)
      if not parent then
         return false
      end
      local nchildren = # parent
      local a = (a <= 0 and (nchildren + a) + 1) or a
      if nchildren < a then
         return false
      end
      local b = ((b <= 0 and (nchildren + b) + 1) or (nchildren < b and nchildren)) or b
      for i = a, b do
         if parent[i] == node then
            return true
         end
      end
      return false
   end
end

function M.children (ast)
   local acc = { }
   local cfg = { }
   function cfg.down (x)
      if x ~= ast then
         table.insert (acc, x)
         return "break"
      end
   end
   walk.guess (cfg, ast)
   return acc
end

local comment_extractor = function (which_side)
   return function (node)
      local x = node.lineinfo
      x = x and x[which_side]
      x = x and x.comments
      if not x then
         return nil
      end
      local lines = { }
      for _, record in ipairs (x) do
         table.insert (lines, record[1])
      end
      return table.concat (lines, "\n")
   end
end

M.comment_prefix = comment_extractor "first"

M.comment_suffix = comment_extractor "last"

function M:__call (...)
   return self.treequery (...)
end

return setmetatable (M, M)