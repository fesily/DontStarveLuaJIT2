-- Pure-Lua PluginHost mirroring src/DontStarveInjector/core/PluginHost.cpp semantics.
-- Path A: register → resolve(options/when/deps/conflicts/cycles) → load_phase(topo+priority).

local PluginHost = {}
PluginHost.__index = PluginHost

local STATUS = {
    Registered = "Registered",
    Disabled = "Disabled",
    Failed = "Failed",
    Loaded = "Loaded",
}

local FAIL = {
    None = "None",
    MissingHardDep = "MissingHardDep",
    Conflict = "Conflict",
    Cycle = "Cycle",
    LoadThrew = "LoadThrew",
}

local PHASE = {
    None = "None",
    EarlyNative = "EarlyNative",
    AfterLuaBridge = "AfterLuaBridge",
    AfterModMain = "AfterModMain",
    OnDemand = "OnDemand",
}

PluginHost.Status = STATUS
PluginHost.FailReason = FAIL
PluginHost.Phase = PHASE

local function deepcopy_list(t)
    if not t then
        return {}
    end
    local out = {}
    for i = 1, #t do
        out[i] = t[i]
    end
    return out
end

local function list_contains(t, value)
    for i = 1, #t do
        if t[i] == value then
            return true
        end
    end
    return false
end

local function has_phase(phases, phase)
    if phases == nil then
        -- Lua plugins default to AfterModMain
        return phase == PHASE.AfterModMain
    end
    if type(phases) == "string" then
        return phases == phase
    end
    if type(phases) == "table" then
        if phases[phase] == true then
            return true
        end
        for i = 1, #phases do
            if phases[i] == phase then
                return true
            end
        end
    end
    return false
end

local function config_get(config, key)
    if config == nil then
        return nil
    end
    if type(config) == "function" then
        return config(key)
    end
    return config[key]
end

-- Match C++ is_bool_on: bool true; number != 0; string not empty/off/false/0
local function is_bool_on(config, key)
    local v = config_get(config, key)
    if v == nil then
        return false
    end
    local t = type(v)
    if t == "boolean" then
        return v
    end
    if t == "number" then
        return v ~= 0
    end
    if t == "string" then
        return v ~= "" and v ~= "off" and v ~= "false" and v ~= "0"
    end
    return false
end

local function get_string(config, key)
    local v = config_get(config, key)
    if v == nil then
        return ""
    end
    local t = type(v)
    if t == "string" then
        return v
    end
    if t == "boolean" then
        return v and "true" or "false"
    end
    if t == "number" then
        return tostring(v)
    end
    return ""
end

-- Options forms (Lua):
--   nil / true / { always = true }           → AlwaysOn
--   { all_of = { "A", "B" } }
--   { any_of = { "A", "B" } }
--   { option = "A" }                         → AllOf single
--   { neq = { key = "K", value = "off" } }  or { neq = { "K", "off" } }
--   { eq  = { key = "K", value = "on" } }   or { eq  = { "K", "on" } }
--   { string_ne = ... } / { string_eq = ... } aliases
local function eval_option_rule(rule, config)
    if rule == nil or rule == true then
        return true
    end
    if rule == false then
        return false
    end
    if type(rule) ~= "table" then
        return false
    end
    if rule.always == true or rule.always_on == true then
        return true
    end

    local all_of = rule.all_of
    local any_of = rule.any_of
    if rule.option ~= nil then
        all_of = { rule.option }
    end

    if all_of ~= nil then
        if #all_of == 0 then
            return true
        end
        for i = 1, #all_of do
            if not is_bool_on(config, all_of[i]) then
                return false
            end
        end
        return true
    end

    if any_of ~= nil then
        if #any_of == 0 then
            return false
        end
        for i = 1, #any_of do
            if is_bool_on(config, any_of[i]) then
                return true
            end
        end
        return false
    end

    local neq = rule.neq or rule.string_ne or rule.string_neq
    if neq ~= nil then
        local key = neq.key or neq[1]
        local expected = neq.value or neq[2]
        return get_string(config, key) ~= tostring(expected)
    end

    local eq = rule.eq or rule.string_eq
    if eq ~= nil then
        local key = eq.key or eq[1]
        local expected = eq.value or eq[2]
        return get_string(config, key) == tostring(expected)
    end

    -- Empty table = always on (no gate)
    return true
end

local function join_cycle(nodes)
    if not nodes or #nodes == 0 then
        return ""
    end
    local parts = {}
    for i = 1, #nodes do
        parts[#parts + 1] = nodes[i]
    end
    parts[#parts + 1] = nodes[1]
    return table.concat(parts, " -> ")
end

local function plugin_id(plugin)
    return plugin.id or (plugin.manifest and plugin.manifest.id)
end

local function plugin_field(plugin, field, default)
    if plugin[field] ~= nil then
        return plugin[field]
    end
    if plugin.manifest and plugin.manifest[field] ~= nil then
        return plugin.manifest[field]
    end
    return default
end

function PluginHost.new()
    local self = setmetatable({
        entries = {}, -- array of entry
        index = {},   -- id -> array index
        events = {},
        last_config = nil,
        last_ctx = nil,
        resolved = false,
    }, PluginHost)
    return self
end

function PluginHost:clear_events()
    self.events = {}
end

function PluginHost:events_list()
    return self.events
end

function PluginHost:push_event(id, phase, status, reason, detail)
    self.events[#self.events + 1] = {
        plugin_id = id,
        phase = phase or PHASE.None,
        status = status,
        reason = reason or FAIL.None,
        detail = detail or "",
    }
end

function PluginHost:find(id)
    local i = self.index[id]
    if not i then
        return nil
    end
    return self.entries[i]
end

function PluginHost:register(plugin)
    if not plugin then
        return
    end
    local id = plugin_id(plugin)
    if not id or id == "" or self.index[id] then
        return
    end
    self.index[id] = #self.entries + 1
    self.entries[#self.entries + 1] = {
        plugin = plugin,
        status = STATUS.Registered,
        reason = FAIL.None,
        fail_detail = "",
        option_enabled = false,
        gate_ok = false,
        resolved = false,
        loaded_phases = {},
        load_count = 0,
        unload_count = 0,
    }
end

function PluginHost:register_all(list)
    if not list then
        return
    end
    for i = 1, #list do
        self:register(list[i])
    end
end

function PluginHost:status(id)
    local e = self:find(id)
    return e and e.status or STATUS.Registered
end

function PluginHost:fail_reason(id)
    local e = self:find(id)
    return e and e.reason or FAIL.None
end

function PluginHost:loaded_order(phase)
    local out = {}
    for i = 1, #self.events do
        local ev = self.events[i]
        if ev.phase == phase and ev.status == STATUS.Loaded then
            out[#out + 1] = ev.plugin_id
        end
    end
    return out
end

local function can_load_plugin(plugin, ctx)
    if type(plugin.can_load) == "function" then
        return plugin.can_load(ctx) and true or false
    end
    if type(plugin.when) == "function" then
        return plugin.when(ctx) and true or false
    end
    return true
end

function PluginHost:resolve(config, gate_ctx)
    self.last_config = config
    self.last_ctx = gate_ctx or {}
    if type(self.last_ctx) == "table" then
        self.last_ctx.config = config
    end
    self.resolved = true
    self.events = {}

    local result = {
        enabled = {},
        failed = {},
        disabled = {},
    }

    for i = 1, #self.entries do
        local e = self.entries[i]
        e.status = STATUS.Registered
        e.reason = FAIL.None
        e.fail_detail = ""
        e.option_enabled = false
        e.gate_ok = false
        e.resolved = false
        e.loaded_phases = {}
    end

    -- Phase 1: options + can_load/when
    for i = 1, #self.entries do
        local e = self.entries[i]
        local p = e.plugin
        local id = plugin_id(p)
        local options = plugin_field(p, "options", nil)
        e.option_enabled = eval_option_rule(options, config)
        e.gate_ok = e.option_enabled and can_load_plugin(p, self.last_ctx)
        if not e.option_enabled or not e.gate_ok then
            e.status = STATUS.Disabled
            e.resolved = true
            result.disabled[#result.disabled + 1] = id
            self:push_event(id, PHASE.None, STATUS.Disabled, FAIL.None, "options_or_gate")
        else
            result.enabled[#result.enabled + 1] = id
        end
    end

    local function mark_failed(e, reason, detail)
        if e.status == STATUS.Failed then
            return
        end
        local id = plugin_id(e.plugin)
        e.status = STATUS.Failed
        e.reason = reason
        e.fail_detail = detail or ""
        e.resolved = true
        result.failed[#result.failed + 1] = id
        self:push_event(id, PHASE.None, STATUS.Failed, reason, detail)
    end

    -- Phase 2: conflicts among candidates
    local candidates = {}
    for i = 1, #self.entries do
        local e = self.entries[i]
        if e.status == STATUS.Registered then
            candidates[plugin_id(e.plugin)] = true
        end
    end

    local conflict_dead = {}
    for id, _ in pairs(candidates) do
        local e = self:find(id)
        if e and e.status == STATUS.Registered then
            local conflicts = plugin_field(e.plugin, "conflicts", nil) or {}
            for ci = 1, #conflicts do
                local other = conflicts[ci]
                if candidates[other] then
                    local o = self:find(other)
                    if o and o.status == STATUS.Registered then
                        conflict_dead[id] = true
                        conflict_dead[other] = true
                    end
                end
            end
        end
    end
    for id, _ in pairs(conflict_dead) do
        local e = self:find(id)
        if e and e.status == STATUS.Registered then
            mark_failed(e, FAIL.Conflict, "conflict")
        end
    end

    -- Phase 3: hard deps (fixpoint)
    local function refresh_candidates()
        candidates = {}
        for i = 1, #self.entries do
            local e = self.entries[i]
            if e.status == STATUS.Registered then
                candidates[plugin_id(e.plugin)] = true
            end
        end
    end
    refresh_candidates()

    local changed = true
    while changed do
        changed = false
        local ids = {}
        for id, _ in pairs(candidates) do
            ids[#ids + 1] = id
        end
        for ii = 1, #ids do
            local id = ids[ii]
            local e = self:find(id)
            if e and e.status == STATUS.Registered then
                local depends = plugin_field(e.plugin, "depends", nil) or {}
                for di = 1, #depends do
                    local dep = depends[di]
                    local d = self:find(dep)
                    local dep_ok = d and d.status == STATUS.Registered
                    if not dep_ok then
                        mark_failed(e, FAIL.MissingHardDep, dep)
                        candidates[id] = nil
                        changed = true
                        break
                    end
                end
            end
        end
    end

    -- Phase 4: cycle detection (hard deps only)
    refresh_candidates()
    local WHITE, GRAY, BLACK = 0, 1, 2
    local color = {}
    for id, _ in pairs(candidates) do
        color[id] = WHITE
    end
    local stack = {}
    local cycles = {}

    local function dfs(u)
        color[u] = GRAY
        stack[#stack + 1] = u
        local e = self:find(u)
        if e then
            local depends = plugin_field(e.plugin, "depends", nil) or {}
            for di = 1, #depends do
                local dep = depends[di]
                if candidates[dep] then
                    if color[dep] == GRAY then
                        local cyc = {}
                        local start = nil
                        for si = 1, #stack do
                            if stack[si] == dep then
                                start = si
                                break
                            end
                        end
                        if start then
                            for si = start, #stack do
                                cyc[#cyc + 1] = stack[si]
                            end
                        end
                        cycles[#cycles + 1] = cyc
                    elseif color[dep] == WHITE then
                        dfs(dep)
                    end
                end
            end
        end
        stack[#stack] = nil
        color[u] = BLACK
    end

    for id, _ in pairs(candidates) do
        if color[id] == WHITE then
            dfs(id)
        end
    end

    local cycle_nodes = {}
    for ci = 1, #cycles do
        local cyc = cycles[ci]
        for ni = 1, #cyc do
            cycle_nodes[cyc[ni]] = cyc
        end
    end
    for id, cyc in pairs(cycle_nodes) do
        local e = self:find(id)
        if e and e.status == STATUS.Registered then
            mark_failed(e, FAIL.Cycle, join_cycle(cyc))
        end
    end

    for i = 1, #self.entries do
        local e = self.entries[i]
        if e.status == STATUS.Registered then
            e.resolved = true
        end
    end

    return result
end

function PluginHost:topo_order_for_phase(phase)
    local nodes = {}
    local node_set = {}
    for i = 1, #self.entries do
        local e = self.entries[i]
        local p = e.plugin
        local id = plugin_id(p)
        local phases = plugin_field(p, "phases", nil)
        if has_phase(phases, phase)
            and (e.status == STATUS.Registered or e.status == STATUS.Loaded)
            and not list_contains(e.loaded_phases, phase)
        then
            nodes[#nodes + 1] = id
            node_set[id] = true
        end
    end

    local function is_ready_provider(id)
        local e = self:find(id)
        if not e then
            return false
        end
        if e.status == STATUS.Failed or e.status == STATUS.Disabled then
            return false
        end
        return e.status == STATUS.Registered or e.status == STATUS.Loaded
    end

    local indeg = {}
    local adj = {} -- dep -> {dependents}
    for i = 1, #nodes do
        indeg[nodes[i]] = 0
        adj[nodes[i]] = {}
    end

    local function add_edge(from_dep, to)
        if not node_set[from_dep] or not node_set[to] then
            return
        end
        adj[from_dep][#adj[from_dep] + 1] = to
        indeg[to] = (indeg[to] or 0) + 1
    end

    for i = 1, #nodes do
        local id = nodes[i]
        local e = self:find(id)
        if e then
            local depends = plugin_field(e.plugin, "depends", nil) or {}
            for di = 1, #depends do
                local dep = depends[di]
                if is_ready_provider(dep) then
                    add_edge(dep, id)
                end
            end
            local soft = plugin_field(e.plugin, "soft_depends", nil) or {}
            for di = 1, #soft do
                local dep = soft[di]
                if node_set[dep] and is_ready_provider(dep) then
                    add_edge(dep, id)
                end
            end
        end
    end

    local function priority_of(id)
        local e = self:find(id)
        if not e then
            return 100
        end
        local pr = plugin_field(e.plugin, "priority", 100)
        return pr or 100
    end

    -- Ready set: indegree 0, sorted by (priority, id)
    local function collect_ready()
        local ready = {}
        for i = 1, #nodes do
            local id = nodes[i]
            if indeg[id] == 0 then
                ready[#ready + 1] = id
            end
        end
        table.sort(ready, function(a, b)
            local pa, pb = priority_of(a), priority_of(b)
            if pa ~= pb then
                return pa < pb
            end
            return a < b
        end)
        return ready
    end

    local order = {}
    local remaining = {}
    for i = 1, #nodes do
        remaining[nodes[i]] = true
    end

    while true do
        local ready = {}
        for id, _ in pairs(remaining) do
            if indeg[id] == 0 then
                ready[#ready + 1] = id
            end
        end
        if #ready == 0 then
            break
        end
        table.sort(ready, function(a, b)
            local pa, pb = priority_of(a), priority_of(b)
            if pa ~= pb then
                return pa < pb
            end
            return a < b
        end)
        local u = ready[1]
        remaining[u] = nil
        order[#order + 1] = u
        local outs = adj[u] or {}
        for oi = 1, #outs do
            local v = outs[oi]
            indeg[v] = indeg[v] - 1
        end
    end

    if #order ~= #nodes then
        local rest = {}
        local seen = {}
        for i = 1, #order do
            seen[order[i]] = true
        end
        for i = 1, #nodes do
            if not seen[nodes[i]] then
                rest[#rest + 1] = nodes[i]
            end
        end
        table.sort(rest, function(a, b)
            local pa, pb = priority_of(a), priority_of(b)
            if pa ~= pb then
                return pa < pb
            end
            return a < b
        end)
        for i = 1, #rest do
            order[#order + 1] = rest[i]
        end
    end

    return order
end

function PluginHost:load_phase(phase)
    local result = {
        loaded_order = {},
        ok = true,
    }
    if not self.resolved then
        result.ok = false
        return result
    end

    local order = self:topo_order_for_phase(phase)
    for oi = 1, #order do
        local id = order[oi]
        local e = self:find(id)
        if e and e.status ~= STATUS.Failed and e.status ~= STATUS.Disabled then
            local dep_fail = false
            local depends = plugin_field(e.plugin, "depends", nil) or {}
            for di = 1, #depends do
                local dep = depends[di]
                local d = self:find(dep)
                if not d or (d.status ~= STATUS.Loaded and d.status ~= STATUS.Registered) then
                    e.status = STATUS.Failed
                    e.reason = FAIL.MissingHardDep
                    e.fail_detail = dep
                    self:push_event(id, phase, STATUS.Failed, FAIL.MissingHardDep, dep)
                    result.ok = false
                    dep_fail = true
                    break
                end
                if d.status == STATUS.Failed then
                    e.status = STATUS.Failed
                    e.reason = FAIL.MissingHardDep
                    e.fail_detail = dep
                    self:push_event(id, phase, STATUS.Failed, FAIL.MissingHardDep, dep)
                    result.ok = false
                    dep_fail = true
                    break
                end
            end

            if not dep_fail then
                local load_fn = e.plugin.load
                local ok, err = true, nil
                if type(load_fn) == "function" then
                    ok, err = pcall(load_fn, self.last_ctx)
                end
                if ok then
                    e.status = STATUS.Loaded
                    e.loaded_phases[#e.loaded_phases + 1] = phase
                    e.load_count = (e.load_count or 0) + 1
                    result.loaded_order[#result.loaded_order + 1] = id
                    self:push_event(id, phase, STATUS.Loaded, FAIL.None, "")
                else
                    e.status = STATUS.Failed
                    e.reason = FAIL.LoadThrew
                    e.fail_detail = tostring(err)
                    self:push_event(id, phase, STATUS.Failed, FAIL.LoadThrew, tostring(err))
                    result.ok = false
                    -- Fail hard dependents later in this phase
                    for i = 1, #self.entries do
                        local other = self.entries[i]
                        if (other.status == STATUS.Registered or other.status == STATUS.Loaded)
                            and not list_contains(other.loaded_phases, phase)
                        then
                            local odeps = plugin_field(other.plugin, "depends", nil) or {}
                            for di = 1, #odeps do
                                if odeps[di] == id then
                                    other.status = STATUS.Failed
                                    other.reason = FAIL.MissingHardDep
                                    other.fail_detail = id
                                    self:push_event(plugin_id(other.plugin), phase, STATUS.Failed,
                                        FAIL.MissingHardDep, id)
                                    break
                                end
                            end
                        end
                    end
                end
            end
        end
    end

    return result
end

function PluginHost:unload(id, ctx)
    local e = self:find(id)
    if not e or e.status ~= STATUS.Loaded then
        return false
    end
    local support = plugin_field(e.plugin, "support_reload", false)
    if not support then
        return false
    end
    local unload_fn = e.plugin.unload
    if type(unload_fn) == "function" then
        unload_fn(ctx or self.last_ctx)
    end
    e.unload_count = (e.unload_count or 0) + 1
    e.status = STATUS.Registered
    e.loaded_phases = {}
    self:push_event(id, PHASE.None, STATUS.Registered, FAIL.None, "unloaded")
    return true
end

-- Alias matching C++ name
PluginHost.unload_plugin = PluginHost.unload

-- Export option evaluator for unit tests
PluginHost.evaluate_option_rule = eval_option_rule
PluginHost.is_bool_on = is_bool_on

return PluginHost
