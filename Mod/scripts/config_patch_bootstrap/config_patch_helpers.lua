local M = {}

-- Supported rule subset:
-- - disabled_by = { option = "controller_name", value = v }
-- - disabled_by = { option = "controller_name", values = { v1, v2, ... } }
-- - optional disabled_by.reason string for UI text
-- - require_restart = true (boolean only)
-- Anything else is treated as unsupported and safely ignored.

function M.GetDisabledByRule(option)
    if option == nil then return nil end
    local rule = option.disabled_by
    if rule == nil or type(rule) ~= "table" then return nil end
    if type(rule.option) ~= "string" or rule.option == "" then return nil end
    return rule
end

function M.IsOptionDisabled(option, options_by_name)
    if option ~= nil and option.disabled_by == true then return true end
    local rule = M.GetDisabledByRule(option)
    if rule == nil then return false end
    if options_by_name == nil or type(options_by_name) ~= "table" then return false end

    local controller = options_by_name[rule.option]
    if controller == nil then return false end

    local controller_value = controller.value

    if rule.values ~= nil and type(rule.values) == "table" then
        for _, v in ipairs(rule.values) do
            if v == controller_value then return true end
        end
        return false
    end

    if rule.value ~= nil then
        return controller_value == rule.value
    end

    return false
end

function M.GetDisabledReason(option)
    if option == nil then return "" end
    local rule = option.disabled_by
    if rule ~= nil and type(rule) == "table" and rule.reason ~= nil then
        return rule.reason
    end
    return option.hover or ""
end

function M.HasRequireRestart(option)
    if option == nil then return false end
    return option.require_restart == true
end

function M.HasRequireRestartChanges(options)
    if options == nil or type(options) ~= "table" then return false end
    for _, option in ipairs(options) do
        if option.require_restart == true and option.value ~= option.initial_value then
            return true
        end
    end
    return false
end

return M
