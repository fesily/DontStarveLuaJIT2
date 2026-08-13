-- tools/bake_plugin_options.lua
-- Collect package configuration_options and splice them into parent Mod/modinfo.lua.

local load_string = loadstring or load

local BEGIN_MARK = "-- BEGIN GENERATED PLUGIN OPTIONS"
local END_MARK = "-- END GENERATED PLUGIN OPTIONS"

local SKIP_STEMS = {
    plugin_client_anim = true,
}

local ROW_KEYS_BEFORE_GATE = {
    "name",
    "label",
    "hover",
    "options",
    "default",
    "disabled_by",
    "disabled_value",
    "require_restart",
}

local TRANSLATE_KEYS = { "en", "zh", "zhr", "zht" }

local function is_windows()
    return package.config:sub(1, 1) == "\\"
end

local function norm_path(p)
    p = tostring(p or ""):gsub("\\", "/")
    p = p:gsub("/+$", "")
    return p
end

local function join_path(a, b)
    return norm_path(a) .. "/" .. tostring(b):gsub("^/+", "")
end

local function file_exists(path)
    local f = io.open(path, "rb")
    if not f then
        return false
    end
    f:close()
    return true
end

local function read_all(path)
    local f, err = io.open(path, "rb")
    if not f then
        error("cannot read " .. tostring(path) .. ": " .. tostring(err))
    end
    local text = f:read("*a") or ""
    f:close()
    return text
end

local function write_all(path, text)
    local f, err = io.open(path, "wb")
    if not f then
        error("cannot write " .. tostring(path) .. ": " .. tostring(err))
    end
    f:write(text)
    f:close()
end

local function dir_exists(path)
    path = norm_path(path)
    if is_windows() then
        local cmd = 'if exist "' .. path:gsub("/", "\\") .. '" (echo YES) else (echo NO)'
        local p = io.popen(cmd)
        if not p then
            return false
        end
        local out = (p:read("*a") or ""):gsub("%s+", "")
        p:close()
        return out:find("YES", 1, true) ~= nil
    end
    local f = io.open(path .. "/.", "r")
    if f then
        f:close()
        return true
    end
    return false
end

local function list_dir_names(path)
    path = norm_path(path)
    if not dir_exists(path) then
        error("plugins-root not found: " .. path)
    end
    local cmd
    if is_windows() then
        cmd = 'dir /b "' .. path:gsub("/", "\\") .. '"'
    else
        cmd = 'ls -1 "' .. path .. '"'
    end
    local p, err = io.popen(cmd)
    if not p then
        error("cannot list " .. path .. ": " .. tostring(err))
    end
    local names = {}
    for line in p:lines() do
        line = (line or ""):gsub("\r", "")
        if line ~= "" and line ~= "File Not Found" and not line:find("cannot find", 1, true) then
            names[#names + 1] = line
        end
    end
    p:close()
    return names
end

local function make_sandbox(stem)
    local env = {
        folder_name = stem,
        locale = "",
        ChooseTranslationTable = function(t)
            return t
        end,
        translate = function(t)
            return { __bake_translate = t }
        end,
        toggle = { __bake_toggle = true },
        AddSection = function(label, hover)
            return { __bake_section = true, label = label, hover = hover }
        end,
        disable_by_non_win = { __bake_ident = "disable_by_non_win" },
        disable_by_lua51 = { __bake_ident = "disable_by_lua51" },
        disable_by_gen_gc = { __bake_ident = "disable_by_gen_gc" },
        platform_info = nil,
    }
    setmetatable(env, { __index = _G })
    return env
end

local function load_modinfo(path, stem)
    local fn, err = loadfile(path)
    if not fn then
        error("cannot load " .. path .. ": " .. tostring(err))
    end
    local env = make_sandbox(stem)
    setfenv(fn, env)
    fn()
    return env
end

local function is_obsolete_options(opt)
    if type(opt) ~= "table" then
        return false
    end
    if opt.all_of ~= nil or opt.any_of ~= nil or opt.option ~= nil then
        return true
    end
    return next(opt) ~= nil
end

local function is_section_row(row)
    return type(row) == "table" and (row.__bake_section or row.section_start == true)
end

local function validate_row(row, stem)
    if type(row) ~= "table" then
        error("non-table configuration_options entry in " .. tostring(stem))
    end
    if is_section_row(row) then
        return
    end
    if row.name == nil or row.name == "" or row.label == nil or row.options == nil or row.default == nil then
        error("incomplete widget row in " .. tostring(stem) .. ": missing name/label/options/default")
    end
    local dt = type(row.default)
    if dt ~= "boolean" and dt ~= "number" and dt ~= "string" then
        error("unsupported default type for " .. tostring(row.name) .. ": " .. dt)
    end
end

local function is_array(t)
    local n = 0
    for k, _ in pairs(t) do
        if type(k) ~= "number" or k < 1 or k ~= math.floor(k) then
            return false
        end
        n = n + 1
    end
    return n == #t
end

local serialize_value

local function serialize_translate(t)
    local parts = {}
    local seen = {}
    for _, key in ipairs(TRANSLATE_KEYS) do
        if t[key] ~= nil then
            -- zhr/zht only if present (the nil check above).
            parts[#parts + 1] = string.format("%s = %s", key, serialize_value(t[key]))
            seen[key] = true
        end
    end
    local extra = {}
    for k, _ in pairs(t) do
        if type(k) == "string" and not seen[k] then
            extra[#extra + 1] = k
        end
    end
    table.sort(extra)
    for _, key in ipairs(extra) do
        parts[#parts + 1] = string.format("%s = %s", key, serialize_value(t[key]))
    end
    return "translate({ " .. table.concat(parts, ", ") .. " })"
end

local function serialize_section(row)
    local label = serialize_value(row.label)
    if row.hover == nil then
        return "AddSection(" .. label .. ")"
    end
    return "AddSection(" .. label .. ", " .. serialize_value(row.hover) .. ")"
end

local function serialize_map(t)
    local parts = {}
    local seen = {}
    for _, key in ipairs({ "description", "data" }) do
        if t[key] ~= nil then
            parts[#parts + 1] = key .. " = " .. serialize_value(t[key])
            seen[key] = true
        end
    end
    local extra = {}
    for k, _ in pairs(t) do
        if type(k) == "string" and not seen[k] and k:sub(1, 7) ~= "__bake_" then
            extra[#extra + 1] = k
        end
    end
    table.sort(extra)
    for _, key in ipairs(extra) do
        parts[#parts + 1] = key .. " = " .. serialize_value(t[key])
    end
    return "{ " .. table.concat(parts, ", ") .. " }"
end

local function serialize_array(t, indent)
    indent = indent or ""
    if #t == 0 then
        return "{}"
    end
    local inner = indent .. "    "
    local lines = { "{" }
    for _, item in ipairs(t) do
        lines[#lines + 1] = inner .. serialize_value(item, inner) .. ","
    end
    lines[#lines + 1] = indent .. "}"
    return table.concat(lines, "\n")
end

serialize_value = function(v, indent)
    local typ = type(v)
    if typ == "string" then
        return string.format("%q", v)
    elseif typ == "number" then
        return tostring(v)
    elseif typ == "boolean" then
        return v and "true" or "false"
    elseif typ == "nil" then
        return "nil"
    elseif typ ~= "table" then
        error("cannot serialize type " .. typ)
    end
    if v.__bake_translate then
        return serialize_translate(v.__bake_translate)
    end
    if v.__bake_toggle then
        return "toggle"
    end
    if v.__bake_section then
        return serialize_section(v)
    end
    if type(v.__bake_ident) == "string" then
        return v.__bake_ident
    end
    if is_array(v) then
        return serialize_array(v, indent)
    end
    return serialize_map(v)
end

local function serialize_widget(row, indent)
    indent = indent or "    "
    local inner = indent .. "    "
    local lines = { indent .. "{" }
    local seen = {}
    for _, key in ipairs(ROW_KEYS_BEFORE_GATE) do
        if row[key] ~= nil then
            lines[#lines + 1] = inner .. key .. " = " .. serialize_value(row[key], inner) .. ","
            seen[key] = true
        end
    end
    local extra = {}
    for k, _ in pairs(row) do
        if type(k) == "string" and not seen[k] and k ~= "host_gate" and k:sub(1, 7) ~= "__bake_" then
            extra[#extra + 1] = k
        end
    end
    table.sort(extra)
    for _, key in ipairs(extra) do
        lines[#lines + 1] = inner .. key .. " = " .. serialize_value(row[key], inner) .. ","
        seen[key] = true
    end
    if row.host_gate ~= nil then
        lines[#lines + 1] = inner .. "host_gate = " .. serialize_value(row.host_gate, inner) .. ","
    end
    lines[#lines + 1] = indent .. "},"
    return table.concat(lines, "\n")
end

local function serialize_rows(rows)
    rows = rows or {}
    local parts = {}
    for _, row in ipairs(rows) do
        if type(row) == "table" and row.__bake_section then
            parts[#parts + 1] = "    " .. serialize_section(row) .. ","
        else
            parts[#parts + 1] = serialize_widget(row, "    ")
        end
    end
    return table.concat(parts, "\n")
end

local function split_generated(text)
    local b_s = text:find(BEGIN_MARK, 1, true)
    local e_s = text:find(END_MARK, 1, true)
    if not b_s or not e_s or e_s <= b_s then
        error("missing generated plugin option markers")
    end
    local begin_nl = text:find("\n", b_s, true)
    local prefix
    if begin_nl then
        prefix = text:sub(1, begin_nl)
    else
        prefix = text .. "\n"
    end
    local end_line_start = e_s
    while end_line_start > 1 do
        local ch = text:sub(end_line_start - 1, end_line_start - 1)
        if ch == "\n" then
            break
        end
        end_line_start = end_line_start - 1
    end
    local interior_start = begin_nl and (begin_nl + 1) or (#text + 1)
    local interior = text:sub(interior_start, end_line_start - 1)
    local suffix = text:sub(end_line_start)
    return prefix, interior, suffix
end

local function uses_crlf(text)
    return text:find("\r\n", 1, true) ~= nil
end

local function splice(modinfo_text, generated_body)
    generated_body = generated_body or ""
    local prefix, _, suffix = split_generated(modinfo_text)
    if generated_body ~= "" then
        generated_body = generated_body:gsub("\r\n", "\n"):gsub("\r", "\n")
        if generated_body:sub(-1) ~= "\n" then
            generated_body = generated_body .. "\n"
        end
        if uses_crlf(prefix) then
            generated_body = generated_body:gsub("\n", "\r\n")
        end
    end
    return prefix .. generated_body .. suffix
end

local function norm_nl(s)
    s = (s or ""):gsub("\r\n", "\n"):gsub("\r", "\n")
    while s:sub(-1) == "\n" do
        s = s:sub(1, -2)
    end
    return s
end

local function widget_name(row)
    if type(row) ~= "table" then
        return nil
    end
    if is_section_row(row) then
        return nil
    end
    if type(row.name) ~= "string" or row.name == "" then
        return nil
    end
    return row.name
end

local function scan_names(text)
    local names = {}
    for n in text:gmatch('name%s*=%s*"([^"]+)"') do
        names[n] = true
    end
    for n in text:gmatch("name%s*=%s*'([^']+)'") do
        names[n] = true
    end
    return names
end

local function handwritten_names(modinfo_text)
    local empty = splice(modinfo_text, "")
    local fn = load_string(empty)
    if not fn then
        local prefix, _, suffix = split_generated(modinfo_text)
        return scan_names(prefix .. suffix)
    end
    local env = make_sandbox("parent")
    setfenv(fn, env)
    local ok = pcall(fn)
    if not ok then
        local prefix, _, suffix = split_generated(modinfo_text)
        return scan_names(prefix .. suffix)
    end
    local names = {}
    for _, row in ipairs(env.configuration_options or {}) do
        local n = widget_name(row)
        if n then
            names[n] = true
        end
    end
    return names
end

local function check_collisions(rows, handwritten)
    local seen = {}
    for _, row in ipairs(rows) do
        local n = widget_name(row)
        if n then
            if handwritten[n] then
                error("widget name " .. n .. " collides with hand-written parent option")
            end
            if seen[n] then
                error("duplicate widget name " .. n .. " from " .. tostring(seen[n]) .. " and " .. tostring(row.__bake_stem or "?"))
            end
            seen[n] = row.__bake_stem or row.__bake_plugin_id or "?"
        end
    end
end

local function collect(plugins_root)
    if not plugins_root or plugins_root == "" then
        error("collect: plugins_root required")
    end
    plugins_root = norm_path(plugins_root)
    local names = list_dir_names(plugins_root)
    local pkgs = {}
    for _, name in ipairs(names) do
        if name:match("^plugin_") and not SKIP_STEMS[name] then
            local path = join_path(plugins_root, name .. "/modinfo.lua")
            if file_exists(path) then
                local env = load_modinfo(path, name)
                if is_obsolete_options(env.options) then
                    error("obsolete field options; use configuration_options + host_gate (" .. name .. ")")
                end
                local rows = env.configuration_options
                if type(rows) == "table" and #rows > 0 then
                    for _, row in ipairs(rows) do
                        validate_row(row, name)
                    end
                    pkgs[#pkgs + 1] = {
                        stem = name,
                        plugin_id = env.plugin_id or name,
                        priority = tonumber(env.priority) or 0,
                        rows = rows,
                    }
                end
            end
        end
    end
    table.sort(pkgs, function(a, b)
        if a.priority ~= b.priority then
            return a.priority < b.priority
        end
        if a.plugin_id ~= b.plugin_id then
            return a.plugin_id < b.plugin_id
        end
        return a.stem < b.stem
    end)
    local flat = {}
    for _, pkg in ipairs(pkgs) do
        for _, row in ipairs(pkg.rows) do
            if type(row) == "table" then
                row.__bake_stem = pkg.stem
                row.__bake_plugin_id = pkg.plugin_id
            end
            flat[#flat + 1] = row
        end
    end
    return flat
end

local function resolve_opts(opts)
    opts = opts or {}
    local source_root = norm_path(opts.source_root or ".")
    local plugins_root = opts.plugins_root and norm_path(opts.plugins_root)
        or join_path(source_root, "src/DontStarveInjector/plugins")
    local modinfo = opts.modinfo and norm_path(opts.modinfo)
        or join_path(source_root, "Mod/modinfo.lua")
    return {
        source_root = source_root,
        plugins_root = plugins_root,
        modinfo = modinfo,
    }
end

local function write(opts)
    opts = resolve_opts(opts)
    local text = read_all(opts.modinfo)
    local rows = collect(opts.plugins_root)
    local body = serialize_rows(rows)
    check_collisions(rows, handwritten_names(text))
    local out = splice(text, body)
    write_all(opts.modinfo, out)
    return out
end

local function check(opts)
    opts = resolve_opts(opts)
    local text = read_all(opts.modinfo)
    local rows = collect(opts.plugins_root)
    local body = serialize_rows(rows)
    check_collisions(rows, handwritten_names(text))
    local _, interior = split_generated(text)
    return norm_nl(interior) == norm_nl(body)
end

local function parse_args(argv)
    local opts = {}
    local i = 1
    while i <= #argv do
        local a = argv[i]
        if a == "--write" then
            opts.mode = "write"
        elseif a == "--check" then
            opts.mode = "check"
        elseif a == "--source-root" then
            i = i + 1
            opts.source_root = argv[i]
            if not opts.source_root then
                error("missing value for --source-root")
            end
        elseif a == "--modinfo" then
            i = i + 1
            opts.modinfo = argv[i]
            if not opts.modinfo then
                error("missing value for --modinfo")
            end
        elseif a == "--plugins-root" then
            i = i + 1
            opts.plugins_root = argv[i]
            if not opts.plugins_root then
                error("missing value for --plugins-root")
            end
        else
            error("unknown argument: " .. tostring(a))
        end
        i = i + 1
    end
    return opts
end

local function main(argv)
    local opts = parse_args(argv)
    if opts.mode == "write" then
        write(opts)
        return 0
    elseif opts.mode == "check" then
        if not check(opts) then
            io.stderr:write("generated plugin options region is dirty\n")
            return 1
        end
        return 0
    end
    io.stderr:write(
        "usage: luajit tools/bake_plugin_options.lua [--write|--check] [--source-root DIR] [--modinfo PATH] [--plugins-root PATH]\n"
    )
    return 2
end

if os.getenv("BAKE_PLUGIN_OPTIONS_AS_MODULE") == "1" then
    return {
        collect = collect,
        serialize_rows = serialize_rows,
        splice = splice,
        check = check,
        write = write,
    }
end

local ok, err = pcall(function()
    return main(arg)
end)
if not ok then
    io.stderr:write(tostring(err) .. "\n")
    os.exit(1)
end
os.exit(err)
