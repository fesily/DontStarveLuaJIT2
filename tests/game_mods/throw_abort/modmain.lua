-- Harness fixture: valid Lua that aborts mod load by indexing a nil object.
-- print first (via GLOBAL, the way real mods reach engine globals) so the log
-- proves force_enable_mods actually reached this file.
GLOBAL.print("[ds_harness] THROW_ABORT")

local t = nil
GLOBAL.print(t.test)
