-- DEPRECATED: gc.policy was merged into debug.profiler (priority 20).
-- Kept as a nil-registration shim so accidental require("plugins.gc_policy") is a no-op.
-- Do not re-add load_plugin("gc_policy") in init.lua — that would double-apply GC policy.
return nil
