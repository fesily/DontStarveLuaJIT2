name = "ds_harness_puc_dump_compat_table"
description = "Harness probe: a mod declaring luajit_compatible as a table receives the local LuaJIT capability."
author = "harness"
version = "1.0.0"

api_version = 10

dst_compatible = true
dont_starve_compatible = false
reign_of_giants_compatible = false

client_only_mod = false
server_only_mod = true
all_clients_require_mod = false

luajit_compatible = {
    since = "2.1",
}
