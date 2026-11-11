---
name: ghidra-mcp-headless-enable-scripts
description: Enable/verify GHIDRA_MCP_ALLOW_SCRIPTS in start-ghidra-mcp-headless.ps1 (dst/maplestory profiles) and prove inline script execution end-to-end.
---

# GhidraMCP headless: enable + verify script execution

## Facts
- Launcher: `C:\Users\fesil\Desktop\ghidra_12.1.3_PUBLIC\start-ghidra-mcp-headless.ps1`. Profiles: `dst` (dst.gpr `/dontstarve_steam` :8089), `maplestory` (:8090).
- Gate read by `com.xebyte.core.SecurityConfig` ctor via **`System.getenv("GHIDRA_MCP_ALLOW_SCRIPTS")`**, singleton — read once at startup, so a live server needs a restart to pick it up.
- Truthy values: `1`, `true`, `yes` (case-insensitive). Anything else / unset = scripts disabled; `/run_script_inline` and `/run_ghidra_script` return "Script execution disabled".
- `Start-Process` inherits the parent env, so setting `$env:GHIDRA_MCP_ALLOW_SCRIPTS` before launch is enough (no `-Environment` param needed on PS 5.1).
- Token: `%LOCALAPPDATA%\ghidra-mcp\auth-token.txt` (and per-profile copy under `...\ghidra-mcp\<profile>\auth-token.txt`).

## Edit pattern in the launcher
```powershell
# near JAVA_OPTS
$AllowScripts = if ($env:GHIDRA_MCP_ALLOW_SCRIPTS) { $env:GHIDRA_MCP_ALLOW_SCRIPTS } else { "1" }
# with the other env exports, before Start-Process
$env:GHIDRA_MCP_ALLOW_SCRIPTS = $AllowScripts
```
Default `1` keeps opt-out (`=0` in caller shell) working. Also print it in the startup banner.

## Verify end-to-end (do not skip)
1. Restart: `powershell -NoProfile -ExecutionPolicy Bypass -File ./start-ghidra-mcp-headless.ps1 -Profile dst`
   (script stops the PID from `headless.pid`; a stale `.lock` warning is non-fatal.)
2. POST a probe:
```powershell
$t=(Get-Content "$env:LOCALAPPDATA\ghidra-mcp\auth-token.txt" -Raw).Trim()
$body='{"code":"println(\"GATE_PROBE_OK \" + currentProgram.getName());"}'
Invoke-WebRequest -Uri http://127.0.0.1:8089/run_script_inline -Method Post `
  -Headers @{Authorization="Bearer $t"} -ContentType application/json -Body $body -UseBasicParsing
```
3. Expect `GATE_PROBE_OK <program>`. A `Script execution disabled` message = gate still off; reaching the script provider = gate on.

## Gotcha: first inline call can fail
`C:\Users\fesil\ghidra_scripts` holds legacy scripts that no longer compile against Ghidra 12.1.3 (`UndefinedDataType`, `ReferenceIterator.length`, `ReferenceManager` package). The first `/run_script_inline` triggers full OSGi bundle activation and dies with `Error activating bundle ... sourceFileObject is null` / `GhidraScriptLoadException`. **Retry once — the second call succeeds.** Fixing the script dir removes the flake.

## Shell notes (win32)
- Bash tool is POSIX-ish (git bash): `powershell -File ./x.ps1` works with forward slashes; chaining `&& powershell ... && cmd` breaks.
- Never put `pause` in a probe Start-Process: it blocks the session shell and gets backgrounded.
