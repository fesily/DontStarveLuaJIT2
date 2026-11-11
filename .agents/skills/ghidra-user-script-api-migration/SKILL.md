---
name: ghidra-user-script-api-migration
description: Fix C:\Users\fesil\ghidra_scripts Java scripts failing to compile after a Ghidra upgrade; verify via javac + GhidraMCP headless bundle build.
---

# Ghidra user-script API migration (Windows, Ghidra 12.x, GhidraMCP headless)

## Symptom
`/run_script_inline` or `/run_ghidra_script` output contains
`C:\Users\fesil\ghidra_scripts hasn't changed, with N files failing in previous build(s)`
plus javac errors, then `GhidraScriptLoadException ... sourceFileObject is null`.
The gate env var is unrelated (that failure mode says *Script execution disabled*).

## Step 1 — collect the real error list
POST to the headless server (port from profile: dst 8089, maplestory 8090):

```powershell
$token = (Get-Content "$env:LOCALAPPDATA\ghidra-mcp\auth-token.txt" -Raw).Trim()
Invoke-WebRequest -Uri "http://127.0.0.1:8089/run_script_inline" -Method Post `
  -Headers @{Authorization="Bearer $token"} -ContentType "application/json" `
  -Body '{"code":"println(1);"}' -UseBasicParsing | % Content
```
The `--- SCRIPT OUTPUT ---` block lists every failing file with line numbers.

## Step 2 — confirm the replacement signature before editing
Never guess. Decompile/javap the shipped jar:

```bash
unzip -o -q Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar 'ghidra/program/model/symbol/ReferenceManager.class' -d /tmp/j
javap -cp /tmp/j ghidra.program.model.symbol.ReferenceManager | grep -i count
```

## Step 3 — known 12.1.3 migrations

| Old | New |
|---|---|
| `rm.getReferencesTo(a).length` | `rm.getReferenceCountTo(a)` (int) |
| `import ghidra.program.model.reloc.ReferenceManager` | `ghidra.program.model.symbol.ReferenceManager` |
| `fm.removeFunction(Function)` | `fm.removeFunction(f.getEntryPoint())` |
| `new UndefinedDataType()` | `new Undefined1DataType()` / `Undefined4DataType` |
| `for (DataType dt : dtm.getAllDataTypes())` | `Iterator<DataType> it = dtm.getAllDataTypes(); while (it.hasNext())` |
| `decompileFunction(f.getEntryPoint(), n, monitor)` | `decompileFunction(f, n, monitor)` |
| `getFunction(name)` (dep. 7.4) | `getGlobalFunctions(name)` -> first element |
| `DemanglerUtil.demangle(program, mangled)` (dep. 11.3) | `DemanglerUtil.demangle(program, mangled, null)` -> `List` |

Files ending `.java_failed`, `.backup`, `.bak-*`, `.disabled-*` are not compiled — leave them alone.

## Step 4 — verify (two layers, both required)

1. Whole-directory compile against real API:

```bash
CP=$(ls -d Ghidra/*/*/lib/*.jar Ghidra/*/*/*/lib/*.jar | grep -v -- '-src' | paste -sd';' -)
javac -Xlint:all -encoding UTF-8 -cp "$CP" -d /tmp/cls "C:/Users/fesil/ghidra_scripts/"*.java
```

Expect exit 0; remaining warnings may be `[path]` entries for optional jars Ghidra also lacks.

2. Ghidra-side bundle build + runtime. Endpoint JSON key is **`script_name`** (not `script`, not `name` — those return `{"error":"Script name is required"}`):

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8089/run_ghidra_script" -Method Post `
  -Headers @{Authorization="Bearer $token"} -ContentType "application/json" `
  -Body '{"script_name":"DumpStruct.java"}' -UseBasicParsing
```

Success = `"success":true` and no `files failing` line. Prefer read-only scripts (`DumpStruct`, `FindEntityGuid`, `Query`) for the smoke run; `ForceDump`/`DumpContaining` delete and recreate functions and `*Anim*Structs` use `REPLACE_HANDLER`, so they mutate the project.

## Gotchas
- Bundle is recompiled only when a file's mtime changes; after edits, trigger one inline call to force it.
- Before the fix, only the *second* inline call succeeded (first hit the activation NPE). After the script dir compiles clean, the first call works.
- Remove probe artifacts (`McpInline_*.java` if any), scratch `_work/` dirs and unzipped `_tmp*` dirs inside the extension `lib/` folder when done.
