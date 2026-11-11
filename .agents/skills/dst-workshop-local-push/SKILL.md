---
name: dst-workshop-local-push
description: "Push DST mod content+tags to Steam Workshop locally via tools/update_workshop_tags.py, and diagnose client states that silently drop the upload"
---

# DST local Workshop push

Use `tools/update_workshop_tags.py` (repo DontStarveLuaJIT2): stdlib + ctypes on the game's own
`steam_api64.dll`, talks to the running Steam client session (no steamcmd, no third-party deps).
One `SubmitItemUpdate` writes **content + tags** together.

## Preconditions
- Windows, Steam client **running and logged in**, DST installed (its `bin64\steam_api64.dll` is copied).
- Item `3444078585` (DontStarveLuaJIT2), appid 322330. Version comes from `Mod/modinfo.lua`.

## Commands (repo root)
```powershell
python tools/update_workshop_tags.py --push-content            # prompts: write this update? [y/N]
python tools/update_workshop_tags.py --push-content --yes      # non-interactive
python tools/update_workshop_tags.py --push-content --dry-run  # stage + print plan, no write
python tools/update_workshop_tags.py --push-content --note "3.3.0: ..."
python tools/update_workshop_tags.py --version 3.3.1 --push-content
```
Metadata is untouched unless `--title/--description/--visibility/--preview` are passed (one-shot).
Exit codes: 0 ok, 1 environment, 2 write refused, 3 verification failed.

Staging filter (Windows-only release shape): skips `*.pdb/*.lib/*.exp/*.ilk`, `*.so/*.so.*/*.dylib`,
`bin64/osx`, `bin64/linux`, `plugins/update_pending`, `.ds_plugin_update.lock`, `test.log`.
`--no-filter` disables; `--ignore-file <globs>` adds gitignore-style patterns.

## Success signature
```
content folder set → tags set ['version:X'] → submitted
upload: preparing update → uploading content → 100% (N/N bytes) → committing → finished
verified: tags=['version:X'] (content: hcontent_file=... size=...)
```

## Failure: writes silently dropped
Symptom: `upload: idle/finished` immediately, no progress, no submit result, verification says
`tags=[] (wanted version:X), content_moved=False`.
Check client-update-pending state:
```powershell
Get-Process steam | Select-Object Id,StartTime      # compare with:
Get-ChildItem 'C:\Program Files (x86)\Steam\package' | Sort-Object LastWriteTime -Descending | Select -First 3
(Get-Item 'C:\Program Files (x86)\Steam\steam.exe').LastWriteTime
```
`package\` newer than both ⇒ update downloaded, restart pending. Restart the client properly
(Steam menu → Exit; verify `Get-Process steam` is gone), start it, confirm logged on, rerun.
On an up-to-date client the same push finishes in ~10 s for a 0.2 MiB item.

## Pitfall: process check in Git Bash
`tasklist //FI "IMAGENAME eq steam.exe"` fails — MSYS does not translate `//FI`, tasklist exits
with `无效参数/选项 - '//FI'`; with `2>/dev/null` that becomes a false "Steam not running".
Use `tasklist | findstr /i steam.exe` or `Get-Process steam`.
The tool itself does not use tasklist: it retries `SteamAPI_Init` for `--client-timeout` (90 s).

## Verify / clean up test items
Public API check: `GetPublishedFileDetails` (v1, POST `publishedfileids[0]`) → `result`, `tags`,
`hcontent_file`, `file_size`; unlisted items return `result=9` (needs `--allow-unreadable` to write).
Deleting a throwaway item: `ISteamUGC_DeleteItem(handle, id)` via ManualDispatch (no callback needed);
confirm the workshop page no longer resolves.
