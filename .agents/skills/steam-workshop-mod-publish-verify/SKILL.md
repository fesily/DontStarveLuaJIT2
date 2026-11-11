---
name: steam-workshop-mod-publish-verify
description: "DST Steam Workshop mod publish/verify: diff local payload against the published manifest with an independent anonymous steamcmd download, handle the .pkg layout, debug/dev filtering, and stale Steam-client UGC drops."
---

# Verify what a Steam Workshop mod item actually publishes

Use when a workshop item's published files look stale, when a local push "succeeded" but the item did not change, or when you need proof that the shipped payload matches the local build.

## Two independent facts to establish first

1. **What the item currently serves.** The local Steam client's
   `steamapps/workshop/content/<appid>/<item>` may be a **junction to the dev tree** (in this repo it is:
   `.../content/322330/3444078585 -> C:\Users\fesil\DontStarveLuaJIT2\Mod`, created 2025-03-14). Anything
   inspected there is the working tree, not the published content.
2. **When the content last changed.** Steam's own logs are authoritative:
   `Steam/logs/workshop_log.txt` — look for
   `Upload starting ...` / `Uploaded new content ( ManifestID ... )` / `Upload finished ... : OK`.
   An update entry *without* `Uploaded new content` was metadata/tags only.

## Independent download

```powershell
steamcmd +login anonymous +workshop_download_item 322330 <item> validate +quit
# lands in <steamcmd>\steamapps\workshop\content\322330\<item>
```

- Downloaded files carry the **download time** as mtime — never judge build age by mtime.
- Build age = **PE `TimeDateStamp`** (link time, UTC): read `e_lfanew` at 0x3C, then the DWORD at
  `PE+8`. Appending bytes keeps it readable; a truncated/empty file yields no stamp.
- Anonymous works for public items only; private/unlisted need a logged-in SteamCMD.

## In-repo tool

```powershell
python tools/update_workshop_tags.py --verify-content            # download + hash diff, exit 3 on difference
python tools/update_workshop_tags.py --push-content             # content + tags in one SubmitItemUpdate
python tools/update_workshop_tags.py --push-content --dry-run   # staging only, prints count/size/skips
```

- Push source is the **filtered staging copy of `Mod/`** (`--content` overrides) taken at run time —
  it uploads whatever is in `Mod/`, so a rebuilt binary that was never installed into `Mod/` is not published.
- `--verify-content` applies `pack_payload.published_name` to both sides before hashing: mapped modules
  (`<root>/*.dll`, `deps/*.dll`, `plugins/<stem>/*.dll`) are published as `<name>.pkg`, so an item that
  predates that rule reports one `layout:` note instead of one "rename" per module. Debug/dev detection
  strips `.pkg` first.

## Filter rules (staging)

- `*.pdb *.lib *.exp *.ilk`, `*.so*`, `*.dylib`, `bin64/osx`, `bin64/linux`, `plugins/update_pending`
- debug-only vcpkg runtimes: `Xd{N}.dll` whose release twin `X{N}.dll` is in the same folder, plus the
  explicit list `bz2d/fmtd/spdlogd/zlibd1/zstdd/mimalloc-debug` (the CI check rejects the same set)
- VCS/editor junk (`.git*`, `*.log`, `*.bak`, `*.orig`, `*.tmp`, `Thumbs.db`), `.ds_plugin_update.lock`,
  `*_fresh.dll` (lock-dodge copy, `GAME_MODULE` doc)
- **Keep** import-closure deps even when they look dev-ish: `frida-gum.dll`, `function_relocation.dll`,
  `pe-parse.dll`, `TracyClient.dll`, `spdlog/fmt/zip/bz2/zlib1`, both ANGLE pairs + `vulkan-1.dll`,
  `lua51DS[_gengc]/lua51Original/lua51`. Verify by parsing PE import tables of `Injector.dll`,
  `bin64/windows/Winmm.dll` and `plugins/*/*.dll`, then recursing into `Mod/deps`.

## Failure modes seen in practice

| Symptom | Cause | Fix |
|---|---|---|
| `upload: idle/finished`, no progress, verification fails | Steam client's UGC state stale (long uptime, client update downloaded but not applied) | restart the Steam client; confirm with `Get-Process steam | Select Id,StartTime` — the StartTime is the truth, not an exit/relaunch attempt |
| `错误: 无效参数/选项 - '//FI'` | Git Bash does not translate `//FI` for tasklist | use `tasklist | grep -i steam` or PowerShell `Get-Process` |
| published DLLs "old" but local is new | the push happened before `cmake --install` refreshed `Mod/` (or the item was never re-pushed) | compare staged payload vs manifest with `--verify-content`; check `Mod/deps` dir mtime vs binary PE time |
| `file_size: 0` right after a push | Valve has not finished indexing the new manifest | not an error; a fresh anonymous download proves the bytes |
