---
name: steam-workshop-content-vs-local-verify
description: "Verify what a Steam Workshop item actually serves vs the local mod tree (anonymous steamcmd download, PE timestamps, junction/mtime pitfalls); use when published DLLs look stale or after a local push."
---

# Verify a Steam Workshop item's published content vs local

Use when: the workshop copy of a mod has stale DLLs, or right after a local `--push-content`, to prove what is actually published.

## 1. Item metadata

```powershell
python -c "import json,urllib.request,datetime; req=urllib.request.Request('https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/', data=b'itemcount=1&publishedfileids[0]=3444078585'); d=json.load(urllib.request.urlopen(req))['response']['publishedfiledetails'][0]; print('size',d['file_size'],'manifest',d['hcontent_file'],'updated',datetime.datetime.fromtimestamp(d['time_updated']))"
```

## 2. Download the published manifest (anonymous, does not touch the client cache)

```powershell
"C:/steamcmd/steamcmd.exe" +login anonymous +workshop_download_item 322330 <ID> validate +quit
# -> C:\steamcmd\steamapps\workshop\content\322330\<ID>
```

The reported byte count must equal the API `file_size`; otherwise the download is not the current manifest.

## 3. Diff against the local tree with the upload tool's own filter

`tools/update_workshop_tags.py` stages `Mod/` skipping: `*.pdb *.lib *.exp *.ilk *.so *.so.* *.dylib`, `bin64/osx`, `bin64/linux`, `plugins/update_pending`, `.ds_plugin_update.lock`, `test.log`. Apply the same rules, then compare file count, total bytes, names only in one side, and per-file size mismatches.

## 4. Judge build age by PE header, not mtime

```python
pe = struct.unpack_from("<I", b, 0x3C)[0]
ts = struct.unpack_from("<I", b, pe + 8)[0]   # TimeDateStamp, UTC
```

Plus `sha1` for equality. Reason: Steam downloads stamp every file with the download time.

## 5. Upload history

`C:\Program Files (x86)\Steam\logs\workshop_log.txt`: only entries containing `Uploaded new content ( ManifestID ... )` are content uploads; others are metadata/tag updates. `Upload starting` + `Upload finished ... : OK` without the ManifestID line means the content did not change.

## Pitfalls (hit in practice)

- On this workstation `.../steamapps/workshop/content/322330/3444078585` is a junction to `C:\Users\fesil\DontStarveLuaJIT2\Mod`. Browsing it shows the working tree, never downloaded bytes.
- Downloaded files all carry the download timestamp; an "Oct 9" file date proves nothing.
- `deps/lua51.dll` is the upstream PUC Lua 5.1 prebuilt (PE 2024-04-30) that the build never regenerates — not a staleness signal.
- The local push uploads `Mod/` **as it is at run time**; if `cmake --install` has not refreshed it, the previous build is republished. The CI `release.yaml` only zips `./Mod` into `<platform>_Mod.zip` (release asset); it has no workshop-upload job.
- Git Bash: `tasklist //FI "IMAGENAME eq steam.exe"` fails (`无效参数/选项`) because MSYS does not translate `//FI`; with `2>/dev/null` that reads as "Steam not running". Use `tasklist | grep -i steam` or `Get-Process steam`.
- A Steam client that staged a client update but was never restarted can drop UGC writes; the tool reports `upload: idle/finished` with no progress. Re-check with `Get-Process steam | Select StartTime` before concluding anything about restarts.
