# steam-workshop-deploy (vendored fork)

Upstream: <https://github.com/m00nl1ght-dev/steam-workshop-deploy>, tag `v4`, MIT (see `LICENSE`).
This directory is a copy of upstream v4 plus the single addition described below. When upstream
moves, copy the new files first and re-apply the patch — nothing else here is ours.

## Why a copy

Upstream builds its `workshopitem` manifest with only `appid` / `publishedfileid` /
`contentfolder` / `changenote`, so the SteamCMD run inside the container has no way to express
tags. SteamCMD's manifest parser (the image's `steamconsole.so`) recognises exactly one tag key —
`kvtags` (key/value pairs, mapped to `ISteamUGC::AddItemKeyValueTag`) — and no plain `tags` key.
This copy exists to add that key.

## Patch (pure insertions, upstream text verbatim)

| File | Addition |
|---|---|
| `action.yml` | input `kvTags` (newline-separated `key=value`), forwarded to the container as `$kvTags` |
| `steam_deploy.sh` | builds a `"kvtags" { ... }` block from `$kvTags` and interpolates it into `manifest.vdf`; an entry without `=` aborts the run before anything is uploaded |

Additions are marked with `fork addition` comments in `steam_deploy.sh`.

## Limitation — read before relying on it

DST decides "mod out of date" from the item's **plain** tag string:
`SteamModWorkshop::GetVersionFromTags` scans the comma-joined `m_rgchTags` field of the legacy
`RemoteStorageGetPublishedFileDetailsResult_t` for `version:` and compares it with the local
`modinfo.version` (`Mod/modmain.lua` → `AllowLocalNewerWorkshopVersion`). SteamCMD cannot write
plain tags at all — only `kvtags` — so this action adds metadata; it does **not** maintain the
`version:<modinfo.version>` tag that the game reads. Keeping that tag current needs an
authenticated UGC client (Steam client session, or a CM session with a refresh token), or the
official Don't Starve Mod Tools uploader.

## Usage

```yaml
- uses: ./.github/actions/steam-workshop-deploy
  with:
    username: ${{ secrets.STEAM_USERNAME }}
    configVdf: ${{ secrets.STEAM_CONFIG_VDF }}
    appId: '322330'
    publishedFileId: '3444078585'
    path: workshop
    kvTags: |
      version=${{ steps.project-version.outputs.version }}
    changeNote: 'v${{ steps.project-version.outputs.version }}'
```
