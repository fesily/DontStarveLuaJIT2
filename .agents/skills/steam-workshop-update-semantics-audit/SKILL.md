---
name: steam-workshop-update-semantics-audit
description: 判断 Steam 创意工坊物品更新在客户端/引擎侧是覆盖、整目录删除还是 API 驱动；查 stale 文件来源
---

# Steam 创意工坊更新语义核查

## 结论骨架（先给答案）
- 引擎（如 DST 的 `SteamModWorkshop.cpp`）只用 **ISteamUGC**：`SubscribeItem` / `DownloadItem` / `GetItemInstallInfo` / `GetItemUpdateProgress`；不自己拷贝内容。
- Steam 客户端才是落盘者：先下到 `steamapps/workshop/downloads/<appid>/<itemid>`，再 **commit** 到 `steamapps/workshop/content/<appid>/<itemid>`：`N updated, N moved, N deleted files`。
- 更新**不删目录**；整目录删除只发生在取消订阅/物品不可见（引擎 `DeleteSubscribedFiles` / `Deleting directory`）或校验重下。
- `deleted` 生效的前提是物品带 **content manifest**（steamcmd `workshop_build_item` 的 `contentfolder`，或 `ISteamUGC::SetItemContent` 指向文件夹）。无 manifest 的上传只覆盖同名文件 → 孤儿文件永留（典型事故：新 Lua + 旧 DLL）。

## 取证步骤（本机可复现）
1. Steam 内容日志：`<Steam>/logs/content_log.txt`，grep `starting commit from` / `Validating active workshop item` / `deleted files`。这是“覆盖 vs 删除”的第一手证据。
2. 物品状态：`<library>/steamapps/workshop/appworkshop_<appid>.acf`（manifest/timeupdated）。
3. 引擎侧：对游戏 exe 跑 `strings`，搜 `ISteamUGC` 接口版本串（如 `STEAMUGC_INTERFACE_VERSION016`）、`DownloadPublishedFile`、`DeleteSubscribedFiles`、`Deleting directory`、`CancelDownloads`；`-ugc_directory` 可改 workshop 根。
4. 平台差异只有路径：Windows `<Steam>/steamapps/...`，macOS `~/Library/Application Support/Steam/steamapps/...`，Linux `~/.steam/steam/steamapps/...`（Flatpak/WSL 另有变体）；算法一致，APFS 默认大小写不敏感只影响命名。

## 发布侧建议
- 每次上传用**干净重建**的 staging 目录 + `contentfolder`，让 removals 传播到订阅端；不要在内容目录里就地改再传。
- 服务器侧 `steamcmd +workshop_download_item` 同样走 downloads→content 的 commit，不是重下整目录。
