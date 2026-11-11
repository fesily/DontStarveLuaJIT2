---
name: dst-workshop-local-publish
description: 本地发布/核对 DST 创意工坊模组（3444078585）：过滤开发件、--push-content 上传、匿名下载+PE 时间戳复核
---

# 本地发布 DST 工坊模组（DontStarveLuaJIT2）

## 前置
- Steam 客户端在运行并登录（工具走**本地客户端 UGC 会话**，appid 322330；steamcmd 写不了 plain tags）。进程检查用 `Get-Process steam` 或 `tasklist | findstr /i steam.exe` —— **不要**在 Git Bash 里写 `tasklist //FI ...`（`//FI` 不会转成 `/FI`，报“无效参数”并被 `2>/dev/null` 吃掉，误判客户端没开）。
- 构建产物必须已 install 进 `Mod/`（`cmake --install`，mtime 会继承构建时间）；`Mod/` 就是上传源。

## 发布
```powershell
python tools/update_workshop_tags.py --push-content --dry-run   # 核对文件数/大小/跳过项
python tools/update_workshop_tags.py --push-content             # 交互确认；脚本加 --yes
```
版本标签取自 `Mod/modinfo.lua` 的 `version`，发版前先 bump（否则订阅者看不到更新）。

## 过滤规则（已内建，`--no-filter` 关闭，`--ignore-file` 追加）
- `*.pdb *.lib *.exp *.ilk`；`*.so *.so.* *.dylib`；`bin64/linux`、`bin64/osx`；`plugins/update_pending`
- debug vcpkg 运行时：`Xd{N}.dll` 且同目录有 `X{N}.dll`（bz2d/fmtd/spdlogd/zlibd1），与 CI 的 debug-only 检查同规则
- `*_fresh.dll`（`GAME_LUA_MODULE_NAME=lua51DS_fresh.dll` 锁规避副本）、`.git*`、`*.log`、`*.bak`、`Thumbs.db`、`.ds_plugin_update.lock`
- **不要**删 `frida-gum.dll`/`TracyClient.dll`/`function_relocation.dll`/`pe-parse.dll`/`zip,bz2,zlib1`/两套 ANGLE/`lua51DS*`/`lua51Original`/`lua51`：它们由插件导入表或 `stage_core_vm_deps.cmake`、`src/DontStarveInjector/CMakeLists.txt:190,196` 决定，删了 LoadLibrary 失败。删任何 deps 前先跑导入闭包验证。

## 复核（必做）
```powershell
Remove-Item -Recurse steamcmd\steamapps\workshop\content\322330\3444078585
steamcmd +login anonymous +workshop_download_item 322330 3444078585 validate +quit
```
- 文件数/总字节 对比本地 staging；`deps/lua51DS.dll`、`Injector.dll` 用 **PE TimeDateStamp**（`e_lfanew+8`）判断构建日期——下载文件的 mtime 全是下载时刻，不可用。
- 物品 API `ISteamRemoteStorage/GetPublishedFileDetails`：看 `hcontent_file` 是否变化、`tags` 里的 `version:x`；`file_size` 可能短暂为 0，不代表失败。
- Steam 日志：`Steam/logs/workshop_log.txt` 有 `Uploaded new content ( ManifestID … )` 才是真内容更新；没有这行的 OK 只是元数据/标签。

## 已知坑
- 客户端长时间运行或“更新已下载待重启”时，`SubmitItemUpdate` 可能被静默吞掉（进度停在 idle/finished、校验失败）→ 真正重启 Steam 客户端再推；工具会在校验失败时提示。
- `steam://exit` 不一定生效，用进程 StartTime 验证是否真的重启过。
- `Mod/deps` 里没有 `meta/manifest.json`（CI 才用 `gen_plugins_manifest --write-meta` 生成 build_config 戳）。
