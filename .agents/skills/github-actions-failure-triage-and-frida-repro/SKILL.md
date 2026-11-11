---
name: github-actions-failure-triage-and-frida-repro
description: 定位 GitHub Actions 失败步骤/注解：无 gh 用公开 API，有 gh 直接拉 job 日志；含 DontStarveLuaJIT2 Windows job 的 vcpkg/frida 下载与 Git-Bash-link 坑清单
---

# 定位 CI 失败步骤（无 gh、无 actions:read 时）

公开 API 足够定位“哪一步、多久、什么注解”，日志正文需要权限：

```bash
# 1) 某 commit 的所有 check-run（拿到 job id 与结论）
curl -sS "https://api.github.com/repos/<owner>/<repo>/commits/<sha>/check-runs?per_page=20"
# 2) check-run 的注解（往往就是唯一的错误文本，如 FATAL_ERROR 的 message）
curl -sS "https://api.github.com/repos/<owner>/<repo>/check-runs/<check_id>/annotations"
# 3) job 的分步时间戳 → 直接看出失败的那一步
curl -sS "https://api.github.com/repos/<owner>/<repo>/actions/jobs/<job_id>"
```

时长本身就是证据：同一 job 之前某步 14 分钟成功、现在 86 秒失败，说明是早退错误而不是“变慢”。

日志正文：`/actions/jobs/<id>/logs` 需要 `actions:read`。Windows 上 `git credential fill`（protocol=https host=github.com）拿到的 GCM token 通常能过 `/user` 但对该端点 403——不要反复试 Bearer/token/Basic，直接请用户贴日志片段。

注意：`/actions/runs?head_sha=` **只认完整 40 位 sha**，短 sha 返回 total_count 0（用 `?per_page=N` 列表 + 前缀匹配代替）。未认证 API 只有 60 次/小时，反复轮询会把自己打停（reset 前所有查询都返回 rate-limit JSON，`j['jobs']` 直接 KeyError）。

# 有 gh（已认证）时：直接拉 job 日志

本机 `gh` 在 `C:\Program Files\GitHub CLI\gh.exe`，账号已 `repo`+`workflow` 授权，5 000 次/小时，足以替代上面所有 curl 轮询：

```bash
# 失败步骤全文（job 结束后可取；in-progress 时会提示 logs will be available when it is complete）
gh run view --log --job <job_id> > job.log
# 只要失败步骤：按 “\t<step name>\t” 切分日志，再 grep error/failed/timeout
# 结论与步骤状态
gh run view <run_id> --json jobs --jq '.jobs[] | "== \(.name) \(.conclusion // .status)", (.steps[] | select(.conclusion!="success" and .conclusion!="skipped") | "   FAIL \(.number) \(.name) \(.conclusion)")'
gh run watch <run_id> --interval 30 --exit-status    # 后台跑，别前台阻塞
```

从 Node/action 包装层抛出的错误（如 `run-vcpkg action execution failed: Last command execution failed with error code '1'`）**只有日志能给出真因**——注解永远是退出码。

# DontStarveLuaJIT2 Windows job：已知下载/工具链坑（2026-11 实测）

| 失败签名 | 真因 | 处置 |
|---|---|---|
| `Download failed, halting portfile` + `vcpkg install failed` | port 源码从 codeload.github.com 拉，且 `.vcpkg-downloads` 未缓存 | job env `VCPKG_DOWNLOADS=<ws>/.vcpkg-downloads` + `actions/cache`（key 用 vcpkg.json + vcpkg-configuration 的 pinned baseline，前缀 restore）；实测一次失败 run 仍能存下 706.9 MiB |
| `run-vcpkg action execution failed: … error code '1'`，日志里 `Downloading …/vcpkg-tool/releases/download/<tag>/vcpkg.exe` → `The operation timed out` | `lukka/run-vcpkg@v11` 默认 `doNotCache: true`，每次 run 用 `scripts/tls12-download.exe`（无重试、约 30 s 超时）重下 6.6 MB 工具 | 去掉该 action：读 `vcpkg/scripts/vcpkg-tool-metadata.txt` 的 `VCPKG_TOOL_RELEASE_TAG`，`curl -fL --retry 3 --retry-all-errors --connect-timeout 20 --max-time 300` 下 `vcpkg.exe`，再用 `vcpkg version` 校验；工具按 vcpkg submodule sha 缓存 |
| `Failed to set up Frida-Gum`（每次 attempt 一条） | frida `configure` 的 meson `[wrap-git]` 逐个 `git clone` 失败（504） | 在 configure 前预克隆每个 wrap（`git init` + `fetch --depth 1 <pinned sha>` + `checkout FETCH_HEAD`，每仓库 3 次重试；跳过 v8）；并在 `tools/setup_frida_gum.py` 只对 configure 步做 3 次重试（`make` 失败是编译错误，重试会把构建成本×3） |
| `meson.build:1:0: ERROR: Found GNU link.exe instead of MSVC link.exe in C:\Program Files\Git\usr\bin\link.EXE` | configure 步用 `shell: bash` 后 Git Bash 把自带 `usr/bin` 排在前，GNU `link` 抢掉 MSVC `link.exe`（`lukka/run-cmake` 是 Node 动作所以以前没事） | 步内把 `$VCToolsInstallDir/bin/Hostx64/x64` 用 `cygpath -u` 转成 POSIX 路径**前置**到 PATH，并打印 `command -v link` 自证；**不要**删 PATH 里的 MSYS 目录（`sed`/`printf`/`sleep` 都在那），Linux 上该变量为空即 no-op |

通用注意：
- `actions/cache/save` 若写 `if: cache-hit != 'true'`，已存在的 key **永不更新**（缓存冻结在首份快照）；本仓 `Windows-vcpkg` 因此长期只有 45 MiB，每次 run 都要重装全部 port。需要滚动更新时改成唯一 key（含 `github.run_id`）+ 前缀 `restore-keys`。
- 用 `gh api …/actions/caches` 可读缓存清单与大小（未认证也可），判断“淘汰 vs 冻结”比猜快。
- `tools/frida/**` 里 4 900+ 条目多是未跟踪的 node_modules，`hashFiles('tools/frida/**')` 在 CI 干净检出时只哈希 8 个跟踪文件，不必担心。

# 本地复现 frida-gum 从源码构建（DontStarveLuaJIT2 场景）

```bash
cd 3rd/frida-gum-src
git worktree add --detach "C:/Users/<u>/AppData/Local/Temp/fgrepro/fg" <pinned-sha>   # 路径必须写 Windows 原生形态，/c/... 会被 git 当成 C:/c/...
cd <fg> && git submodule update --init --recursive --depth 1                        # releng/meson 是嵌套子模块
```

然后用 py driver（`python -c` 多行在 .bat 里会被拆散，必须落成 .py）调用 `releng.meson_configure.main()`，`sys.argv=['configure','.','--prefix=...','--with-devkits=gum','--disable-tests']`，并在 vcvars64 环境里跑。

坑：`releng/env_generic.py detect_linker_flavor` 用 `locale.getpreferredencoding()` 解 `cl -Wl,--version` 的输出；系统开了 UTF-8 beta 时返回 utf-8，遇到本地化中文 `cl` 报错（CP936 字节）直接抛 `UnicodeDecodeError: 0xb0`——在 driver 里设 `PYTHONUTF8=0` 即可绕过（`VSLANG=1033` 对 VS2022 的中文 cl 无效）。

configure 成功只证明下载+meson setup 没问题（SDK 约 700MB，缓存在 `<src>/deps/`）；真正耗时的 `make.bat` 才是 CI 上无法验证的盲区。
