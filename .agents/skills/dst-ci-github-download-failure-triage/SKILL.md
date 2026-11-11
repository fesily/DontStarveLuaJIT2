---
name: dst-ci-github-download-failure-triage
description: DontStarveLuaJIT2 的 Windows CI 因 GitHub 下载失败（504/timeout/匿名限流）变红时：用 gh 取证、盘点四个下载面与缓存实况、按“不下载 token+单次 重试”修复；含 Git Bash link.exe 顶掉 MSVC、GITHUB_TOKEN 不自动注入 env、vcpkg registry 缓存在 workspace 外等陷阱
---

# 适用
DontStarveLuaJIT2 的 Windows CI 因“从 GitHub 下载”变红（504 / `Download failed, halting portfile` / `The operation timed out` / `API rate limit exceeded`），或要改 CI 的下载/缓存步骤。

# 1. 先取证，别猜
```bash
gh run list --limit 5 --json databaseId,headSha,status,conclusion
gh run view --log --job <job-id> > job.log      # 需要登录态
grep -E "Download failed|timed out|rate limit|Failed to set up Frida|link.exe" job.log
```
- 未认证 REST 取日志 = `403 Must have admin rights to Repository`；未认证 REST 只有 60 次/小时 → 排查期间一律用 `gh`。
- 缓存现状（公开可读）：`gh api repos/<o>/<r>/actions/caches --jq '.actions_caches[] | "\(.size_in_bytes/1048576|floor)MiB \(.key)"'`。二进制缓存只有几十 MiB 通常意味着“保存步骤被 `if: cache-hit != 'true'` 冻结在首次快照”，不是被淘汰。

# 2. 四个下载面（本仓库）
| 面 | 谁在下载 | 缓存位置 | 须知 |
|---|---|---|---|
| vcpkg tool (6.6 MB) | `lukka/run-vcpkg`（输入 `doNotCache: true`）→ `bootstrap.ps1` → `tls12-download.exe`（约 30 s 超时、无重试） | 无（可自建） | 改 `gh release download <tag> -R microsoft/vcpkg-tool -p vcpkg.exe` |
| vcpkg registry | `vcpkg install` clone `microsoft/vcpkg@baseline` | `%LOCALAPPDATA%\vcpkg\registries` / `~/.cache/vcpkg/registries` —— **workspace 之外** | `actions/cache` 抓不到；`X_VCPKG_REGISTRIES_CACHE` 可重定向，或改 `builtin-baseline` = submodule HEAD 走本地 ports 树 |
| port 源码 tarball | `vcpkg install` | `VCPKG_DOWNLOADS`（必须显式设，默认在 vcpkg 树里） | 缓存它可让 port 重装时不联网 |
| frida-gum 15 个 `[wrap-git]` | meson 逐个 `git clone`（单次、无重试） | 无 | 本仓库支持 `--skip-meson`：`3rd/frida-gum/<plat>` marker 或 `3rd/frida-gum-build/input` 的大静态库；`3rd/frida-gum/<plat>/lib/frida-gum.lib` 是壳的 import lib（0.3 MB），**不能**当静态库 |

判定类型：`403 API rate limit exceeded` = 真限流（匿名 60/h/共享 IP）；504 / `Download failed` / `The operation timed out` = CDN/网关，**token 不能免疫**。

# 3. 修复优先级
1. **不下载**：把输入放进仓库或 runner 镜像（frida devkit、镜像自带 `C:\vcpkg`），或让缓存按输入内容命名并滚动更新（`key: <base>-${{ github.run_id }}` + `restore-keys: <base>-`），而不是 `cache-hit != 'true'` 一锤子。
2. **token 认证 + 单次请求**：job `env: GITHUB_TOKEN/GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}`（Actions 自动签发但**不注入 env**）；`actions/checkout` 只给自己的 fetch 设 `http.extraheader`，meson/vcpkg spawn 的 git 需要
   `git config --global --add credential.https://github.com.helper '!f() { echo username=x-access-token; echo "password=${GITHUB_TOKEN}"; }; f'`（只引用变量，避免 token 落盘/进日志）。
3. **重试**：只在“改 manifest”这类明确事件上兜底，不要当机制。

# 4. 已知陷阱
- 把 `lukka/run-cmake` 换成 `shell: bash` 后：Git Bash 的 `/usr/bin/link` 顶掉 MSVC `link`，frida meson 报 `Found GNU link.exe instead of MSVC link.exe in C:\Program Files\Git\usr\bin\link.EXE`。修法：该步内 `PATH="$(cygpath -u "${VCToolsInstallDir%\\}")/bin/Hostx64/x64:$PATH"`。
- `vcpkg` 是 submodule：**不能**把 `vcpkg.exe` 放进 `vcpkg/` 提交（`git check-ignore` 报 is in submodule）；要放就放 `3rd/vcpkg-tool/` 再 copy。
- 只提交 stage 不安全：frida 的 fingerprint 绑 submodule commit + `tools/frida/FridaGum.def`，失配后脚本需要大静态库，否则 `die`。

# 5. 验证套路（本地可做）
- 用 Python 从 YAML 抽出 `run:` 整块，改 `${{ runner.os }}` 后落成 .sh 交给 `C:\Program Files\Git\bin\bash.exe` 真跑（stub `cmake`/`sleep` 可测重试语义；隔离 `HOME` 可测 credential helper 不泄漏 token）。
- `gh release download <tag> -R microsoft/vcpkg-tool -p vcpkg.exe` 后必须 `vcpkg version --disable-metrics` 校验。
