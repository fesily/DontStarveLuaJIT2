---
name: gha-ci-github-download-reliability
description: GitHub Actions 下载（vcpkg/frida/资产）随机 504/超时/限流：用 gh 取证、token 化、按 ABI 定 key、少下载；含 Git Bash GNU link 顶掉 MSVC link 的坑
---

# 症状

GitHub Actions 下载类步骤随机失败：`504`、`Download failed, halting portfile`、`The operation timed out`、`run-vcpkg … error code 1`（只有退出码没有原因），而同一 commit 的 Linux job 通过。重试后仍失败。

# 先取证据（不要再猜）

```bash
# 未认证 API 只有 60/h，会被自己的轮询打爆 → 一律用已登录的 gh
gh auth status                                  # 需要 repo(+workflow) scope
gh run list --limit 5 --json databaseId,headSha,status
gh run view <run-id> --json jobs --jq '.jobs[] | "\(.name) \(.conclusion)", (.steps[]|select(.conclusion!="success")|"  FAIL \(.number) \(.name) \(.conclusion)")'
gh run view --log --job <job-id> > job.log     # 匿名 REST /logs = 403 admin rights
```

在 `job.log` 里只 grep 关键词即可定位：`Downloading`、`Restored `、`Running vcpkg install`、`The operation timed out`、`error code`、`GNU link.exe`、`VCToolsVersion:`。

缓存的真实内容用公开 API 就能看（不需要 actions:read）：

```bash
gh api "repos/<o>/<r>/actions/caches?per_page=30" \
  --jq '.actions_caches[] | "\(.size_in_bytes/1048576|floor)MiB created=\(.created_at) used=\(.last_accessed_at) \(.key[0:52])"'
```

`created_at` 与 `VCToolsVersion`/`vcpkg version` 一对照，就能判定"缓存是哪个 ABI 代的"。

# 判定表

| 现象 | 本质 | 处理 |
|---|---|---|
| `API rate limit exceeded` / 403 | 匿名按共享出口 IP 限流（60/h） | token 化 |
| `Download failed, halting portfile` | port 源码（codeload）拿不到 | 源码缓存 / 镜像 |
| `The operation timed out`（~30 s） | 上游下载器无重试（如 `tls12-download.exe`） | 换 `gh release download` |
| `error code 1` 且无正文 | action 把子进程退出码直接抛出 | 看 step 展开的 `with:`/日志行，或干脆自建该步骤 |
| `Restored 0 package(s)` + 长时间 `Installing n/N` | 二进制缓存 key 与 ABI 不同源 | key 叠加 toolset/镜像版本 |

# 修法（按可靠性排序，不要只加重试）

1. **不下载**：把输入放进仓库或镜像里——例如 CMake 已有 `--skip-meson` 分支时，提交 `3rd/<dep>/_legacy_<plat>/{lib,header}`；vcpkg registry 用 builtin registry（`builtin-baseline` = 子模块 HEAD）代替 git registry。
2. **token 化**（消除匿名限流）：
   ```yaml
   env:
     GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}   # 自动签发，但默认不注入
     GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
   ```
   checkout 只给自己的 fetch 设 `http.extraheader`，后续被 spawn 的 git（meson wrap、vcpkg registry）仍是匿名：
   ```bash
   git config --global --add credential.https://github.com.helper \
     '!f() { echo username=x-access-token; echo "password=${GITHUB_TOKEN}"; }; f'
   ```
   （helper 里只放变量引用，别把 token 拼进 URL，否则会进 `.gitconfig`/日志。）
   资产下载用 `gh release download <tag> -R <o>/<r> -p <asset> --dir <d> --clobber`，然后跑一次校验（如 `vcpkg version`）。
3. **缓存必须与"内容身份"同源**：
   - vcpkg 二进制缓存条目按 ABI hash（含**编译器版本**）命名；外层 key 只用 manifest 会出现"key 命中但还原 0 条"。key 里叠加 `VCPKG_TOOL_RELEASE_TAG` + `$VCToolsVersion` + `$ImageVersion`，并**去掉 restore-keys**（别的 ABI 域的二进制不可用）。
   - 保存条件 `if: cache-hit != 'true'` 在 key 正确时才是对的；key 不精确时它会永久冻结缓存。
   - 源码缓存（`VCPKG_DOWNLOADS`）、stage/devkit 缓存按"内容哈希"取 key 即可。
4. **重试只做兜底**，别当机制：整步 3 次 + 20/40 s 退避；只重试 configure 这类"会下载"的命令，`make`/编译失败不要重试（会 3 倍耗时）。

# 坑

- `shell: bash` 在 Windows runner 上把 Git 的 `usr/bin` 排在 PATH 前面，里面有 GNU `link`，meson 探测会报 `Found GNU link.exe instead of MSVC link.exe in C:\Program Files\Git\usr\bin\link.EXE`。修：在步骤内把 `$VCToolsInstallDir/bin/Hostx64/x64` 前置到 PATH。
- `runner` label（如 `windows-2025-vs2026`）是滚动的，"指定 label"≠ ABI 固定；`ImageVersion`/`VCToolsVersion` 才是 ABI 代际。
- 想量化收益：同 ABI 的 files-provider 缓存实测 `Restored 27 package(s) … in 1.8 s`，而全量重编 11 分钟。
