---
name: gha-vcpkg-cache-and-toolchain-forensics
description: Windows/Linux GitHub Actions 构建因 GitHub 下载 504、vcpkg 缓存冻结、toolset 漂移失败：用 gh 取日志判定、按 ABI 域修缓存键
---

# 适用

GitHub Actions 构建因「从 GitHub 下载」失败（`504`、vcpkg `Download failed, halting portfile`、`run-vcpkg … error code 1`、`The operation timed out`）、或 vcpkg 缓存看起来有却没生效、或换了 runner 镜像后行为突变时。

# 1. 先拿日志，别猜

* 未认证 REST 拿 job 日志会 403：`{"message":"Must have admin rights to Repository."}`；公开 API 还只有 **60 次/小时**（按出口 IP，`gh` 之外反复轮询会把自己打爆）。
* 用登录的 `gh`（`repo` scope 足够）：

```bash
gh run list --limit 8 --json databaseId,headSha
gh run view --log --job <job-id> > job.log     # 完成后的 job 才能拿；进行中会说 logs will be available when it is complete
gh api "repos/<o>/<r>/actions/runs/<run>/jobs?per_page=20" --jq '.jobs[] | "\(.id) \(.name) \(.conclusion)"'
```

字段坑：`gh run view --json jobs` 里 job 主键是 **`id`**（不是 `databaseId`）；run 的尝试号是 **`attempt`**（不是 `runAttempt`）；`gh run view --exit-status` 套 `| tail` 会被 tail 的退出码盖掉。

# 2. 判定「缓存是否真生效」

在 configure 日志里 grep 这两类行：

```
Restored N package(s) from <bincache> in <t>        # 二进制缓存还原数
Elapsed time to handle <port>: <t>                   # 每包耗时（秒级=还原，分钟级=重编）
```

* `Restored 0` + 逐包 `Installing … / Elapsed time … min` ⇒ **key 命中但条目全废**。
* 参照：本项目 manifest 的完整二进制缓存 ≈ **48 MiB / 29 zip**，同 ABI 下 `Restored 27 package(s) in 1.8 s`（整体 install 57 s，对比 11–15 分钟重编）。

# 3. vcpkg 三层缓存别混

| 层 | 默认位置 | 内容 | CI 注意 |
|---|---|---|---|
| 二进制缓存（编译产物） | `~/AppData/Local/vcpkg/archives` / `~/.cache/vcpkg/archives` | 每包 zip，文件名为 **ABI hash（含编译器版本）** | 外层 `actions/cache` key 必须体现 ABI 域，否则 key 命中、条目全废 |
| 源码缓存 | `VCPKG_DOWNLOADS` | 三方源码包 + vcpkg 自用工具（cmake/7z/msys2） | 命中后仍编译但**不联网**，是扛 504 的真正那层 |
| registry 缓存 | `X_VCPKG_REGISTRIES_CACHE`，默认 `%LOCALAPPDATA%\vcpkg\registries` / `~/.cache/vcpkg/registries` | baseline 的 git checkout（ports 元数据） | **在 workspace 之外**，`actions/cache` 抓不到 ⇒ 每 run 都 clone；要么指进 workspace，要么改 builtin registry |

# 4. 修缓存键（最小改动）

```yaml
- name: Compute vcpkg binary-cache key      # 必须放在 MSVC 环境初始化之后
  id: vcpkg-abi
  shell: bash
  run: |
    tool=$(sed -n 's/^VCPKG_TOOL_RELEASE_TAG=//p' vcpkg/scripts/vcpkg-tool-metadata.txt | tr -d '\r' | head -1)
    echo "key=${tool}-${VCToolsVersion:-no-msvc}-${ImageVersion:-no-image}" >> "$GITHUB_OUTPUT"
- uses: actions/cache/restore@v4
  with:
    path: .vcpkg-bincache
    key: ${{ runner.os }}-vcpkg-${{ steps.vcpkg-abi.outputs.key }}-${{ hashFiles('vcpkg.json','vcpkg-configuration.json','cmake/custom-triplets/**','CMakeLists.txt') }}
    # 不要 restore-keys：跨 ABI 域的二进制按定义不可用
```

`Save` 保留 `if: cache-hit != 'true'` 即可——key 与 ABI 同源后，命中就意味着条目真的匹配。
`windows-*` 是**滚动镜像**：label 固定时 `VCToolsVersion` 仍会变（实测 14.44.35207 → 14.51.36231），一次重建是正常行为。

# 5. token 化，别只加重试

```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}   # 自动签发但默认不注入，必须显式传
  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

* `actions/checkout` 只给自己的 fetch 设 `http.extraheader`；meson/vcpkg 里 spawn 的 git 是**匿名**的。用 credential helper（只引用变量，别把 token 写进 URL/配置）：

```bash
git config --global --add credential.https://github.com.helper \
  '!f() { echo username=x-access-token; echo "password=${GITHUB_TOKEN}"; }; f'
```

* 资产下载走 `gh release download <tag> -R <repo> -p <asset> --dir <dir> --clobber`（认证 API，错误可判定），别用仓库自带的无重试下载器（如 vcpkg 的 `tls12-download.exe`：~30 s 超时、只报 `error code 1`）。
* 边界：API 配额只约束 `api.github.com`；`github.com/.../releases/download/...`、`codeload.github.com` 是 CDN，token 只降低"匿名被限/降级"，**不能免疫 504** ⇒ 真正的确定性来自"不下载"（内置/缓存/单次不可变对象）。

# 6. Windows 专属坑

* `shell: bash` 会把 Git 的 `usr/bin` 排在 PATH 前，里面有 GNU `link`；meson 探测报 `Found GNU link.exe instead of MSVC link.exe in C:\Program Files\Git\usr\bin\link.EXE`。修法：把 `$VCToolsInstallDir`（去尾分隔符）`/bin/Hostx64/x64` 用 `cygpath -u` 转换后**前置**；**不要**删 `/usr/bin`（sed/printf/sleep 都在那）。
* runner 镜像自带 vcpkg（`C:\vcpkg`，且 VS 下也有 `VCPKG_ROOT`），可用它省掉 bootstrap 下载；注意 `vcpkg/` 是 submodule，exe 不能提交进它内部。
* `lukka/run-vcpkg@v11` 的输入里 `doNotCache: true`，且 Windows bootstrap 走 `scripts/tls12-download.exe`（30 s 超时、无重试）——这就是 `error code 1` 的最常见真因。

# 7. 想"零重试"时的顺序

1. 不下载：内置（提交 devkit/工具）→ 镜像自带 → 内容寻址缓存；
2. token 化 + 单次不可变对象（release asset + checksum）；
3. 匿名 + 重试（只当兜底，不要当机制）。
