---
name: dst-ci-github-download-and-abi-cache-triage
description: GitHub Actions 下载失败（504/timeout）与 vcpkg 二进制缓存失效的诊断与确定性修法：gh 拉日志分类、三缓存辨析、ABI/toolset 漂移与 key 组成、frida/vcpkg 免下载方案、本仓库踩坑
---

# 适用
本仓库 GitHub Actions 因「下载」失败（504 / `Download failed, halting portfile` / `The operation timed out` / `error code 1`），或 vcpkg 二进制缓存看起来命中却仍在重编时。不适用：本地构建失败、非 GitHub 源的问题。

# 1. 先拿日志（不要猜）
未认证 REST 只有 60 次/小时（会拿到 `API rate limit exceeded for <ip>`）；日志端点要求 admin。用已登录的 gh：
```bash
gh run list --limit 5 --json databaseId,headSha,status,conclusion
gj=$(gh api "repos/<o>/<r>/actions/runs/<run>/jobs?per_page=20" --jq '.jobs[]|select(.name|test("windows"))|.id')
gh run view --log --job "$gj" > job.log      # 只在 job 结束后可取
```
按 `\t<step name>\t` 切段看单步输出；`--jq` 里 `jobs` 的键名：REST 用 `id`，`gh run view --json jobs` 用 `databaseId`。

# 2. 分类，别混谈
| 现象 | 本质 | 处理 |
|---|---|---|
| `403 API rate limit exceeded` | 匿名按共享出口 IP 限流 | 用 `GITHUB_TOKEN`/`gh` |
| `504` / `Download failed` / `The operation timed out` | CDN/网关超时 | token 只降低概率；要「零重试」只能不下载 |
| `Restored 0 package(s)` + 全量 `Installing n/27` | 二进制缓存 ABI 不匹配 | 见 §4 |

# 3. 三个 vcpkg 缓存（必须分清）
| 缓存 | 路径 | 内容 |
|---|---|---|
| 二进制缓存 | `VCPKG_BINARY_SOURCES=clear;files,<dir>,readwrite` | 编译产物 zip，按 **ABI hash** 命名；本 manifest 全量约 48 MiB |
| 源码缓存 | `VCPKG_DOWNLOADS` | 第三方源码包 + vcpkg 自用工具（cmake/7z/msys2） |
| registry 缓存 | `~/.cache/vcpkg/registries`（Win `%LOCALAPPDATA%\vcpkg\registries`） | pinned baseline 的 ports 元数据克隆，**在 workspace 外**，actions/cache 抓不到 |

用 `gh api repos/<o>/<r>/actions/caches?per_page=30 --jq ...` 看每个 key 的 `size_in_bytes/created_at`：`created_at` 早于当前镜像/toolset 就是「化石」。

# 4. 二进制缓存失效的两个独立原因
1. **外层 key 与 ABI 不同源**：ABI 含 compiler version。查证方法：对比旧 job 与当前 job 日志里的 `VCToolsVersion:`（本仓库实测 `14.44.35207` → `14.51.36231`，因为 `windows-2025-vs2026` 是滚动标签）。vcpkg 工具版本来自 `vcpkg/scripts/vcpkg-tool-metadata.txt`，由 submodule pin 决定，一般不是漂移源。
2. **`if: cache-hit != 'true'` 冻结**：key 命中就永不写，条目永远是最早那份。
修复形状：
```yaml
- id: vcpkg-abi                        # 放在 Initialize MSVC 之后
  run: |
    tool=$(sed -n 's/^VCPKG_TOOL_RELEASE_TAG=//p' vcpkg/scripts/vcpkg-tool-metadata.txt | tr -d '\r' | head -1)
    echo "key=${tool}-${ImageVersion:-unknown}-${VCToolsVersion:-none}" >> "$GITHUB_OUTPUT"
key: ${{ runner.os }}-vcpkg-${{ steps.vcpkg-abi.outputs.key }}-${{ hashFiles('vcpkg.json','vcpkg-configuration.json','cmake/custom-triplets/**','CMakeLists.txt') }}
# Save: if: always()
```

# 5. 本地验证缓存机制本身（不烧 CI）
```python
# 复制 %LOCALAPPDATA%\vcpkg\archives 到临时 bin，然后：
# VCPKG_BINARY_SOURCES=clear;files,<tmp bin>,read
vcpkg install --triplet x64-windows-custom --overlay-triplets=cmake/custom-triplets \
  --only-binarycaching --x-install-root <tmp> --x-manifest-root .
# 期望：Restored 27 package(s) … in 1.8 s
```
`--only-binarycaching` 让「无缓存」直接报错而不是编译，几秒出结论。manifest 模式不能带包名参数。

# 6. 「不需要重试」的做法（按确定性排序）
1. **不下载**：frida-gum 提交 `3rd/frida-gum/_legacy_<plat>/{frida-gum.lib,frida-gum.h}`（win64 68.9 MiB）走 CMake 的 `--skip-meson`；只交 stage 不够（其 `lib/frida-gum.lib` 是 0.3 MB import lib，fingerprint 失配时 `_looks_like_static_archive` 会拒绝）；vcpkg tool 用镜像自带 `C:\vcpkg` 或提交到 `3rd/vcpkg-tool/`（不能进 `vcpkg/`，那是 submodule）；registry 改 `builtin-baseline` 指向 submodule commit。
2. **token 化 + 单次不可变对象**：job 级 `GITHUB_TOKEN`/`GH_TOKEN`；git 加 credential helper（只引用 `${GITHUB_TOKEN}`，不落盘）；`gh release download` 取代裸 `curl`/`tls12-download.exe`。
3. 重试只作兜底，不作为机制。

# 7. 本仓库踩过的坑
- `lukka/run-vcpkg@v11` 默认 `doNotCache: true`，每 run 重新 bootstrap；其 `tls12-download.exe` 30 s 超时 → `error code 1`，无重试。
- Configure 步一旦改用 `shell: bash`，Git Bash `usr/bin/link` 会顶掉 MSVC `link.exe`，frida meson 报 `Found GNU link.exe instead of MSVC link.exe`；修法是把 `$VCToolsInstallDir/bin/Hostx64/x64`（`cygpath -u`）前置到 PATH。
- 只重试 configure，不要重试 `make`（编译错误会被放大成 3 倍耗时）。
