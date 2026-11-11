---
name: dst-ci-github-download-504-triage
description: GitHub Actions Windows job 因 GitHub 下载（vcpkg ports / vcpkg-tool 自举 / frida meson wraps）超时或 504 变红时：用 gh 取日志定位，按三段下载链修，并本地原样验证 workflow run 块
---

# 适用
DontStarveLuaJIT2 的 GitHub Actions（`.github/workflows/release.yaml`）在 Windows job 上因 GitHub 下载失败（504 / `The operation timed out` / `Download failed, halting portfile`）或缓存不生效而红，而本地/ Linux 正常时。

# 1. 拿到真正的失败点（不要猜）
公开 API 只有注解，日志需要权限；本机 `gh` 已登录（repo+workflow scope）：

```bash
gh run list --limit 5 --json databaseId,headSha,status,conclusion
gh api repos/fesily/DontStarveLuaJIT2/actions/runs/<run>/jobs --jq '.jobs[]|{name,conclusion,id}'
gh run view --log --job <job_id> > /tmp/job.log   # 未完成时只有一行提示
```

注解端点（无 token 可读，但**未认证 60 次/小时**，排查时优先 `gh`）：
`/repos/<o>/<r>/check-runs/<job_id>/annotations`——本项目这个 ID 就是 job id。

判据：同一 job 里某步 30~40 s 就失败 → 大概率是无重试的下载超时，而不是编译错误；步骤时间戳差距本身就是证据。

# 2. 该仓库已知的三段下载链（按出现顺序）

| 阶段 | 下载内容 | 失败文本 | 修法（已落地） |
|---|---|---|---|
| vcpkg ports | port 源码（codeload/github） | `Download failed, halting portfile` | `VCPKG_DOWNLOADS=$WS/.vcpkg-downloads` + actions/cache；configure 步 3 次重试 |
| vcpkg tool 自举 | 6.6 MB `vcpkg-tool/releases/download/<tag>/vcpkg.exe` | `Downloading …vcpkg.exe` → `The operation timed out`（`bootstrap.ps1` 的 `tls12-download.exe`，无重试、~30 s 超时） | 自建 bootstrap：按 `vcpkg/scripts/vcpkg-tool-metadata.txt` 的 `VCPKG_TOOL_RELEASE_TAG` 用 `curl -fL --retry 3 --retry-all-errors --max-time 300` 拉取，4 次外层重试 + `vcpkg version` 校验；工具按 vcpkg submodule sha 缓存。**不要再用 `lukka/run-vcpkg`**（`doNotCache: true`，每次 run 重下） |
| frida-gum meson | `[wrap-git]` 共 15 个（glib/libffi/capstone/…）逐个 `git clone` | configure 失败 → `Failed to set up Frida-Gum`（注解里重复 N 次 = CI 重试次数） | ① `setup_frida_gum.py` 只对 **configure** 重试 3 次（`make` 失败是编译错误，不重试）；② CI 预克隆 wraps（每仓库 3 次重试，跳过 v8）；③ 缓存 `3rd/frida-gum` stage + `3rd/frida-gum-build/input`（命中即 `--skip-meson`，完全不联网） |

# 3. 缓存为什么“看起来没用”

`/actions/caches`（未认证可读）看 `size_in_bytes`：本项目 Windows vcpkg 二进制缓存只有 ~45 MiB ⇒ 说明它从第一次快照后**再没更新**——因为保存步骤写成 `if: always() && steps.<id>.outputs.cache-hit != 'true'`，key 已存在时永远不覆盖（缓存冻结）。判断“被淘汰”还是“从未写入”必须看这个接口，不要凭 LRU 猜。

# 4. 本地验证套路（改 CI 必做）

- **原样跑 workflow 里的 `run:` 块**：用 `yaml.safe_load` 取出 step，把 `${{ runner.os }}` 等表达式替换成字面值，交给 `C:\Program Files\Git\bin\bash.exe`（本机 PATH 上的 `bash` 是 WSL，会因路径失败；heredoc 缩进经 YAML 折叠后可直接执行）。
- **`VCPKG_DOWNLOADS` 是否被尊重**：`vcpkg install zlib --triplet x64-windows --x-install-root <tmp>/inst` 且 `VCPKG_DOWNLOADS=<tmp>/dl`，成功后 `<tmp>/dl` 里应出现 `madler-zlib-*.tar.gz` 以及 vcpkg 自举的 cmake/7z。
- **wrap 预克隆**：解析 `3rd/frida-gum-src/subprojects/*.wrap`（全部是 `[wrap-git]`），`git init` + `git fetch --depth 1 origin <sha>` + `checkout FETCH_HEAD`（GitHub 允许取任意 sha），已存在的目录跳过。
- **configure 是否还依赖 `lukka/run-vcpkg`**：`cmake --preset ninja-multi-vcpkg -DCMAKE_OSX_ARCHITECTURES=x86_64` 直接跑，应出现 `-- Running vcpkg install - done` 与 `Frida-Gum: stage marker present; using --skip-meson`。

# 5. 坑

- 提交信息里有反引号时不要用 `git commit -m "…`cmd`…"`（bash 会做命令替换，把内容吃掉）；用 `-F <file>`。
- 免费额度内别用裸 `curl` 轮询 run/job；用 `gh run watch <id> --exit-status`。
- pre-push 钩子会跑全量 ctest + `cmake --install` + 部署到 workshop 目录，每次 push 约 4~7 分钟；连续多次 push 会排队跑多份 CI。
- 仓库 Actions 缓存上限 10 GB：新增缓存（尤其 frida clone 缓存）会挤占，先用 `/actions/caches` 核算再决定。
