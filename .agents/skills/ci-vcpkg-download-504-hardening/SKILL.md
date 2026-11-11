---
name: ci-vcpkg-download-504-hardening
description: GitHub Actions 因 codeload/github 504 在下载类步骤失败：公开 API 定位失败步与缓存实况，按 VCPKG_DOWNLOADS / frida-gum stage / 自建 vcpkg bootstrap 加固，并识别缓存冻结陷阱
---

## 适用
GitHub Actions 因 `codeload.github.com` / `github.com` 504（或 5xx、无输出直接 exit 1）在**下载类步骤**失败：vcpkg port 源码、frida-gum 的 meson subproject、run-vcpkg bootstrap。非下载类失败（编译错误、断言）不适用。

## 1. 无 gh / 无 actions:read 时定位失败步
```bash
curl -sS "https://api.github.com/repos/<o>/<r>/actions/jobs/<job_id>"        # steps 的结论+起止时间
curl -sS "https://api.github.com/repos/<o>/<r>/check-runs/<job_id>/annotations" # 唯一错误文本
curl -sS "https://api.github.com/repos/<o>/<r>/actions/caches?per_page=30"      # 公开可读！key/大小/最后访问
```
时长本身就是证据：35 s 失败 ⇒ 早退（下载 5xx / bootstrap），而不是"变慢"。日志正文 `/actions/jobs/<id>/logs` 需 admin，403 时不要再试 token，直接请用户贴日志。

## 2. 两类 504 源（DontStarveLuaJIT2 实测）
| 源 | 触发点 | 加固 |
|---|---|---|
| vcpkg port 源码 | `cmake --preset` → manifest install | job env `VCPKG_DOWNLOADS=<ws>/.vcpkg-downloads` + actions/cache；configure 3 次重试（重试只补缺失 tarball） |
| frida-gum meson subproject | `tools/setup_frida_gum.py` 的 `configure.bat` | 缓存 `3rd/frida-gum`(stage, 含 `version-<v>.txt` marker) + `3rd/frida-gum-build/input`(静态库+合并头)，key 精确绑 `git -C 3rd/frida-gum-src rev-parse HEAD`；命中后 CMake 走 `--skip-meson`，不进 meson 不联网。注意 key 必须精确（CMake 只要看到 input 就 `--skip-meson`，旧版本会被误用） |
| run-vcpkg bootstrap/install | `lukka/run-vcpkg@v11` | 该 action 无重试、只报 `error code '1'`；改为自己 `bootstrap-vcpkg`（3 次重试 + 缓存 `vcpkg/vcpkg.exe`/`vcpkg/downloads`，key 绑 vcpkg submodule sha），install 归一到带重试的 configure 步 |

## 3. 验证 vcpkg 环境变量真的生效
```bash
VCPKG_DOWNLOADS=<tmp> vcpkg install zlib --triplet x64-windows --x-install-root <tmp>/inst
# 期望: 下载的 cmake/7zip/zlib 等落进 <tmp>，而不是 vcpkg/downloads
```

## 4. 缓存冻结陷阱（很容易误判成"缓存被淘汰"）
`actions/cache/restore` + `save` 两段式里若 `if: cache-hit != 'true'`，**已存在的 key 永不更新**，缓存冻结在第一次快照。用 `/actions/caches` 看大小即可判定：本项目 Windows 二进制缓存只有 45 MiB（而 1 次全量应达 GB 级）⇒ 从未更新，于是每个 run 从源码重装全部 port。要增长必须用唯一 key（如追加 `run_id`）+ `restore-keys` 前缀。

## 5. 逃生舱
仓库变量 `VCPKG_ASSET_SOURCES`（`x-azurl,<url>,`）导出为 `X_VCPKG_ASSET_SOURCES`；未设置保持原生 GitHub 源。frida 的 `[wrap-git]` 没有镜像机制，只能靠缓存 + 重试。
