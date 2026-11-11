---
name: local-green-ci-red-triage
description: DontStarveLuaJIT2 本地构建通过但 GitHub Actions 失败时用：先查未入 git 的预构建缓存（frida-gum stage、lua51.dll），再用 CI 同款工具链/命令复现，区分工具链新旧与上游头文件缺陷。
---

# 本地绿 / CI 红 的分诊流程（DontStarveLuaJIT2）

先假设：**CI 编译的输入和本地不是同一个文件**，而不是代码不同。本项目大量第三方依赖是"本机生成物"，不入 git。

## 1. 拿真实失败点

```bash
gh auth status                      # 需要 token 有 repo 权限
gh run list --limit 3
gh run view <run-id> --json status,conclusion,jobs --jq '.jobs[]|"\(.name) :: \(.conclusion)"'
gh run view <run-id> --log-failed > ci_fail.log
```

`actions/jobs/<id>/logs` 用 `curl` 会 401/403（GCM 的 token 不含 actions:read），用 `gh` 才行；annotation 只给 FATAL_ERROR 行，不够定位。

## 2. 列出"CI 现场生成、本地缓存"的输入

已知缓存型输入（`git ls-files` 均返回 0）：

| 路径 | 谁生成 | 本地为何有 |
|---|---|---|
| `3rd/frida-gum/<plat>/` | `tools/setup_frida_gum.py` | 8 月遗留，`is_staged()` 命中即跳过 |
| `3rd/frida-gum-build/` | 同上（`meson-prefix` / `input`） | `--skip-meson` 复用它的 `.lib` + `frida-gum.h` |
| `src/lua51/release/lua51.dll` | `src/lua51/build_lua51.bat` | 见第 5 节（危险品） |
| `3rd/angle/` | `tools/setup_angle.py` | CI 有独立 cache |

确认：`git ls-files 3rd/frida-gum 3rd/frida-gum-build | wc -l` → 0 表示不跟踪。

## 3. 在本地重现「CI 那份输入」

不要信任本地 stage，直接从 pin 的 commit 现场生成（临时 worktree，别污染仓库）：

```bash
cd 3rd/frida-gum-src
git worktree add --detach "C:/Users/fesil/AppData/Local/Temp/fg/fg" <pinned-sha>   # 用 Windows 路径，别用 /c/...
cd <worktree> && git submodule update --init --recursive --depth 1
# configure + make：需要 vcvars64 + PYTHONUTF8=0（见第 5 节）
```

然后用**项目自己的编译命令**（从 `builds/ninja-multi-vcpkg/compile_commands.json` 抄，含 `-std:c++latest`、`-external:I`）编一个失败 TU，把 `-I` 指到新头目录，A/B 对照旧头。这一步能把"工具链问题"和"上游头文件问题"分开。

## 4. 判断是否真的是工具链新旧问题

- 查 CI 实际用的工具链：`grep VCToolsInstallDir: ci_fail.log`，再和本地 `cl.exe` 版本比。
- 如果版本相同却仍失败 → 不是版本问题，是输入/上游缺陷。本次案例：glib 2.90 的 `G_NORETURN` 判定顺序（C++11 分支优先 + `G_CXX_STD_CHECK_VERSION` 走 `_MSVC_LANG`）叠上 `__declspec(dllimport)` → MSVC 14.44/14.51 都报 `C3829`。修法是改写宏为 glib 自己的 MSVC 拼法 `__declspec (noreturn)`，**不是**换 runner。

## 5. 附带的两个已知陷阱

- `Mod/deps/lua51.dll` 是签名训练参照（`DontStarveSignature.cpp` 用它的导出函数体指纹匹配游戏模块）。必须保持 VC9/MSVCR90；`build_lua51.bat` 缺 `H:\vc2008-cli` 时会拒绝构建（只有显式 `LUA51_ALLOW_MODERN_TOOLSET=1` 才强制）。装了 VS2022 版本的表现：游戏启动即 `unresolved Lua functions: lua_setfuncchunkname`。修复：`git checkout -- Mod/deps/lua51.dll` + 删 `src/lua51/release`，再 `cmake --install`。
- 本机是 UTF-8 代码页时，frida 的 releng（`env_generic.detect_linker_flavor`、`mkdevkit`）用 `locale.getpreferredencoding()` 解 `cl.exe` 中文输出 → `UnicodeDecodeError`。设 `PYTHONUTF8=0` 绕过；CI 是 en-US 不命中。

## 6. 验证 → 推送 → 看 CI

```bash
git push origin master      # 触发 .githooks/pre-push：build + 全量 ctest + deploy
gh run watch <new-run-id> --interval 20 --exit-status
gh run view <new-run-id> --json conclusion,jobs --jq '.conclusion, (.jobs[]|"\(.name) :: \(.conclusion)")'
```

pre-push 的 deploy 偶尔 `cmake --install exited 1`（`Permission denied` 拷 `Mod/deps/*.dll`）：是 ctest 遗留专服还在退出时占着文件，进程消失后重跑 install 即可，非阻塞、非回归。
