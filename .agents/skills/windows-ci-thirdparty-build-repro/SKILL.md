---
name: windows-ci-thirdparty-build-repro
description: Diagnose and locally reproduce Windows-only GitHub Actions build failures (frida-gum/3rd-party) in DontStarveLuaJIT2; use when CI compile is red but local build is green.
---

# Why this exists

DontStarveLuaJIT2's Windows CI (`compile (windows-2022, ...)`) builds third-party
sources from scratch that a developer machine never rebuilds, so CI-only
failures are the norm after a `3rd/**` submodule bump. The local build being
green proves nothing.

# 1. Get the real error (annotations are not enough)

```bash
gh run list --limit 5
gh run view <run-id> --log-failed        # full failing-step log; needs `repo`+`workflow` scope
gh run view <run-id> --json status,conclusion,jobs --jq '.status, (.jobs[]|"\(.name)::\(.conclusion)")'
gh api repos/<owner>/<repo>/actions/jobs/<job-id> --jq '.steps[]|"\(.number) \(.conclusion) \(.name)"'
```

* The check-run annotations (`/check-runs/<id>/annotations`) only carry the
  CMake `FATAL_ERROR` line; the linker/compiler diagnostics are in `--log-failed`.
* The GCM-issued token from `git credential fill` returns 403 on
  `actions/jobs/<id>/logs`; use `gh` (its own token) instead.

# 2. Reproduce the CI-only frida-gum build locally

CI checks out `3rd/frida-gum-src` at the **gitlink commit** and runs
`tools/setup_frida_gum.py` through `configure.bat`/`make.bat` (meson, ~90 s on a
runner). Locally the same script short-circuits on
`3rd/frida-gum/{win64,frida-gum-build}` — so reproduce in a throwaway worktree of
the submodule at the pinned commit:

```bash
# native Windows path! "/c/..." gets rewritten to "C:/c/..."
git -C 3rd/frida-gum-src worktree add --detach "C:/Users/<u>/AppData/Local/Temp/fg/fg" <gitlink-sha>
cd <worktree> && git submodule update --init --recursive --depth 1     # fetches releng (meson)
```

Drive it the way `configure.bat` does, from a **batch file** (msys quoting
mangles `cmd.exe /c "... && ..."`):

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
set PYTHONUTF8=0        rem otherwise locale.getpreferredencoding()='utf-8' and cl.exe's CP936
                        rem error text throws UnicodeDecodeError inside frida's releng
cd /d <worktree>
python drive.py         rem sys.argv=['configure','.','--prefix=...','--with-devkits=gum','--disable-tests']
cmd /c make.bat         rem then: cmd /c make.bat install
```

`drive.py` = `sys.path.insert(0,'.'); from releng.meson_configure import main; main()` inside
`try/except: traceback.print_exc()` — frida's wrappers print bare `str(e)`, so the
traceback is the only way to see where it died.

Artifacts land in `<worktree>/build/gum/devkit/{frida-gum.lib,frida-gum.h}`; the
amalgamated header is what our C++ TUs include, and its line numbers match CI.

# 3. Things that bite

| Symptom | Cause |
|---|---|
| `No module named 'pathlib._local'; 'pathlib' is not a package` | worktree configured with python 3.13 but `make.bat` hardcodes `python` (3.11) — keep one interpreter for configure and make |
| `UnicodeDecodeError: 0xb0` in `detect_linker_flavor` / `mkdevkit` | Chinese-locale `cl.exe` output decoded as UTF-8; set `PYTHONUTF8=0` |
| `error LNK2001` list of `gum_darwin_*` | a hand-maintained `.def` vs. new upstream export set |
| `error C3829: attribute [[noreturn]] may only be applied to a function declaration` | glib's C++11 `G_NORETURN` expansion + older MSVC; local VS18 14.51 accepts it |

# 4. Verify before pushing

Re-run the exact failing link/compile with the artifact built from the pinned
source, and keep a no-op proof for the pre-existing local archive. Then push —
the `pre-push` hook runs the full ctest suite — and confirm with
`gh run watch <run-id> --exit-status`.
