#!/bin/bash

# DontStarveLuaJIT2 shell installer (Linux x64).
#
# Sole job: install the injection shell - the stub libInjector.so into the
# game's bin64/lib64 plus the LD_PRELOAD launchers. The rest of the package -
# libInjector.so, plugins/, deps/, signatures_*.json - is shipped in place by
# the release package. This script never stages, migrates or deletes mod files,
# and never writes into the game data dir (the shell writes its own resolution
# marker once it finds the mod).

# Needs bash (arrays + `local`); re-exec instead of dying with a dash syntax
# error when started as `sh install_linux.sh`.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

# List of processes to check
processes=("dontstarve_steam_x64" "dontstarve_dedicated_server_nullrenderer_x64")

# Terminate running processes
for process in "${processes[@]}"; do
    pid=$(pgrep -f "$process" 2>/dev/null)
    if [ -n "$pid" ]; then
        echo "[INFO] Terminating process: $process (PID: $pid)"
        kill -INT "$pid"
        sleep 1 # Wait for the process to fully terminate
    fi
done

# The script's own folder decides source/destination; the caller's cwd is
# irrelevant (logical pwd keeps a symlinked mod folder path intact).
script_dir=$(cd -- "$(dirname -- "$0")" && pwd) || exit 1
source="$script_dir/bin64/linux"

if echo "$script_dir" | grep -q "workshop/content/322330"; then
    destination="$script_dir/../../../../common/Don't Starve Together/bin64"
else
    destination="$script_dir/../../bin64"
fi

# Verify if the source directory exists
if [ ! -d "$source" ]; then
    echo "[ERROR] Source directory does not exist: $source"
    exit 1
fi

# Verify if the destination directory exists
if [ ! -d "$destination" ]; then
    echo "[ERROR] Destination directory does not exist: $destination"
    exit 1
fi
# Absolute: the launcher rewrite and the check paths must not depend on the
# current directory anymore.
destination=$(cd "$destination" && pwd) || exit 1

# Boot-log location the loader writes (see docs/plugin-system.md).
game_root=$(dirname "$destination")
boot_log_file="$game_root/data/unsafedata/ds_luajit_boot.log"

# Static post-install check: the shell the installer owns, the real module the
# package ships, and unresolved dependencies.
static_check() {
    local stub="$destination/lib64/libInjector.so"
    local real="$script_dir/libInjector.so"
    local fail=0

    echo "[CHECK] shell : $stub"
    if [ -f "$stub" ]; then
        echo "[CHECK]         ok ($(stat -c%s "$stub" 2>/dev/null || echo '?') bytes)"
    else
        echo "[CHECK]         MISSING"
        fail=1
    fi

    echo "[CHECK] module: $real"
    if [ -f "$real" ]; then
        echo "[CHECK]         ok ($(stat -c%s "$real" 2>/dev/null || echo '?') bytes)"
    else
        echo "[CHECK]         MISSING"
        fail=1
    fi

    if [ -f "$real" ] && command -v ldd >/dev/null 2>&1; then
        # Mirror the launcher env: libsteam_api.so comes from the game's lib64.
        local ldd_out
        ldd_out=$(LD_LIBRARY_PATH="$destination/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ldd "$real" 2>&1)
        local unresolved
        unresolved=$(printf '%s\n' "$ldd_out" | grep -c "not found")
        if [ "$unresolved" = "0" ]; then
            echo "[CHECK] ldd  : all dependencies resolved"
        else
            echo "[CHECK] ldd  : $unresolved unresolved line(s):"
            printf '%s\n' "$ldd_out" | grep "not found" | sed 's/^/[CHECK]         /'
            if printf '%s\n' "$ldd_out" | grep -q "GLIBC_2"; then
                echo "[CHECK]         hint: this distro is too old for the shipped binaries"
            fi
            fail=1
        fi
    fi
    return $fail
}

# Live probe: load the stub (and through it the real module) in a throwaway
# process. Opt-in (`install_linux.sh selftest`) because it runs the injector's
# boot path outside the game; DS_LUAJIT_FORCE_NO_CORE_VM=1 keeps it light.
live_probe() {
    local stub="$destination/lib64/libInjector.so"
    if [ ! -f "$stub" ]; then
        echo "[SELFTEST] stub missing; run the installer first"
        return 1
    fi

    # Probe binary inside the game's bin64, so the stub derives the real game
    # root (marker / mods scan) exactly like an actual launch would.
    local probe="$destination/.ds_luajit_selftest_probe"
    local probe_src="/bin/true"
    [ -x "$probe_src" ] || probe_src="/bin/echo"
    if ! cp -f "$probe_src" "$probe"; then
        echo "[SELFTEST] cannot stage a probe binary in $destination"
        return 1
    fi
    chmod +x "$probe"

    echo "[SELFTEST] loading the stub through a throwaway process ..."
    local out
    out=$(DS_LUAJIT_FORCE_NO_CORE_VM=1 \
          LD_LIBRARY_PATH="$destination/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
          LD_PRELOAD="$stub" \
          "$probe" 2>&1)
    rm -f "$probe"
    printf '%s\n' "$out" | sed 's/^/[SELFTEST] /'

    echo "[SELFTEST] boot log: $boot_log_file"
    if [ -f "$boot_log_file" ]; then
        sed 's/^/[SELFTEST]   /' "$boot_log_file"
    fi
    if printf '%s\n' "$out" | grep -q "stub: HookStartupEntry OK"; then
        echo "[SELFTEST] OK: stub -> real module -> HookStartupEntry"
        return 0
    fi
    echo "[SELFTEST] FAILED: stub could not load the real module (see above / boot log)"
    return 1
}

uninstall() {
    # Remove the game stub + the legacy marker, and undo the launcher rewrite
    # so the game starts again without the shell.
    echo "[INFO] removing injector shell from $destination ..."
    rm -f "$destination/lib64/libInjector.so"
    rm -f "$game_root/data/unsafedata/ds_luajit_injector.path"
    for bin in dontstarve_steam_x64 dontstarve_dedicated_server_nullrenderer_x64; do
        if [ -f "$destination/${bin}_1" ]; then
            mv -f "$destination/${bin}_1" "$destination/$bin" && echo "[INFO] restored original $bin"
        fi
    done
    echo "[INFO] removing success"
    exit 0
}

if [ "${1:-}" = "uninstall" ]; then
    uninstall
fi

if [ "${1:-}" = "selftest" ]; then
    static_check || true
    live_probe
    exit $?
fi

# 1) Shell: stub into game bin64/lib64 (LD_PRELOAD path) - the only artifact
#    this script installs.
echo "[INFO] install shell -> $destination/lib64"
mkdir -p "$destination/lib64"
shell_src=""
if [ -f "$source/lib64/libInjector.so" ]; then
    shell_src="$source/lib64/libInjector.so"
elif [ -f "$source/stub/libInjector.so" ]; then
    # legacy/alternate package layout
    shell_src="$source/stub/libInjector.so"
elif [ -f "$source/shell/libInjector.so" ]; then
    # macOS-style package layout (if reused)
    shell_src="$source/shell/libInjector.so"
fi
if [ -z "$shell_src" ]; then
    echo "[ERROR] inject shell missing: no stub libInjector.so under $source/lib64 (or stub/shell)"
    exit 1
fi
if [ -f "$destination/lib64/libInjector.so" ] && cmp -s "$shell_src" "$destination/lib64/libInjector.so"; then
    echo "[INFO] shell already up to date."
else
    cp -a "$shell_src" "$destination/lib64/libInjector.so"
    if [ $? -ne 0 ]; then
        echo "[ERROR] install shell failed"
        exit 1
    fi
fi

# 2) Launchers: LD_PRELOAD=./lib64/libInjector.so (stub). The real binaries are
#    kept as *_1, so a second run sees the small wrapper and skips.
cd "$destination" || exit 1

if [ -f dontstarve_steam_x64 ] && [ "$(stat -c%s dontstarve_steam_x64)" -gt 1048576 ]; then
    mv dontstarve_steam_x64 dontstarve_steam_x64_1

    cat > dontstarve_steam_x64 <<'EOF'
#!/bin/bash
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so
./dontstarve_steam_x64_1
EOF

    chmod +x dontstarve_steam_x64
    echo "rewrite dontstarve_steam_x64 success"
else
    echo "skip rewrite dontstarve_steam_x64."
fi

if [ -f dontstarve_dedicated_server_nullrenderer_x64 ] && [ "$(stat -c%s dontstarve_dedicated_server_nullrenderer_x64)" -gt 1048576 ]; then
    mv dontstarve_dedicated_server_nullrenderer_x64 dontstarve_dedicated_server_nullrenderer_x64_1

    cat > dontstarve_dedicated_server_nullrenderer_x64 <<'EOF'
#!/bin/bash
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so
./dontstarve_dedicated_server_nullrenderer_x64_1 "$@"
EOF

    chmod +x dontstarve_dedicated_server_nullrenderer_x64
    echo "rewrite dontstarve_dedicated_server_nullrenderer_x64 success"
else
    echo "skip rewrite dontstarve_dedicated_server_nullrenderer_x64."
fi

echo "[INFO] Operation completed successfully"
echo
static_check && echo "[CHECK] install OK" || echo "[CHECK] problems found (see above)"
echo "[INFO] If luajit still does not take effect, read: $boot_log_file"
echo "[INFO] Re-check any time: ./install_linux.sh selftest   Uninstall: ./install_linux.sh uninstall"
exit 0
