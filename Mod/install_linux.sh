#!/bin/bash

# List of processes to check
processes=("dontstarve_steam_x64" "dontstarve_dedicated_server_nullrenderer_x64")

# Terminate running processes
for process in "${processes[@]}"; do
    pid=$(pgrep -f "$process")
    if [ -n "$pid" ]; then
        echo "[INFO] Terminating process: $process (PID: $pid)"
        kill -INT "$pid"
        sleep 1 # Wait for the process to fully terminate
    fi
done

# Set path variables
source="bin64/linux"
current_dir=$(pwd)
mod_plugins="${current_dir}/plugins"
mod_bin64="${current_dir}/bin64"
mod_deps="${current_dir}/deps"

if echo "$current_dir" | grep -q "workshop/content/322330"; then
    destination="../../../../common/Don't Starve Together/bin64"
else
    destination="../../bin64"
fi

# Verify if the source directory exists
if [ ! -d "$source" ]; then
    echo "[ERROR] Source directory does not exist: $source"
    exit 1
fi

# Create the destination directory if it doesn't exist
if [ ! -d "$destination" ]; then
    echo "[ERROR] Destination directory does not exist: $destination"
    exit 1
fi

abs_path() {
    # Prefer realpath; fall back to readlink -f; last resort: cd+pwd
    if command -v realpath >/dev/null 2>&1; then
        realpath "$1"
    elif command -v readlink >/dev/null 2>&1 && readlink -f / >/dev/null 2>&1; then
        readlink -f "$1"
    else
        local dir base
        dir=$(cd "$(dirname "$1")" && pwd) || return 1
        base=$(basename "$1")
        printf '%s/%s\n' "$dir" "$base"
    fi
}

uninstall() {
    # Only remove game stub + marker; leave mod bin64/plugins/deps alone
    echo "[INFO] removing injector shell from $destination ..."
    rm -f "$destination/lib64/libInjector.so"
    rm -f "$destination/../data/unsafedata/ds_luajit_injector.path"
    echo "[INFO] removing success"
    exit 0
}

if [ "${1:-}" = "uninstall" ]; then
    uninstall
fi

# 1) Shell: stub into game bin64/lib64 (LD_PRELOAD path)
echo "[INFO] install shell -> $destination/lib64"
mkdir -p "$destination/lib64"
if [ -f "$source/lib64/libInjector.so" ]; then
    cp -a "$source/lib64/libInjector.so" "$destination/lib64/libInjector.so"
elif [ -f "$source/stub/libInjector.so" ]; then
    # legacy/alternate package layout
    cp -a "$source/stub/libInjector.so" "$destination/lib64/libInjector.so"
elif [ -f "$source/shell/libInjector.so" ]; then
    # macOS-style package layout (if reused)
    cp -a "$source/shell/libInjector.so" "$destination/lib64/libInjector.so"
else
    echo "[WARN] no stub libInjector.so under $source/lib64 (or stub/shell)"
fi
if [ $? -ne 0 ]; then
    echo "[ERROR] install shell failed"
    exit 1
fi

# 2) Real Injector into mod bin64
echo "[INFO] install Injector -> $mod_bin64"
mkdir -p "$mod_bin64"
if [ -f "$source/libInjector.so" ]; then
    cp -a "$source/libInjector.so" "$mod_bin64/libInjector.so"
    if [ $? -ne 0 ]; then
        echo "[ERROR] install libInjector.so failed"
        exit 1
    fi
else
    echo "[WARN] no real libInjector.so at $source/libInjector.so"
fi

# 3) Business plugins stay under the mod directory
if [ -d "$source/plugins" ]; then
    echo "[INFO] install plugins -> $mod_plugins"
    mkdir -p "$mod_plugins"
    cp -a "$source/plugins"/. "$mod_plugins"/
    if [ $? -ne 0 ]; then
        echo "[ERROR] install plugins failed"
        exit 1
    fi
else
    echo "[INFO] no package plugins tree at $source/plugins — skip mod plugins copy"
fi

# 4) Runtime deps stay under the mod directory
if [ -d "$source/deps" ]; then
    echo "[INFO] install deps -> $mod_deps"
    mkdir -p "$mod_deps"
    cp -a "$source/deps"/. "$mod_deps"/
    if [ $? -ne 0 ]; then
        echo "[ERROR] install deps failed"
        exit 1
    fi
else
    echo "[INFO] no package deps tree at $source/deps — skip mod deps copy"
fi

# 5) Marker: game data/unsafedata/ds_luajit_injector.path -> absolute mod Injector path
marker_dir="$destination/../data/unsafedata"
mkdir -p "$marker_dir"
if [ -f "$mod_bin64/libInjector.so" ]; then
    abs_path "$mod_bin64/libInjector.so" > "$marker_dir/ds_luajit_injector.path"
    if [ $? -ne 0 ]; then
        echo "[ERROR] write marker failed"
        exit 1
    fi
    echo "[INFO] wrote marker -> $marker_dir/ds_luajit_injector.path"
else
    echo "[WARN] skip marker: $mod_bin64/libInjector.so missing"
fi

# Launcher rewrite UNCHANGED: LD_PRELOAD=./lib64/libInjector.so (stub)
cd "$destination" || exit 1

if [ -f dontstarve_steam_x64 ] && [ $(stat -c%s dontstarve_steam_x64) -gt 1048576 ]; then
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

if [ -f dontstarve_dedicated_server_nullrenderer_x64 ] && [ $(stat -c%s dontstarve_dedicated_server_nullrenderer_x64) -gt 1048576 ]; then
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
exit 0
