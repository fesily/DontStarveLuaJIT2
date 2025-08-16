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

# Move files
echo "[INFO] Moving files..."
cp -r "$source"/* "$destination/"

# Check the result of the operation
if [ $? -eq 0 ]; then
    echo "[INFO] Files moved successfully"
else
    echo "[ERROR] An error occurred while moving files"
    exit 1
fi

cd "$destination"

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
