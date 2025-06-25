#!/bin/bash

# Set default values if variables are not already set
ROOT_CONFIG_DIR=${ROOT_CONFIG_DIR:="$HOME/.klei/DoNotStarveTogether/DSTWhalesCluster"}
ROOT_GAME_DIR=${ROOT_GAME_DIR:="$HOME/server_dst"}
SHARD_NAME=${SHARD_NAME:="Master"}

# first exec docker/copy_server_config.sh
docker/copy_server_config.sh ROOT_CONFIG_DIR="$ROOT_CONFIG_DIR" ROOT_GAME_DIR="$ROOT_GAME_DIR"

# Change to the game directory and start the server
cd "$ROOT_GAME_DIR/bin64"
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so
echo "Starting Don't Starve Together dedicated server with LD_LIBRARY_PATH=$LD_LIBRARY_PATH and LD_PRELOAD=$LD_PRELOAD"
./dontstarve_dedicated_server_nullrenderer_x64 -console -cluster DSTWhalesCluster -shard "$SHARD_NAME"