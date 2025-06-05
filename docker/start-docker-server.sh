#!/bin/bash

# Set default values if variables are not already set
ROOT_CONFIG_DIR=${ROOT_CONFIG_DIR:="$HOME/.klei/DoNotStarveTogether/DSTWhalesCluster"}
ROOT_GAME_DIR=${ROOT_GAME_DIR:="$HOME/server_dst"}
SHARD_NAME=${SHARD_NAME:="Master"}
# Check if the directory /workspaces/dontstarveluajit2 exists
if [ -d "/workspaces/dontstarveluajit2" ]; then
  mkdir -p $ROOT_CONFIG_DIR
  cp -rvf $PWD/docker/DSTClusterConfig/* $ROOT_CONFIG_DIR
  mkdir -p $ROOT_GAME_DIR/mods/luajit2
  cp -rvf $PWD/Mod/* $ROOT_GAME_DIR/mods/luajit2
fi

echo "Using config directory: $ROOT_CONFIG_DIR"
echo "Using game directory: $ROOT_GAME_DIR"
echo "Using shard name: $SHARD_NAME"  

# Check for game updates before each start (manual restart may be needed if outdated)
# Copy dedicated_server_mods_setup.lua if it exists
ds_mods_setup="$ROOT_CONFIG_DIR/mods/dedicated_server_mods_setup.lua"
if [ -f "$ds_mods_setup" ]; then
  cp -vf "$ds_mods_setup" "$ROOT_GAME_DIR/mods/"
fi

# Copy modoverrides.lua to Master and Caves directories if it exists
modoverrides="$ROOT_CONFIG_DIR/mods/modoverrides.lua"
if [ -f "$modoverrides" ]; then
  cp "$modoverrides" "$ROOT_CONFIG_DIR/Master/"
  cp "$modoverrides" "$ROOT_CONFIG_DIR/Caves/"
fi

# Change to the game directory and start the server
cd "$ROOT_GAME_DIR/bin64"
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so
echo "Starting Don't Starve Together dedicated server with LD_LIBRARY_PATH=$LD_LIBRARY_PATH and LD_PRELOAD=$LD_PRELOAD"
./dontstarve_dedicated_server_nullrenderer_x64 -console -cluster DSTWhalesCluster -shard "$SHARD_NAME"