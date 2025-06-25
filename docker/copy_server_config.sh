#!/bin/bash

# Set default values if variables are not already set
ROOT_CONFIG_DIR=${ROOT_CONFIG_DIR:="$HOME/.klei/DoNotStarveTogether/DSTWhalesCluster"}
ROOT_GAME_DIR=${ROOT_GAME_DIR:="$HOME/server_dst"}
# Check if the directory /workspaces/dontstarveluajit2 exists
if [ -d "/workspaces/dontstarveluajit2" ]; then
  mkdir -p $ROOT_CONFIG_DIR
  cp -rvf $PWD/docker/DSTClusterConfig/* $ROOT_CONFIG_DIR
  mkdir -p $ROOT_GAME_DIR/mods/luajit2
  cp -rvf $PWD/Mod/* $ROOT_GAME_DIR/mods/luajit2
fi


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
