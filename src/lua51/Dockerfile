# Build environment for the Linux replacement Lua VM shipped in
# Mod/bin64/linux/lib64/:
#   lua51       -> standalone interpreter (ET_EXEC, text based at 0x40000000)
#   liblua51.so -> shared VM library, dlopen'ed by libInjector.so
#
# Toolchain: GCC 9.4.0 from Ubuntu 20.04 -- the exact compiler the Don't Starve
# executables are built with, so the Lua codegen matches the game:
#   $ readelf -p .comment bin64/dontstarve_steam_x64
#   GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
#
# glibc note: Ubuntu 20.04 ships glibc 2.31, the same version as the Steam
# Runtime 3 "sniper" runtime. The produced binaries require at most GLIBC_2.29
# (from libm's exp/log/pow), which is the same requirement as the game binaries
# themselves, so they stay loadable inside the sniper environment.
#
# Usage (cwd = src/lua51):
#   docker build -t build_ds_lua51 .
#   ./build_lua51.sh            # Linux
#   build_lua51_by_docker.bat   # Windows
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        gcc-9 make libreadline-dev libncurses-dev \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/output
COPY Makefile /home/lua51/
COPY ./src /home/lua51/src
WORKDIR /home/lua51

# lua51: standalone interpreter (`make linux`). The historic link flags
# (-Wl,-Ttext-segment=0x40000000) are kept so the image stays at the fixed
# 0x40000000 preferred base used by the tooling that inspects lua51.
RUN make clean \
 && make linux CC=gcc-9 \
 && cp /home/lua51/src/lua /home/output/lua51

# liblua51.so: shared VM library (`make linux_so` -> -DLUA_USE_LINUX -fPIC)
RUN make clean \
 && make linux_so CC=gcc-9 \
 && cp /home/lua51/src/liblua.so /home/output/liblua51.so
