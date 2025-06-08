#!/bin/bash
set -x

# Docker镜像的名称
image_name="build_ds_mod"

# 构建Docker镜像
docker build -t $image_name .

# 运行容器
container_id=$(docker run -d $image_name)

# 复制目录
docker cp $container_id:/dontstarveluajit2/Mod .

# 停止并删除容器
docker stop $container_id
docker rm $container_id

echo "Directory copied successfully."