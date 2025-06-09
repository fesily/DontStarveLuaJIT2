#!/bin/bash

# 检查是否提供了正确的参数数量
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <path_to_Dockerfile> <destination_path>"
    exit 1
fi

DOCKERFILE_PATH=$1
DEST_PATH=$2
IMAGE_NAME="myimage"
CONTAINER_NAME="mycontainer"
MODS_PATH_IN_CONTAINER="/Mods"

# 如果存在同名容器，先删除
docker rm -f $CONTAINER_NAME 2>/dev/null

# 构建镜像
echo "正在从 $DOCKERFILE_PATH 构建Docker镜像"
docker build -t $IMAGE_NAME $DOCKERFILE_PATH
if [ $? -ne 0 ]; then
    echo "构建镜像失败"
    exit 1
fi

# 运行容器
echo "正在运行容器 $CONTAINER_NAME"
docker run -d --name $CONTAINER_NAME $IMAGE_NAME
if [ $? -ne 0 ]; then
    echo "运行容器失败"
    exit 1
fi

# 拷贝Mods文件夹
echo "正在将Mods文件夹从容器拷贝到 $DEST_PATH"
docker cp $CONTAINER_NAME:$MODS_PATH_IN_CONTAINER $DEST_PATH
if [ $? -ne 0 ]; then
    echo "拷贝Mods文件夹失败"
    # 继续执行清理步骤
fi

# 停止并删除容器
echo "正在停止并删除容器 $CONTAINER_NAME"
docker rm -f $CONTAINER_NAME

echo "脚本执行完成"