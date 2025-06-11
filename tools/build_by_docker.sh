#!/bin/bash

set -x

# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <path_to_Dockerfile> <destination_path>"
    exit 1
fi

DOCKERFILE_PATH=$1
DEST_PATH=$2
IMAGE_NAME="myimage"
CONTAINER_NAME="mycontainer"
MODS_PATH_IN_CONTAINER="/dontstarveluajit2/Mod"

# Remove container with the same name if it exists
docker rm -f $CONTAINER_NAME 2>/dev/null

# Build image
echo "Building Docker image from $DOCKERFILE_PATH"
docker build -t $IMAGE_NAME -f $DOCKERFILE_PATH .
if [ $? -ne 0 ]; then
    echo "Failed to build image"
    exit 1
fi

# Run container
echo "Running container $CONTAINER_NAME"
docker run -d --name $CONTAINER_NAME $IMAGE_NAME bash -c "tail -f /dev/null"
if [ $? -ne 0 ]; then
    echo "Failed to run container"
    exit 1
fi

# Copy Mods folder
echo "Copying Mods folder from container to $DEST_PATH"
docker cp $CONTAINER_NAME:$MODS_PATH_IN_CONTAINER $DEST_PATH
if [ $? -ne 0 ]; then
    echo "Failed to copy Mods folder"
    # Continue to cleanup steps
fi

# Stop and remove container
echo "Stopping and removing container $CONTAINER_NAME"
docker rm -f $CONTAINER_NAME

echo "Script execution completed"
