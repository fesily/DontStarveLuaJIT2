@echo off

REM Docker镜像的名称
set image_name=build_ds_lua51

REM 构建Docker镜像
docker build -t %image_name% .

REM 运行容器
for /f "tokens=*" %%i in ('docker run -d %image_name%') do set container_id=%%i

REM 复制目录
docker cp %container_id%:/home/output/ .

REM 停止并删除容器
docker stop %container_id%
docker rm %container_id%

echo Directory copied successfully.