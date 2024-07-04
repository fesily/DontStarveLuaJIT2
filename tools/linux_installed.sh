#!/bin/bash
set -x
# 获取用户输入的路径
read -p "请输入游戏目录路径: " input_path

# 如果 input_path 为空，则设置为默认路径
if [ -z "$input_path" ]; then
  input_path="$script_dir/../../../../common/Don't Starve Together/bin64"
  echo "使用默认路径: $input_path"
fi

# 检查 bin64 文件夹是否存在
if [ -d "$input_path/bin64" ]; then
  echo "$input_path/bin64 文件夹存在"
else
  echo "$input_path/bin64 文件夹不存在 请检查路径是否正确"
  exit 1
fi

# 下载远程路径的 zip 文件
#read -p "请输入远程zip文件的URL: " zip_url
#wget -O /tmp/temp.zip "$zip_url"

# 解压缩到 bin64 文件夹下
#unzip /tmp/temp.zip -d "$input_path/bin64"
cp -rf ./Mod/bin64/linux/* "$input_path/bin64"
# 检查 dontstarve_steam_x64 文件是否存在并且开头是否是 #!/bin/bash
if [ -f "$input_path/bin64/dontstarve_steam_x64" ]; then
  if head -n 1 "$input_path/bin64/dontstarve_steam_x64" | grep -q "^#!/bin/bash"; then
    echo "dontstarve_steam_x64 是一个.sh 文件，不进行重命名和后续步骤"
    exit 0
  fi
fi

# 重命名 dontstarve_steam_x64 文件
mv -f "$input_path/bin64/dontstarve_steam_x64" "$input_path/bin64/dontstarve_steam_x64_1"

# 创建新的 dontstarve_steam_x64 文件
cat <<EOF > "$input_path/bin64/dontstarve_steam_x64"
#!/bin/bash
export LD_LIBRARY_PATH=./lib64
export LD_PRELOAD=./lib64/libInjector.so
./dontstarve_steam_x64_1
EOF

# 赋予可执行权限
chmod +x "$input_path/bin64/dontstarve_steam_x64"

echo "操作完成！"