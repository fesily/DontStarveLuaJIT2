import zipfile
import os
import sys
import pathlib

root_dir = sys.argv[1] or os.getcwd()
dataDir = pathlib.Path(root_dir, "data")
databundleDir =  pathlib.Path(dataDir, "databundles")
scriptsZipPath =  pathlib.Path(databundleDir, "scripts.zip")
targetPath = pathlib.Path(dataDir, "scripts")
os.removedirs(targetPath)

# 创建一个ZipFile对象
with zipfile.ZipFile(scriptsZipPath, 'r') as zip_ref:
    # 解压zip文件到指定目标文件夹
    zip_ref.extractall(targetPath)

os.rename(scriptsZipPath, pathlib.Path(scriptsZipPath, ".bak"))

print("解压完成！")
