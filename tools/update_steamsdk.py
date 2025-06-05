import subprocess
import os
import shutil

def clone_extract_and_delete(repo_url, branch, folder_path, new_name):
    # 构建临时目录名
    temp_dir = "temp_clone"
    
    # 克隆仓库到临时目录
    clone_command = f"git clone --depth 1 -b {branch} {repo_url} {temp_dir}"
    subprocess.run(clone_command, shell=True, check=True)
    
    # 构建源文件夹路径
    source_folder = os.path.join(temp_dir, folder_path)
    
    # 复制文件夹到新位置
    if os.path.exists(source_folder):
        shutil.copytree(source_folder, new_name)
    else:
        raise FileNotFoundError(f"文件夹 {folder_path} 不存在于仓库中。")
    
    # 删除临时目录
    shutil.rmtree(temp_dir)

# 示例用法
repo_url = "https://github.com/Detanup01/gbe_fork.git"
branch = "dev"  # 假设分支为 main，请根据实际分支调整
folder_path = "sdk/steam"
new_name = "3rd/steam_sdk"
if os.path.exists(new_name):
    shutil.rmtree(new_name)  # 删除已存在的文件夹
clone_extract_and_delete(repo_url, branch, folder_path, new_name)