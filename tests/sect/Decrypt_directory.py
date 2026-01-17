import os
import subprocess
import shlex
import sys

# 获取当前脚本文件所在的目录
script_dir = os.path.dirname(os.path.abspath(__file__))
# 构建 desect.py 的完整路径
desect_path = os.path.join(script_dir, 'desect.py')
print(f"desect_path: {desect_path}")
def process_lua_files(directory):
    """
    深度遍历指定文件夹，处理所有 .lua 文件。
    
    参数:
        directory (str): 要遍历的文件夹路径
    """
    # 使用 os.walk 递归遍历目录
    for root, dirs, files in os.walk(directory):
        for filename in files:
            # 检查文件是否以 .lua 结尾
            if filename.endswith('.lua'):
                # 构建文件的完整路径
                full_path = os.path.join(root, filename)
                if filename.endswith('modinfo.lua'):
                    continue
                # 检查文件是否以 0.lua 结尾
                if filename.endswith('0.lua'):
                    # 构造新文件名，去掉末尾的 0.lua 中的 0
                    new_filename = filename[:-5] + '.lua'
                    new_full_path = os.path.join(root, new_filename)
                    os.remove(new_full_path)
                    # 重命名文件
                    os.rename(full_path, new_full_path)
                    # 设置要处理的路径为新路径
                    process_path = new_full_path
                else:
                    # 如果不需要重命名，直接使用原路径
                    process_path = full_path

                subprocess.run(['python', desect_path, process_path])


# 示例用法
if __name__ == "__main__":
    directory = sys.argv[1]  # 当前目录，也可以指定其他路径
    process_lua_files(directory)