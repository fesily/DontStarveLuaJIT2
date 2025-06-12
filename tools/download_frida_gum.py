import platform
import os
import urllib.request
import tarfile
import argparse

output_dir = "3rd/frida-gum/"
version = "17.1.0"
file_fmt = "%s-%s.tar.xz"
url_fmt = "https://github.com/frida/frida/releases/download/%s/frida-gum-devkit-%s"

all_os = [
    "macos-x86_64",
    "windows-x86_64",
    "linux-x86_64",
]

def download(url, output, dir):
    # 下载文件
    urllib.request.urlretrieve(url, output)
    # 解压文件
    with tarfile.open(output, 'r:xz') as tar:
        tar.extractall(dir)


def get_platform():
    if platform.system() == "Darwin":
        return "macos"
    elif platform.system() == "Windows":
        return "windows"
    elif platform.system() == "Linux":
        return "linux"
    else:
        raise ValueError("Unsupported platform: %s" % platform.system())


def map_target_dir(target:str):
    if target == "macos-x86_64":
        return "osx"
    if target == "windows-x86_64":
        return "win64"
    if target == "linux-x86_64":
        return "linux64"
    
    raise ValueError(f"Unknown target: {target}")
        
def download_target(target: str, force: bool = False):
    file = file_fmt % (version, target)
    url = url_fmt % (version, file)
    file = os.path.join(output_dir, file)
    target_dir = os.path.join(output_dir, map_target_dir(target))
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    target_file = os.path.join(target_dir, f"version-{version}.txt")
    if os.path.exists(target_file):
        print("use cached ", target_file)

            
    print(url, file)
    download(url, file, target_dir)
    with open(target_file, 'w') as f:
        f.write(version)
    
if __name__ == "__main__":
    ## args
    ## --force,-f # 强制下载
    ## --version,-v # 指定版本
    ## --target,-t # 指定目标平台
    parser = argparse.ArgumentParser(description="Download Frida Gum Devkit")
    parser.add_argument("-f", "--force", action="store_true", help="Force download")
    parser.add_argument("-v", "--version", type=str, default=version, help="Specify Frida Gum version")
    parser.add_argument("-t", "--target", type=str, default=None, help="Specify target platform")
    parser.add_argument("--os", type=str, choices=["macos", "windows", "linux"], help="Specify OS type")
    args = parser.parse_args()
    
    if args.target:
        targets = [args.target]
    else:
        targets = [os for os in all_os if os.startswith(args.os or get_platform())]

    if args.version:
        version = args.version

    for index, target in enumerate(targets):
        print(f"[{index+1}/{len(targets)}] Downloading Frida Gum for {target}...")
        download_target(target=target)