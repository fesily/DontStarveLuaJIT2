
import os
import platform
import subprocess
import argparse
import pathlib

# argparse解析一个arg参数,获得root_dir目录, debug标志位
def parse_arg():
    parser = argparse.ArgumentParser(description='Process some integers.')

    # 添加参数
    parser.add_argument('--root_dir', type=str, help='the root directory', default=pathlib.Path(os.curdir).joinpath('src/lua51').as_posix())
    parser.add_argument('--debug', type=bool, default=False, help='debug mode')
    parser.add_argument('--platform', type=str, default=platform.system(), help='platform type, windows, linux, darwin, etc.')
    args = parser.parse_args()
    return args.root_dir, args.debug, args.platform

def get_shell_sh(platform_system):
    shell = ''
    sh = ''
    # is windows or posix
    if platform.system() == 'Windows':
        shell = 'cmd /c'
        if platform_system == 'Windows':
            sh = 'build_lua51.bat'
        elif platform_system == 'Linux' or platform_system == 'Darwin':
            sh = 'build_lua51_by_docker.sh' + " " + platform_system
        else:
            assert False, 'Unknown platform'
        return shell, sh

root_dir, debug, platform_system = parse_arg()
shell, sh = get_shell_sh(platform_system)

subprocess.call(str.join(' ', [shell, sh]), cwd=root_dir, shell=True)