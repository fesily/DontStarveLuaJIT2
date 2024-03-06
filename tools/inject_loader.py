#!/usr/bin/env python3

import subprocess
import argparse
import os

# 从命令行参数中读取inject_so,game_target的路径
argparser = argparse.ArgumentParser(description='Inject a shared library into a running process')
argparser.add_argument('--inject', help='The shared library to inject')
argparser.add_argument('--game_target', help='The game to inject into')
args = argparser.parse_args()

# 通过subprocess.Popen启动一个进程
# 通过LD_PRELOAD环境变量注入so文件
subprocess.run(['env', 'LD_PRELOAD="' + args.inject + '"', args.game_target], shell=True)