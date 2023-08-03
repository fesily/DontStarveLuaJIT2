import os
import subprocess
import shutil
import pathlib

cwd = "Karta/src"
Target = "Debug"
Target = "Release"
shell = "python3 karta_analyze_src.py -W -N lua 5.1.4 {}".format(
    pathlib.PurePath(os.getcwd()).joinpath("src", "lua51", Target).as_posix()
)
print(shell)
proc = subprocess.run(
    shell,
    shell=True,
    cwd=cwd,
)
if proc.returncode != 0:
    os._exit(1)

shutil.copy(
    os.path.join(cwd, "lua_5.1.4_windows.json"), os.path.join(cwd, "../configs")
)
