import os
import re

MOD_VERSION = os.getenv("MOD_VERSION")
assert MOD_VERSION is not None, "MOD_VERSION is not set"
with open("Mod/modinfo.lua", "r+", encoding="utf-8") as modinfo:
    info = modinfo.read()
    info = re.sub(r"version \= \"\d+\.\d+\.\d+\"\n", f"version = \"{MOD_VERSION}\"\n", info)
    modinfo.seek(0)
    modinfo.write(info)
    modinfo.truncate()
