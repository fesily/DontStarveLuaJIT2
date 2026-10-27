import json
import platform as host
import sys
import util.GameVersion as util
import argparse

# Must match SignatureJson::format_version
# (src/DontStarveInjector/plugins/plugin_core_vm/signature_load/SignatureJson.hpp).
FORMAT_VERSION = 2
# Sections are keyed by "<system>-<arch>" (SignatureJson::platform_name()).
PLATFORMS = ("windows-x64", "windows-arm64", "linux-x64", "linux-arm64",
             "macos-x64", "macos-arm64")


def host_platform() -> str:
    machine = host.machine().lower()
    arch = "x64" if machine in ("amd64", "x86_64") else "arm64" if machine in ("arm64", "aarch64") else machine
    system = "windows" if sys.platform.startswith("win") else "macos" if sys.platform == "darwin" else "linux"
    return f"{system}-{arch}"


current_game_version = util.read_version()
argparser = argparse.ArgumentParser()
argparser.add_argument("input")
argparser.add_argument("--output", required=False)
argparser.add_argument("--platform", choices=PLATFORMS, default=host_platform(),
                       help="platform section to write (the IDA dump is per system+arch)")
missfuncs = set()
with open("src/missfunc.txt", "r") as f:
    for line in f:
        line = line.strip()
        missfuncs.add(line)

def generator(input, output, platform):
    base_addr = 0
    max_addr = 0
    signatures_path = input
    funcs = []
    with open(signatures_path) as f:
        first = False
        for line in f:
            if not first:
                first = True
                continue
            values = line.split()
            filename = values[1]
            func = values[2]
            addr = values[3]
            if addr == "N/A":
                continue
            addr = int(addr, 16)
            max_addr = max(addr, max_addr)
            if func == "index2adr":
                base_addr = addr
            if not (
                func.startswith("lua_")
                or func.startswith("luaL_")
                or func.startswith("luaopen_")
            ):
                continue
            if func.endswith("_"):
                continue
            funcs.append((func, addr))

    funcs.sort()

    outputs = dict()
    
    for i in range(len(funcs)):
        func = funcs[i]
        if func[0] in missfuncs:
            continue
        outputs[func[0]] = {'offset':func[1] - base_addr}
    
    document = {
        'format_version': FORMAT_VERSION,
        'platforms': {platform: {'version': int(current_game_version), 'funcs': outputs}},
    }
    with open(output, mode='w+') as f:
        f.write(json.dumps(document))
        
myargs = argparser.parse_args()
if myargs.output is None:
    myargs.output = myargs.input + ".json"
generator(myargs.input, myargs.output, myargs.platform)
