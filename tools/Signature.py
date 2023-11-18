import os
import json

GameDir = os.getenv("GAME_DIR")
current_game_version = 0
try:
    with open(f"{GameDir}/version.txt","r") as fp:
        current_game_version = fp.readline().strip()
except FileNotFoundError:
    pass

missfuncs = set()
with open("src/missfunc.txt", "r") as f:
    for line in f:
        line = line.strip()
        missfuncs.add(line)

def generator(name):
    base_addr = 0
    max_addr = 0
    signatures_path = f"src/signatures_{name}.txt"
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
        outputs[func[0]] = func[1] - base_addr
    
    with open(f'Mod/bin64/windows/signatures_{name}', mode='w+') as f:
        f.write(json.dumps({'version': int(current_game_version), 'funcs':outputs}))

generator("client")
generator("server")