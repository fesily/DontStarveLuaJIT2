import json
import util.GameVersion as util
import argparse

current_game_version = util.read_version()
argparser = argparse.ArgumentParser()
argparser.add_argument("input")
argparser.add_argument("--output", required=False)
missfuncs = set()
with open("src/missfunc.txt", "r") as f:
    for line in f:
        line = line.strip()
        missfuncs.add(line)

def generator(input, output):
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
    
    with open(output, mode='w+') as f:
        f.write(json.dumps({'version': int(current_game_version), 'funcs':outputs}))
        
myargs = argparser.parse_args()
if myargs.output is None:
    myargs.output = myargs.input + ".json"
generator(myargs.input, myargs.output)
