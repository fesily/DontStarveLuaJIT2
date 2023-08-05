import os
import configparser

base_addr = 0
max_addr = 0
signatures_path = "src/signatures.txt"
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

missfuncs = set()
with open("src/missfunc.txt", "r") as f:
    for line in f:
        line = line.strip()
        missfuncs.add(line)

funcs.sort()
with open("src/signatures.hpp", "w") as f:
    output = [
        "#ifndef SIGNATURES_H\n",
        "#define SIGNATURES_H\n",
        "#include <unordered_map>\n",
        "#include <string_view>\n",
        "using namespace std::string_view_literals;\n",
        "struct Signatures {\n",
        "\tvoid* offset;\n",
        "\tstd::unordered_map<std::string_view, void*> funcs;\n",
        "};\n",
        "static Signatures signatures = {\n",
        f"(void*){max_addr-base_addr},\n",
        "\t{\n",
    ]

    for i in range(len(funcs)):
        func = funcs[i]
        if func in missfuncs:
            continue
        line = '\t{{"{}"sv, (void*){}}},\n'.format(func[0], func[1] - base_addr)
        output.append(line)

    output.append("}};\n#endif\n")
    f.writelines(output)