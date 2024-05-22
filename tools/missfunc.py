import os

cwd = os.path.join(os.getcwd(), "src")

with open(os.path.join(cwd, "missfunc.txt"), "r") as f:
    outputs = [
        """
#ifndef MISSFUNC_H
#define MISSFUNC_H 1
#include <unordered_set>
#include <string_view>
using namespace std::string_view_literals;

auto& get_missfuncs() {
static std::unordered_set<std::string_view> missfuncs = {
"""
    ]
    for line in f:
        line = line.strip()
        outputs.append('"{}"sv,\n'.format(line))
    outputs += [
        """
        };
return missfuncs;
}
#endif
    """
    ]
    with open(os.path.join(cwd, "missfunc.h"), "w") as w:
        w.writelines(outputs)
