import re
import sys

def extract_paths(lua_code):
    # Pattern to match _G followed by one or more ["key"]
    pattern = r'_G(\["[^"]+"\])+'
    matches = re.finditer(pattern, lua_code)
    paths = []
    for match in matches:
        matched_string = match.group(0)
        # Extract keys within [" "]
        keys = re.findall(r'\["([^"]+)"\]', matched_string)
        # Join keys with dots
        path = '.'.join(keys)
        paths.append(path)
    return paths

input_file = 'tests/2847908822/modmain1234.lua'  # 输入文件名
output_file = 'tests/2847908822/modmain1234.lua'  # 输出文件名
if __name__ == "__main__":
    # if len(sys.argv) != 2:
    #     print("Usage: python script.py <lua_file>")
    #     sys.exit(1)
    filename = input_file
    with open(filename, 'r') as f:
        lua_code = f.read()
    paths = extract_paths(lua_code)
    for path in paths:
        print(path)
