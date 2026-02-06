import re
import argparse
import sys

#输入lua源代码文件,折叠所有算数量表达式,并写回到新文件里
#通过正则表达式 替换模式 折叠成常量
# 模式为
# -123+456-1234
# -123 + 456 - 1234
# -123 + 456
# -123 + - 456
# +-41+-22
# +-41+-22+-22+-333
# 73+-73
# 89 + -87

def fold_expression(code):
    pattern = r'(\s*[-+]?\d+\s*[-+]\s*)+[-+]?\d+(\.\d+)?'

    # 定义替换函数
    def replace_expression(match):
        expression = match.group(0)
        try:
            expression = expression.replace('\n', '')  # 去除换行符
            # 计算表达式的值
            result = eval(expression)
            return str(result)
        except Exception as e:
            print(f"Error evaluating expression '{expression}': {e}")
            return expression
    
    # 替换所有匹配的表达式
    folded_code = re.sub(pattern, replace_expression, code)
    
    return folded_code
# 匹配"\076\048\072\098\119\107\099\082\110\107\117\70\072\099\074\106" 这种转换的字符串
# 替换所有转义序列为对应的字符
def fold_escape_sequences(code):
    pattern = r'(\\[0-9]{2,3})'
    
    def replace_escape_sequence(match):
        escape_seq = match.group(0)
        char_code = int(escape_seq[1:])
        return chr(char_code)

    folded_code = re.sub(pattern, replace_escape_sequence, code)
    return folded_code

def fold_file(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        code = f.read()

    folded_code = fold_expression(code)
    folded_code = fold_escape_sequences(folded_code)

    sys.stdout.write(folded_code)
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(folded_code)

if __name__ == "__main__":
    # parse command line arguments for input and output files, output file is optional
    parser = argparse.ArgumentParser(description="Fold expressions in a Lua source code file.")
    parser.add_argument("input_file", help="Path to the input Lua source code file.")
    parser.add_argument("output_file", nargs='?', default=None, help="Path to the output Lua source code file. If not provided, appends '.folded.lua' to the input file name. Use 'stdout' to print to console.")
    args = parser.parse_args()

    input_file = args.input_file
    output_file = args.output_file
    if output_file is None:
        output_file = input_file + ".folded.lua"
    if output_file == "stdout":
        output_file = None

    fold_file(input_file, output_file)
    print(f"Folded expressions from {input_file} and saved to {output_file}.")
    