import sys
import os

def file_to_c_array(input_file, output_file):
    # 读取输入文件的二进制内容
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # 获取文件名（不含扩展名）作为数组名
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    # 替换非法字符（例如 . 或 -）为下划线
    array_name = base_name.replace('.', '_').replace('-', '_')
    
    # 打开输出文件
    with open(output_file, 'w') as f:
        # 写入头文件保护宏
        f.write(f'#ifndef {array_name.upper()}_H\n')
        f.write(f'#define {array_name.upper()}_H\n\n')
        
        # 写入字节数组
        f.write(f'char {array_name}[] = {{\n')
        # 每行最多输出 12 个字节
        for i, byte in enumerate(data):
            if i % 12 == 0:
                f.write('    ')
            f.write(f'0x{byte:02x}')
            if i < len(data) - 1:
                f.write(',')
            if i % 12 == 11 or i == len(data) - 1:
                f.write('\n')
            else:
                f.write(' ')
        f.write('};\n')
        
        # 写入数组长度
        f.write(f'unsigned int {array_name}_len = {len(data)};\n\n')
        
        # 写入头文件保护宏结束
        f.write(f'#endif /* {array_name.upper()}_H */\n')

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <input_file> <output_file>')
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.exists(input_file):
        print(f'Error: Input file "{input_file}" does not exist.')
        sys.exit(1)
    
    file_to_c_array(input_file, output_file)
    print(f'Successfully converted {input_file} to {output_file}')