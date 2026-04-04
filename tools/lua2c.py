import os
import sys
import zlib


def write_c_bytes(output, data):
    for i, byte in enumerate(data):
        if i % 12 == 0:
            output.write('    ')
        output.write(f'0x{byte:02x}')
        if i < len(data) - 1:
            output.write(',')
        if i % 12 == 11 or i == len(data) - 1:
            output.write('\n')
        else:
            output.write(' ')

def file_to_c_array(input_file, output_file):
    with open(input_file, 'rb') as f:
        data = f.read()

    compressed = zlib.compress(data, level=9)

    base_name = os.path.splitext(os.path.basename(input_file))[0]
    array_name = base_name.replace('.', '_').replace('-', '_')

    with open(output_file, 'w') as f:
        f.write(f'#ifndef {array_name.upper()}_H\n')
        f.write(f'#define {array_name.upper()}_H\n\n')
        f.write(f'static const unsigned char {array_name}[] = {{\n')
        write_c_bytes(f, compressed)
        f.write('};\n')
        f.write(f'static const unsigned int {array_name}_len = {len(compressed)};\n')
        f.write(f'static const unsigned int {array_name}_original_len = {len(data)};\n\n')
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