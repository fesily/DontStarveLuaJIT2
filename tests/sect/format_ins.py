import json

def format_json_from_file(input_file_path, output_file_path, indent=4):
    """
    从输入文件中读取 JSON 数据，格式化为：
    - 第一级数组展开，每个内层数组在新行上并缩进。
    - 第二级数组不展开，保持在同一行。
    然后将格式化后的 JSON 写入输出文件。
    
    :param input_file_path: 输入 JSON 文件的路径
    :param output_file_path: 输出格式化 JSON 文件的路径
    :param indent: 缩进空格数，默认为 4
    :return: None
    """
    try:
        # 从输入文件读取 JSON 字符串
        with open(input_file_path, 'r') as file:
            input_json_str = file.read()
        
        # 解析 JSON 字符串
        data = json.loads(input_json_str)
        
        # 确保输入是数组
        if not isinstance(data, list):
            raise ValueError("JSON 数据必须是数组")
        
        # 构建格式化字符串
        formatted_str = "[\n"
        for i, inner_array in enumerate(data):
            # 确保内层元素是数组
            if not isinstance(inner_array, list):
                raise ValueError("内层元素必须是数组")
            
            # 将内层数组转为紧凑的 JSON 字符串
            inner_str = json.dumps(inner_array)
            
            # 添加缩进和内层数组
            formatted_str += " " * indent + inner_str
            
            # 如果不是最后一个元素，添加逗号
            if i < len(data) - 1:
                formatted_str += ","
            formatted_str += "\n"
        
        formatted_str += "]"
        
        # 将格式化后的 JSON 写入输出文件
        with open(output_file_path, 'w') as file:
            file.write(formatted_str)
        
        print(f"格式化后的 JSON 已写入 {output_file_path}")
    
    except json.JSONDecodeError as e:
        print(f"JSON 解析错误: {e}")
    except ValueError as e:
        print(f"数据错误: {e}")
    except FileNotFoundError:
        print(f"文件未找到: {input_file_path}")

# 示例使用
if __name__ == "__main__":
    # 指定输入和输出文件路径
    input_file = "inss.json"  # 替换为你的输入 JSON 文件路径
    output_file = "inss.json"  # 替换为你的输出文件路径
    
    # 格式化 JSON 并写入文件
    format_json_from_file(input_file, output_file)