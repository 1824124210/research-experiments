import pefile
import sys
import os
from datetime import datetime

def analyze_pe(file_path):
    """
    读取一个 PE 文件并打印基本信息。
    """
    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        return

    try:
        # 1. 加载 PE 文件
        pe = pefile.PE(file_path)

        print(f"--- 正在分析: {file_path} ---")

        # 2. 获取文件大小
        file_size = os.path.getsize(file_path)
        print(f"文件大小 (Bytes): {file_size}")

        # 3. 获取编译时间戳
        timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.fromtimestamp(timestamp)
        print(f"编译时间: {compile_time}")

        # 4. 获取节区 (Sections) 数量
        section_count = len(pe.sections)
        print(f"节区数量: {section_count}")

        # 5. 打印节区名称
        print("节区名称:")
        for section in pe.sections:
            # .ljust(10) 是为了格式化输出，让它对齐
            print(f"  - {section.Name.decode('utf-8').strip().ljust(10)} (大小: {section.SizeOfRawData} bytes)")

    except pefile.PEFormatError as e:
        print(f"Error: '{file_path}' 不是一个有效的 PE 文件。 ({e})")
    except Exception as e:
        print(f"发生了一个错误: {e}")

if __name__ == "__main__":
    # 定义我们要分析的样本路径
    sample_path = "data/raw/benign/notepad.exe"
    
    # 调用分析函数
    analyze_pe(sample_path)
