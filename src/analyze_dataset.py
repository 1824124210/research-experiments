import os
import pefile
import pandas as pd # 我们 Day 2 已经安装了 pandas

def analyze_directory(directory_path, label):
    """
    遍历一个目录，分析所有 PE 文件，并返回一个信息列表。
    """
    results = []
    
    print(f"\n--- 正在扫描: {directory_path} ---")
    
    # os.walk 会遍历目录下的所有文件和子目录
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            
            try:
                # 1. 获取文件大小 (所有文件都有)
                file_size = os.path.getsize(file_path)
                
                # 2. 尝试用 pefile 解析
                pe = pefile.PE(file_path)
                
                # 3. 如果成功 (是 PE 文件)，提取信息
                section_count = len(pe.sections)
                timestamp = pe.FILE_HEADER.TimeDateStamp
                
                print(f"  [√] PE 文件: {file.ljust(20)} | 大小: {file_size} B | 节区: {section_count}")
                
                results.append({
                    "file_name": file,
                    "label": label,
                    "file_size_b": file_size,
                    "section_count": section_count,
                    "compile_timestamp": timestamp,
                    "error": None
                })
                
            except pefile.PEFormatError:
                # 这不是一个 PE 文件 (或者已损坏)
                print(f"  [!] 非 PE 文件: {file.ljust(20)} | 大小: {file_size} B")
                results.append({
                    "file_name": file,
                    "label": label,
                    "file_size_b": file_size,
                    "section_count": 0,
                    "compile_timestamp": 0,
                    "error": "NotPEFile"
                })
            except Exception as e:
                # 其他错误
                print(f"  [X] 错误: {file} ({e})")
                
    return results

def analyze_malicious_zips(directory_path):
    """
    !!! 警告：只扫描 .zip 压缩包，绝不解压或读取内容 !!!
    只统计我们有多少个恶意样本压缩包。
    """
    zip_files = []
    print(f"\n--- 正在扫描 (仅 .zip): {directory_path} ---")
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.zip'):
                file_path = os.path.join(root, file)
                file_size = os.path.getsize(file_path)
                print(f"  [Zip] 发现压缩包: {file.ljust(18)} | 大小: {file_size} B")
                zip_files.append(file)
                
    return zip_files

if __name__ == "__main__":
    
    # 1. 定义路径
    benign_path = "data/raw/benign"
    malicious_path = "data/raw/malicious"
    
    # 2. 分析良性样本 (标签为 0)
    benign_results = analyze_directory(benign_path, 0)
    
    # 3. 统计恶意样本 (只统计 .zip 包)
    malicious_zips = analyze_malicious_zips(malicious_path)
    
    # 4. 创建 DataFrame 总结良性样本
    # （恶意样本因为没解压，所以不在这里）
    benign_df = pd.DataFrame(benign_results)
    
    print("\n" + "="*50)
    print("           数据集分布统计 (Dataset Statistics)")
    print("="*50)
    
    print(f"良性样本总数 (Benign):   {len(benign_df)}")
    print(f"恶意样本压缩包 (Malicious): {len(malicious_zips)}")
    
    if not benign_df.empty:
        print("\n--- 良性样本详细统计 (Benign Details) ---")
        # 打印 DataFrame (Pandas 表格)
        print(benign_df[['file_name', 'label', 'file_size_b', 'section_count']])
        
        # 打印平均大小
        avg_size = benign_df['file_size_b'].mean()
        print(f"\n良性样本平均大小: {avg_size:.2f} Bytes")
