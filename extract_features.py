import os
import pefile
import pandas as pd
import math # 我们需要 math 库来计算熵 (entropy)

def get_entropy(data):
    """计算一段数据的熵"""
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features(directory_path, label):
    """
    遍历目录，从所有 PE 文件中提取特征。
    """
    features_list = []
    
    print(f"--- 正在提取特征: {directory_path} ---")
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            
            try:
                pe = pefile.PE(file_path)
                
                # 特征 1: 文件大小
                file_size = os.path.getsize(file_path)
                
                # 特征 2: 节区数量
                section_count = len(pe.sections)
                
                # 特征 3: 导入表 (Import) 数量
                import_count = 0
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    import_count = len(pe.DIRECTORY_ENTRY_IMPORT)
                
                # 特征 4: 导出表 (Export) 数量
                export_count = 0
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

                # 特征 5: 熵 (我们只计算第一个节区 '.text' 的熵作为示例)
                entropy = 0
                if pe.sections:
                    # 获取第一个节区的数据
                    section_data = pe.sections[0].get_data()
                    entropy = get_entropy(section_data)

                print(f"  [√] 已处理: {file.ljust(20)}")

                features_list.append({
                    "file_name": file,
                    "label": label,
                    "file_size": file_size,
                    "section_count": section_count,
                    "import_count": import_count,
                    "export_count": export_count,
                    "entropy_text_section": entropy
                })
                
            except pefile.PEFormatError:
                print(f"  [!] 跳过 (非 PE 文件): {file}")
            except Exception as e:
                print(f"  [X] 错误: {file} ({e})")
                
    return features_list

if __name__ == "__main__":
    
    # 1. 定义路径
    benign_path = "data/raw/benign"
    # 注意：我们只对良性样本提取特征
    # 因为恶意样本是 .zip 格式，需要沙箱解压，我们 Day 5 不做
    
    # 2. 提取良性样本特征 (标签为 0)
    benign_features = extract_features(benign_path, 0)
    
    # 3. 将特征列表转换为 Pandas DataFrame
    features_df = pd.DataFrame(benign_features)
    
    # 4. 定义 CSV 输出路径
    output_csv_path = "features.csv"
    
    # 5. 保存为 CSV
    try:
        features_df.to_csv(output_csv_path, index=False)
        
        print("\n" + "="*50)
        print(f"         特征提取完成！")
        print("="*50)
        print(f"数据已保存到: {output_csv_path}")
        print(f"总共提取了 {len(features_df)} 个样本。")
        
        print("\n--- 特征预览 (Preview) ---")
        print(features_df.head()) # 打印前 5 行

    except Exception as e:
        print(f"\n[X] 错误：无法保存 CSV 文件。 ({e})")
