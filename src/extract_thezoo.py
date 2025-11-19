'''
用途：从 TheZoo 仓库中提取 Windows 恶意样本
功能：
1. 遍历 theZoo/malware/Binaries 下的所有文件夹
2. 解压带密码的 zip (密码: infected)
3. 使用 pefile 检查解压后的文件是否为 PE 格式 (Windows 可执行文件)
4. 如果是 PE 文件，移动到 data/unpacked/malicious
5. 如果不是 (如 Linux ELF)，则删除
'''

import os
import zipfile
import pefile
import shutil
import sys

# --- 配置 ---
SOURCE_DIR = "theZoo-master/malware/Binaries"  # TheZoo 样本存放路径
TARGET_DIR = "data/unpacked/malicious"         # 我们的目标仓库
PASSWORD = b"infected"                         # TheZoo 的通用密码

def is_pe_file(file_path):
    """尝试用 pefile 打开，如果成功则是 PE 文件，否则不是"""
    try:
        pe = pefile.PE(file_path)
        pe.close()
        return True
    except pefile.PEFormatError:
        return False
    except Exception:
        return False

def process_thezoo():
    if not os.path.exists(SOURCE_DIR):
        print(f"[X] 错误：找不到源目录 {SOURCE_DIR}")
        return

    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    print(f"--- 开始从 {SOURCE_DIR} 提取样本 ---")
    
    count_success = 0
    count_skipped = 0
    count_failed = 0

    # 遍历所有子目录
    for root, dirs, files in os.walk(SOURCE_DIR):
        for file in files:
            if file.endswith(".zip"):
                zip_path = os.path.join(root, file)
                
                try:
                    # 1. 解压 Zip
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        # 获取压缩包里的文件名
                        for member in zf.namelist():
                            # 解压到当前文件夹 (临时)
                            zf.extract(member, path=root, pwd=PASSWORD)
                            extracted_file_path = os.path.join(root, member)
                            
                            # 2. 检查是否为 PE 文件
                            if is_pe_file(extracted_file_path):
                                # 3. 为了防止重名，我们加上父文件夹的名字
                                malware_name = os.path.basename(root)
                                new_filename = f"{malware_name}_{member}"
                                target_path = os.path.join(TARGET_DIR, new_filename)
                                
                                # 移动到我们的数据仓库
                                shutil.move(extracted_file_path, target_path)
                                # print(f"  [√] 提取成功: {new_filename}")
                                count_success += 1
                            else:
                                # 不是 PE 文件 (如 Linux 病毒)，删除
                                os.remove(extracted_file_path)
                                count_skipped += 1
                                
                except Exception as e:
                    # print(f"  [!] 处理 {file} 失败: {e}")
                    count_failed += 1
        
        # 简易进度条
        sys.stdout.write(f"\r  已提取: {count_success} | 跳过(非PE): {count_skipped} | 解压失败: {count_failed}")
        sys.stdout.flush()

    print("\n" + "="*50)
    print(f"处理完成！")
    print(f"成功提取 Windows 样本: {count_success} 个")
    print(f"跳过非 Windows 样本: {count_skipped} 个")
    print(f"样本已保存到: {TARGET_DIR}")

if __name__ == "__main__":
    process_thezoo()
