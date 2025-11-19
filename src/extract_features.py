'''用途：我们的特征提取脚本。
[Week 2 更新]：扩展特征集，包括节区熵、W+E权限和导入函数总数。
[Week 2 升级]：新增“可疑 API 扫描”、“ASLR 检测”、“调试信息检测”。
'''
import argparse
import os
import pefile
import pandas as pd
import math
import sys

# [配置] 定义“可疑 API”列表 (黑名单)
SUSPICIOUS_FUNCTIONS = {
    # 网络通信类
    'InternetOpen', 'InternetOpenUrl', 'InternetReadFile', 'InternetWriteFile',
    'URLDownloadToFile', 'HttpSendRequest', 'WSAStartup',
    # 进程操作/注入类 (这是重灾区)
    'CreateRemoteThread', 'OpenProcess', 'WriteProcessMemory', 'ReadProcessMemory',
    'VirtualAllocEx', 'SetThreadContext', 'EnumProcesses',
    # 执行/启动类
    'ShellExecute', 'WinExec', 'CreateProcess', 'System',
    # 注册表/持久化类
    'RegOpenKey', 'RegSetValue', 'RegCreateKey',
    # 键盘记录/钩子类
    'SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow',
    # 躲避/反调试类
    'IsDebuggerPresent', 'OutputDebugString', 'Sleep'
}


def calculate_entropy(data):
    """计算一段数据的香农熵"""
    if not data:
        return 0.0
    entropy = 0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    data_len = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        p = float(count) / data_len
        entropy -= p * math.log2(p)
    return entropy


def extract_features(directory_path, label):
    """
    遍历指定目录，从所有 PE 文件中提取特征。
    """
    features_list = []

    # 检查目录是否存在
    if not os.path.exists(directory_path):
        print(f"[!] 警告: 目录不存在 {directory_path}")
        return []

    file_list = [name for name in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, name))]
    file_count = len(file_list)

    print(f"--- 正在提取特征: {directory_path} (共 {file_count} 个文件) ---")

    for i, file in enumerate(file_list):
        file_path = os.path.join(directory_path, file)

        # 打印进度条
        progress = (i + 1) / file_count
        sys.stdout.write(
            f"\r  进度: [{'=' * int(20 * progress):<20}] {i + 1}/{file_count} - {file[:30]}")  # 只显示文件名前30个字符防止刷屏
        sys.stdout.flush()

        try:
            pe = pefile.PE(file_path)

            # --- 1. 基础特征 ---
            file_size = os.path.getsize(file_path)
            number_of_sections = len(pe.sections)

            # --- 2. 节区特征 (熵 & W+E) ---
            section_entropies = []
            writable_executable_sections_count = 0

            for section in pe.sections:
                # 计算熵
                section_data = section.get_data()
                section_entropies.append(calculate_entropy(section_data))

                # 检查 W+E (可写 & 可执行)
                is_executable = section.Characteristics & 0x20000000
                is_writable = section.Characteristics & 0x80000000
                if is_executable and is_writable:
                    writable_executable_sections_count += 1

            if section_entropies:
                avg_section_entropy = sum(section_entropies) / len(section_entropies)
                max_section_entropy = max(section_entropies)
            else:
                avg_section_entropy = 0.0
                max_section_entropy = 0.0

            # --- 3. [升级版] 导入表特征 & 可疑 API 扫描 ---
            number_of_imports = 0
            number_of_imported_functions = 0
            suspicious_import_count = 0  # [新特征]

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                number_of_imports = len(pe.DIRECTORY_ENTRY_IMPORT)
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    # 累加函数总数
                    number_of_imported_functions += len(entry.imports)

                    # [核心] 扫描每一个导入函数
                    for func in entry.imports:
                        if func.name:
                            try:
                                func_name = func.name.decode('utf-8', 'ignore')
                                # 模糊匹配黑名单
                                for susp_func in SUSPICIOUS_FUNCTIONS:
                                    if susp_func.lower() in func_name.lower():
                                        suspicious_import_count += 1
                                        break
                            except Exception:
                                pass

            # --- 4. 导出表特征 ---
            number_of_exports = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                number_of_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

            # --- 5. [新特征] 安全与调试信息 ---
            # ASLR: 0x0040 (DLL_CHARACTERISTICS_DYNAMIC_BASE)
            aslr_enabled = 0
            if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DllCharacteristics'):
                if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
                    aslr_enabled = 1

            # Debug: 是否有调试目录
            has_debug = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                has_debug = 1

            # --- 数据打包 ---
            features_list.append({
                "file_name": file,
                "label": label,

                # 基础
                "file_size": file_size,
                "number_of_sections": number_of_sections,

                # 节区
                "max_section_entropy": max_section_entropy,
                "avg_section_entropy": avg_section_entropy,
                "writable_executable_sections_count": writable_executable_sections_count,

                # 导入/导出 (含可疑API)
                "number_of_imports": number_of_imports,
                "number_of_imported_functions": number_of_imported_functions,
                "suspicious_import_count": suspicious_import_count,
#                "number_of_exports": number_of_exports,

                # 安全与元数据
                "aslr_enabled": aslr_enabled,
                "has_debug": has_debug
            })

        except pefile.PEFormatError:
            pass
        except Exception as e:
            pass  # 忽略单个文件的处理错误，保持进度

    sys.stdout.write("\n")
    return features_list

# --- 4. 主执行区 (命令行入口) ---
if __name__ == "__main__":
    # 1. 初始化参数解析器
    parser = argparse.ArgumentParser(description="PE文件静态特征提取工具")
    
    # 2. 定义我们需要哪些参数
    # required=True 表示这个参数必须填
    # default="..." 表示如果不填，默认用这个
    parser.add_argument("--benign", required=True, help="良性样本目录路径")
    parser.add_argument("--malicious", required=True, help="恶意样本目录路径")
    parser.add_argument("--output", default="data/processed/features.csv", help="输出CSV文件的路径")

    # 3. 解析参数 (把命令行里输入的东西读进来)
    args = parser.parse_args()

    # 4. 获取路径
    benign_path = args.benign
    malicious_path = args.malicious
    output_csv_path = args.output

    # [健壮性] 检查输入目录是否存在
    if not os.path.exists(benign_path):
        print(f"[X] 错误：找不到良性样本目录: {benign_path}")
        sys.exit(1)
    if not os.path.exists(malicious_path):
        print(f"[X] 错误：找不到恶意样本目录: {malicious_path}")
        sys.exit(1)

    # [健壮性] 确保输出目录存在 (如果 data/processed 不存在，自动创建)
    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)

    # 5. 开始提取 (调用上面的函数)
    print(f"--- [步骤 1/2] 正在提取良性样本: {benign_path} ---")
    benign_features = extract_features(benign_path, 0)
    
    print(f"\n--- [步骤 2/2] 正在提取恶意样本: {malicious_path} ---")
    malicious_features = extract_features(malicious_path, 1)

    # 6. 合并
    all_features = benign_features + malicious_features
    
    if not all_features:
        print("\n[X] 错误：没有提取到任何特征。")
        sys.exit(1)

    # 7. 保存结果
    features_df = pd.DataFrame(all_features)
    try:
        features_df.to_csv(output_csv_path, index=False)
        print("\n" + "=" * 50)
        print(f"         特征提取完成！")
        print("=" * 50)
        print(f"数据已保存到: {output_csv_path}")
        print(f"总样本数: {len(features_df)}")
        print(features_df['label'].value_counts())

    except Exception as e:
        print(f"\n[X] 错误：无法保存 CSV 文件。 ({e})")
