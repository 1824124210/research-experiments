# 恶意软件静态特征工程列表 (Week 2)

本列表基于 Week 1 的文献综述，将高层概念（如 API、DLLs、Strings、混淆检测）转化为可实现的 `pefile`/`lief` 脚本特征。

## 类别 1：文件头/基础特征
* 目的：描述 PE 文件的基本“骨架”。
1.  `file_size`：文件总大小（字节）。
2.  `machine`：CPU 架构（例如 0x14c = 32位, 0x8664 = 64位）。
3.  `is_exe`：是否为 .exe (基于文件头 Characteristics 字段)。
4.  `is_dll`：是否为 .dll (基于文件头 Characteristics 字段)。
5.  `compile_time`：编译时间戳 (恶意软件常有无效或可疑的时间戳)。

## 类别 2：节区 (Section) 特征
* 目的：识别加壳或加密（高熵是强信号）。
6.  `number_of_sections`：节区总数。
7.  `avg_section_entropy`：所有节区的平均熵。
8.  `max_section_entropy`：所有节区中的最高熵。
9.  `writable_executable_sections_count`：可写+可执行 (W+E) 的节区数量 (恶意软件的经典标志)。

## 类别 3：导入表 (Import) 特征
* 目的：分析程序“打算做什么”。
10. `number_of_imports`：导入的 DLL 数量。
11. `number_of_imported_functions`：导入的函数总数。
12. `suspicious_imports_count`：可疑 API 调用计数 (如 `CreateRemoteThread`, `WriteProcessMemory`, `LoadLibraryA` 等)。

## 类别 4：字符串 (String) 特征
* 目的：衡量文件中的文本数据量。
13. `number_of_strings`：可打印字符串的总数。
14. `avg_string_length`：平均字符串长度。

## 类别 5：安全特性 (Security Features)
* 目的：区分现代良性软件和老式/恶意软件。
15. `aslr_enabled`：是否启用了地址空间布局随机化 (ASLR)。
16. `dep_enabled`：是否启用了数据执行保护 (DEP)。
