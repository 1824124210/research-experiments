# Week 1 Day 6 - 静态分析实操笔记

**日期:** 2025-11-15

**目标:** 使用 GUI 工具 (PE-bear) 手动解剖一个良性样本，交叉验证 Day 5 Python 脚本 (`extract_features.py`) 提取特征的准确性。

**工具:** PE-bear v0.7.1
**样本:** `C:\Windows\System32\calc.exe`
**参考数据:** `features.csv` 中 `calc.exe` 的记录。

---

## 验证结论

通过在 PE-bear 中手动查找，`calc.exe` 的关键PE结构特征与 Python 脚本的提取结果**完全一致**。

这证明了 `extract_features.py` 脚本中对 `pefile` 库的调用逻辑是**准确可靠**的。

### 1. 节区数量 (Section Count)

* **脚本提取值 (`features.csv`):** `6`
* **PE-bear 验证:**
    * `NT头` -> `File Header` -> `Sections Count` 字段的值为 `6`。
    * 左侧 `节区` 菜单下也列出了 6 个节区 (`.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc`)。
* **结果:** **一致 ✅**

### 2. 导入表数量 (Import Count)

* **脚本提取值 (`features.csv`):** `7`
    * (注：脚本逻辑 `len(pe.DIRECTORY_ENTRY_IMPORT)` 统计的是依赖的 DLL 文件数量)
* **PE-bear 验证:**
    * 点击 `导入表` 标签页。
    * 列表中显示的 DLL 文件（如 `SHELL32.dll`, `KERNEL32.dll` 等）总数恰好为 `7` 个。
* **结果:** **一致 ✅**

### 3. 熵 (Entropy)
* **脚本提取值 (`features.csv`):** `5.806...` (针对 `.text` 节区)
* **PE-bear 验证:**
    * 点击 `区段` 标签页。
    * 在 `.text` 行，`Entropy` 列显示的值为 `5.806...`。
* **结果:** **一致 ✅**
