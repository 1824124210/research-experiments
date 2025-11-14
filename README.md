# research‑experiments\n\n项目简介 …
这是一个用于恶意软件检测研究的实验环境。

---

## 🚀 如何复现 (Quickstart)

本项目在 Windows 10/11 + WSL2 (Ubuntu) + Conda 环境下进行测试。

### 1. 环境准备 (Environment)

1.  确保已安装 WSL2、Docker Desktop 和 Conda (Miniconda)。
2.  进入 WSL 终端。
3.  创建 Conda 环境：
    ```bash
    # (我们之前已经创建了 'research' 环境)
    # conda create -n research python=3.10
    ```

### 2. 激活环境与安装依赖 (Dependencies)

1.  激活 Conda 环境：
    ```bash
    conda activate research
    ```
2.  安装所需库：
    ```bash
    # (我们之前已安装)
    # pip install pefile lief numpy pandas scikit-learn jupyter
    ```

### 3. 运行第一个示例 (Run Example)

本项目包含一个脚本，用于读取 PE 文件（如 .exe）并提取基本信息。

1.  **获取一个测试样本** (例如: `notepad.exe`)：
    ```bash
    # (我们之前已创建了 data 目录)
    mkdir -p data/raw/benign
    
    # (我们之前已复制了样本)
    cp /mnt/c/Windows/System32/notepad.exe data/raw/benign/
    ```

2.  **运行分析脚本**：
    ```bash
    python read_pe_info.py
    ```

3.  **预期输出**：
    ```text
    --- 正在分析: data/raw/benign/notepad.exe ---
    文件大小 (Bytes): ...
    编译时间: ...
    节区数量: ...
    节区名称:
      - .text    ...
      - .rdata   ...
      ...
    ```
