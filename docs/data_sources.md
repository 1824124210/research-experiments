### 恶意软件研究数据源规划 (v0.1)

**目标**：为 Week 1-2 的实验获取一个**小规模**（例如：< 100 个文件）、**安全可控**且**格式正确**（PE 文件）的数据集，用于跑通特征提取与模型训练（Baseline）流程。

---

### 1. 数据来源推荐

#### A. 恶意样本 (Malicious Samples)

* **推荐源**：theZoo (恶意软件样本开源集合)
* **简介**：一个著名的恶意软件样本开源集合。
* **优点**：公开、分类、受密码保护（密码: `infected`）。
* **采集计划**：
    * 访问其 GitHub 页面 (`malwares/Binaries/`)。
    * 手动下载 5-10 个不同类型的小型 .zip 样本。

#### B. 良性样本 (Benign Samples)

* **推荐源**：Windows 系统目录
* **简介**：Windows 操作系统自带的 .exe 和 .dll。
* **优点**：获取成本为零、绝对良性。
* **采集计划**：
    * 从 Windows 主机的 `C:\Windows\System32\` 目录。
    * 复制 10-20 个 .exe 或 .dll（如 `calc.exe`, `notepad.exe`）。

---

### 2. ⚠️ 安全与许可注意事项

1.  **隔离 (Containment)**：
    * **WSL 不是沙箱！** 不要在 WSL 或主机上解压恶意样本。
    * 所有解压和执行操作都应在**隔离的 VM** 中进行。
    * 静态分析（用 `pefile` 读取）风险较低，但也需谨慎。
2.  **处理 (Handling)**：
    * 在 `data/raw/benign` 存放良性文件。
    * 在 `data/raw/malicious` 存放恶意文件的 **.zip** 压缩包。
3.  **许可 (Licensing)**：
    * theZoo 和 Windows 文件均可用于学术和研究目的。
