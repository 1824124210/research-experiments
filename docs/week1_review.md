# Week 1 周回顾

**日期:** 2025-11-15

---

### 1. 本周成功 (Wins)

1.  **环境与数据 (Day 1-4):** 成功搭建了 WSL + Conda + Docker 的完整开发环境，并明确了 `theZoo` 和 `System32` 作为数据源。
2.  **核心产出 (Day 5):** 完美执行了“深度日”，成功编写 `analyze_dataset.py` 和 `extract_features.py`，从原始样本中提取并保存了 `features.csv` 特征文件。
3.  **验证与探索 (Day 6-7):** 使用 PE-bear 交叉验证了脚本的准确性 (完成了 `day6_analysis.md`)，并完成了 LLM 越狱方向的第一次综述阅读 (完成了 `llm_notes.md`)。

### 2. 本周问题 (Problems)

1.  **工具兼容性:** 经典的 `PEView` 工具在 64 位 `calc.exe` 上崩溃，必须换用现代工具 `PE-bear` 才解决。
2.  **WSL 环境问题:** Docker 启动失败，原因是 WSL 后台服务卡死。**解决方法:** `wsl --shutdown`。
3.  **Git 认证:** `git push` 失败，原因是 `ssh-agent` 没有自动加载正确的私钥 (`id_ed25519_...`)。**解决方法:** `eval $(ssh-agent -s)` 和 `ssh-add`。

### 3. 下周目标 (Next Steps)

* **核心目标:** Week 2 - 最小可行系统 (MVP)。
* **周一 (W2D1) 任务:**
    * 扩展特征列表（目标 10-15 个）。
    * 动手实现 3 个新特征（如字符串密度、节区名称统计等）。
