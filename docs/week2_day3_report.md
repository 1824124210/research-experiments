PE文件静态恶意软件检测器 (PE Static Malware Detector)

🎯 项目简介

这是一个基于机器学习的恶意软件检测项目，专门针对 Windows 可执行文件（Portable Executable, PE）。本项目旨在通过分析 PE 文件的静态特征（如结构信息、节区熵、导入函数等），训练一个高召回率的分类模型（Random Forest），以区分良性程序和恶意软件。

⚙️ 技术栈与环境

环境: WSL2 (Ubuntu) / Python 3.x

主要库: pefile (特征提取), pandas (数据处理), scikit-learn (模型训练)

核心模型: Random Forest Classifier

🚀 快速开始 (如何复现 Baseline)

以下步骤指导你如何从零开始构建数据集并运行最终的冠军模型。

1. 环境准备 (一键安装依赖)

请确保你的 Python 环境 (Conda/Venv) 已激活。

# 创建依赖文件 (我们将在下一步创建这个文件)
# pip install -r requirements.txt


2. 数据准备 (Benign & Malicious)

本项目需要两个数据集：

良性样本 (Label 0): 已通过 Benign-PE-Dataset 仓库获取，存放于 data/raw/benign/。

恶意样本 (Label 1): 已通过 Malware-Database 和 TheZoo 仓库获取，存放于 data/unpacked/malicious/。

3. 特征提取与数据集生成

运行 extract_features.py 脚本以处理所有样本，并将 11 个特征提取到 features.csv 文件中。

python extract_features.py


4. 训练冠军模型与性能评估

运行 train_final.py 脚本。它将自动加载 features.csv，训练 Random Forest 模型，并输出最终的性能报告。

python train_final.py


📈 核心发现与模型原理 (MVP 最终结论)

我们证明了文件结构特征比复杂行为特征更有效。

1. 最终性能 (Random Forest)

指标

性能数值

意义

准确率 (Accuracy)

93.41%

模型总体预测正确的比例。

恶意召回率 (Recall)

89%

关键指标：模型能够正确捕获 89% 的恶意软件。

漏报数 (False Negatives)

18 / 165

在测试集中，只有 18 个恶意样本被错误地放过。

2. 模型决策逻辑 (特征重要性排行榜)

以下是 Random Forest 模型在判断良性/恶意时，最看重的前 5 个特征。

排名

特征 (Feature)

安全意义

重要性得分

1

max_section_entropy (最高节区熵)

加壳/混淆指示器。恶意软件为了隐藏，会使某个节区的数据混乱度极高。

20.71%

2

has_debug (有无调试信息)

反分析指标。良性程序通常包含调试信息，恶意软件为了隐蔽会清除。

13.09%

3

avg_section_entropy (平均节区熵)

文件的整体数据混乱度。

12.69%

4

number_of_sections (节区数量)

PE 文件结构异常的指标。

12.06%

5

file_size (文件大小)

基础物理特征。

10.29%

9

suspicious_import_count (可疑 API 计数)

行为侧写。虽然排名较低，但它确保模型抓住了那些调用高危 API (如注入进程) 的恶意软件。

5.09%

📂 项目文件结构

data/：存放所有原始和处理后的数据。

data/raw/benign/: 原始良性 PE 文件。

data/unpacked/malicious/: 原始恶意 PE 文件。

features.csv: 包含 11 个特征的完整数据集。

extract_features.py: 数据准备脚本。 用于从 PE 文件中提取特征。

train_final.py: 模型训练脚本。 用于训练 Random Forest 并评估性能。

docs/week2_day2_report.md: 详细的实验分析报告。
