'''
用途：[Week 2, Day 3 任务 2]
模型擂台赛：对比 RandomForest, SVM, 和 GradientBoosting 在恶意软件检测上的性能。
这份代码展示了如何在一个脚本中训练多个模型，并科学地对比它们的结果。
'''

# --- 1. 库导入区 ---
import pandas as pd  # 用于处理数据表格 (CSV)
import numpy as np  # 用于数学运算 (虽然这里用得不多，但通常是标配)
import sys  # 用于系统操作 (如退出程序 sys.exit)

# [scikit-learn 库] - 机器学习的核心工具箱
from sklearn.model_selection import train_test_split  # 用于把数据切分成“训练集”和“测试集”
from sklearn.preprocessing import StandardScaler  # [新知识] 用于“数据标准化” (解释见下文)

# [模型库] - 我们的三位“选手”
from sklearn.ensemble import RandomForestClassifier  # 选手 1: 随机森林 (老朋友)
from sklearn.ensemble import GradientBoostingClassifier  # 选手 2: 梯度提升树 (更精准，但更慢)
from sklearn.svm import SVC  # 选手 3: 支持向量机 (擅长找边界)

# [评估库] - 用于给模型打分
from sklearn.metrics import accuracy_score, classification_report, f1_score, recall_score

# --- 配置区 ---
FEATURES_FILE = "features.csv"  # 我们要读取的数据文件


# --- 辅助函数：训练并评估单个模型 ---
def evaluate_model(name, model, X_train, X_test, y_train, y_test):
    """
    这是一个通用的函数，不管你传进来什么模型 (RF, SVM, GBDT)，
    它都会负责训练它，然后并在测试集上跑分。
    """
    print(f"\n--- 正在训练: {name} ---")

    # 1. 训练 (Fit)
    # 就像让学生做练习册，模型在这里学习数据中的规律
    model.fit(X_train, y_train)

    # 2. 预测 (Predict)
    # 就像让学生参加考试，模型对它从未见过的 X_test 进行预测
    y_pred = model.predict(X_test)

    # 3. 打分 (Score)
    # acc: 总体答对的比例 (如 95/100)
    acc = accuracy_score(y_test, y_pred)

    # recall (召回率): [最重要] 在所有真正的恶意软件中，模型抓住了多少？
    # 也就是：没放跑坏人的能力。
    recall = recall_score(y_test, y_pred)

    # f1: 准确率和召回率的平衡分数 (综合指标)
    f1 = f1_score(y_test, y_pred)

    print(f"  [√] 准确率 (Accuracy): {acc:.4f}")
    print(f"  [√] 召回率 (Recall):   {recall:.4f} (抓住恶意软件的能力)")
    print(f"  [√] F1 分数:           {f1:.4f}")

    # 返回一个字典，方便最后做成排行榜
    return {"Model": name, "Accuracy": acc, "Recall": recall, "F1": f1}


# --- 主程序 ---
def main():
    # --- 1. 加载数据 ---
    print(f"--- 1. 加载数据: {FEATURES_FILE} ---")

    # 检查文件是否存在
    # (pd.io.common.file_exists 是 pandas 内部的一个检查函数，也可以用 os.path.exists)
    try:
        df = pd.read_csv(FEATURES_FILE)
    except FileNotFoundError:
        print(f"[X] 错误: 找不到 {FEATURES_FILE}")
        print("    请先运行 extract_features.py 来生成数据。")
        sys.exit(1)

    # --- 2. 数据预处理 ---
    # X: 特征 (去掉文件名和标签列)
    # y: 标签 (0 或 1)
    X = df.drop(columns=['file_name', 'label'])
    y = df['label']

    # 填充缺失值 (fillna) 防止报错
    X = X.fillna(0)

    # [重点] 数据标准化 (StandardScaler)
    # 为什么要这样做？
    # - 我们的特征范围差异巨大：file_size 可能是 10,000,000，而 entropy 只有 7.5。
    # - 某些模型 (特别是 SVM) 看到大数字会以为它更重要，导致“跑偏”。
    # - StandardScaler 把所有特征都缩放到 0 附近 (均值为0，方差为1)，让大家“公平竞争”。
    print("--- 2. 数据标准化 (Scaling) ---")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)  # 拟合规则并转换数据

    # --- 3. 切分数据 ---
    print("--- 3. 切分训练集/测试集 ---")
    # test_size=0.3: 30% 的数据拿来考试 (测试集)
    # random_state=42: 保证每次运行切分结果都一样 (可复现)
    # stratify=y: [关键] 保证训练集和测试集里“好人/坏人”的比例一致，这对不平衡数据非常重要！
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.3, random_state=42, stratify=y
    )
    print(f"  训练集: {len(X_train)} 个样本, 测试集: {len(X_test)} 个样本")

    # --- 4. 定义选手名单 ---
    # 这是一个列表，里面装着我们要对比的所有模型
    models = [
        # 选手 1: 随机森林 (我们之前的冠军)
        ("Random Forest", RandomForestClassifier(n_estimators=100, random_state=42)),

        # 选手 2: SVM (支持向量机)
        # kernel='rbf': 使用“径向基核函数”，适合非线性分类
        ("SVM (RBF)", SVC(kernel='rbf', random_state=42)),

        # 选手 3: 梯度提升树 (Gradient Boosting)
        # 这是一个非常强大的模型，通常比随机森林更准，但更难调参
        ("Gradient Boosting", GradientBoostingClassifier(random_state=42))
    ]

    # --- 5. 开始擂台赛 ---
    results = []
    for name, model in models:
        # 调用我们上面写的辅助函数
        res = evaluate_model(name, model, X_train, X_test, y_train, y_test)
        results.append(res)

    # --- 6. 总结报告 ---
    print("\n" + "=" * 40)
    print("           最终战绩排行榜")
    print("=" * 40)

    # 用 pandas 把结果列表变成表格，方便查看
    results_df = pd.DataFrame(results)

    # 按 Recall (召回率) 降序排列
    # 因为在安全领域，我们最怕“漏报”，所以 Recall 是最重要的指标
    results_df = results_df.sort_values(by="Recall", ascending=False)

    # 打印表格 (index=False 表示不打印行号)
    print(results_df.to_string(index=False))
    print("=" * 40)


if __name__ == "__main__":
    main()
