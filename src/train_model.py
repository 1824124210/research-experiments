'''
用途：[Week 2, Day 4 最终版] - 模型训练脚本
功能：
1. 加载特征数据 (features.csv)。
2. 训练冠军模型 (Random Forest)。
3. 评估性能 (准确率, 召回率, 混淆矩阵)。
4. 分析特征重要性 (Feature Importance)。
5. 支持命令行参数 (argparse)，方便自动化流水线调用。
'''

import pandas as pd
import numpy as np
import sys
import os
import argparse
import joblib  # 用于保存模型 (可选)

# [Scikit-Learn]
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

def main():
    # --- 1. 解析命令行参数 ---
    parser = argparse.ArgumentParser(description="恶意软件检测模型训练工具")
    
    # --input: 输入数据路径 (默认: data/processed/features.csv)
    parser.add_argument("--input", default="data/processed/features.csv", help="特征数据CSV文件的路径")
    
    # --save-model: 模型保存路径 (可选)
    parser.add_argument("--save-model", default=None, help="[可选] 训练好的模型保存路径 (例如 results/rf_model.pkl)")
    
    args = parser.parse_args()
    
    FEATURES_FILE = args.input

    # --- 2. 加载数据 ---
    print(f"--- 1. 加载数据: {FEATURES_FILE} ---")
    if not os.path.exists(FEATURES_FILE):
        print(f"[X] 错误: 找不到文件 {FEATURES_FILE}")
        print("    请先运行 extract_features.py 生成数据。")
        sys.exit(1)
        
    try:
        df = pd.read_csv(FEATURES_FILE)
    except Exception as e:
        print(f"[X] 读取 CSV 失败: {e}")
        sys.exit(1)
    
    # --- 3. 数据预处理 ---
    # X: 特征数据 (去掉文件名和标签)
    X = df.drop(columns=['file_name', 'label'])
    # y: 标签 (0 或 1)
    y = df['label']
    
    # 填充缺失值 (fillna)
    X = X.fillna(0)
    
    # 保存特征名字，用于后续分析
    feature_names = X.columns 

    # --- 4. 切分数据 ---
    print("--- 2. 切分训练集/测试集 ---")
    # random_state=42: 保证结果可复现
    # stratify=y: 保证切分后的正负样本比例一致
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    print(f"  训练集: {len(X_train)} 个样本")
    print(f"  测试集: {len(X_test)} 个样本")

    # --- 5. 训练冠军模型 ---
    print("\n--- 3. 训练冠军模型 (Random Forest) ---")
    # n_estimators=100: 使用 100 棵树
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    model.fit(X_train, y_train)
    print("  [√] 训练完成！")
    
    # [可选] 保存模型到文件
    if args.save_model:
        # 确保目录存在
        os.makedirs(os.path.dirname(args.save_model), exist_ok=True)
        joblib.dump(model, args.save_model)
        print(f"  [√] 模型已保存至: {args.save_model}")

    # --- 6. 最终评估 ---
    print("\n--- 4. 最终评估结果 ---")
    y_pred = model.predict(X_test)
    
    print(f"  准确率 (Accuracy): {accuracy_score(y_test, y_pred):.4f}")
    print("\n  分类报告 (Classification Report):")
    print(classification_report(y_test, y_pred))
    
    print("  混淆矩阵 (Confusion Matrix):")
    # 格式: [[真良性, 误报], [漏报, 真恶意]]
    print(confusion_matrix(y_test, y_pred))

    # --- 7. 特征重要性分析 ---
    print("\n" + "="*40)
    print("           特征重要性排行榜")
    print("="*40)
    
    # 获取特征重要性得分
    importances = model.feature_importances_
    
    # 创建表格
    feature_imp_df = pd.DataFrame({
        'Feature': feature_names,
        'Importance': importances
    })
    
    # 按重要性降序排列
    feature_imp_df = feature_imp_df.sort_values(by='Importance', ascending=False)
    
    # 打印排行榜
    print(feature_imp_df.to_string(index=False))
    
    # 自动解读
    if not feature_imp_df.empty:
        top_feature = feature_imp_df.iloc[0]['Feature']
        top_score = feature_imp_df.iloc[0]['Importance']
        print("-" * 40)
        print(f"  [!] 冠军特征: '{top_feature}' (得分: {top_score:.4f})")
        print("="*40)

if __name__ == "__main__":
    main()
