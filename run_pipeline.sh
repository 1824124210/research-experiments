#!/bin/bash

# [设置] 遇到任何错误立即停止运行
# 这样如果特征提取失败了，就不会继续跑模型训练，防止错误扩大。
set -e

# 定义一些颜色，让输出更好看 (可选)
GREEN='\033[0;32m'
NC='\033[0m' # No Color (清除颜色)

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   🚀 开始运行恶意软件检测流水线 (Pipeline)   ${NC}"
echo -e "${GREEN}==============================================${NC}"

# --- 1. 定义配置变量 (Configuration) ---
# 以后如果你改了文件夹名字，只需要改这里，不用去改下面的命令
BENIGN_DIR="data/raw/benign"
MALICIOUS_DIR="data/unpacked/malicious"
FEATURES_FILE="data/processed/features.csv"
MODEL_FILE="results/rf_model.pkl"

# --- 2. 运行特征提取 (Feature Extraction) ---
echo ""
echo -e "${GREEN}[Step 1/2] 正在提取特征...${NC}"
echo "良性样本: $BENIGN_DIR"
echo "恶意样本: $MALICIOUS_DIR"
echo "输出路径: $FEATURES_FILE"

# 调用 src/extract_features.py 并传入参数
# 注意：我们使用绝对路径来保证脚本无论在哪里运行都能找到文件
python src/extract_features.py \
    --benign "$BENIGN_DIR" \
    --malicious "$MALICIOUS_DIR" \
    --output "$FEATURES_FILE"

# --- 3. 运行模型训练 (Model Training) ---
echo ""
echo -e "${GREEN}[Step 2/2] 正在训练模型...${NC}"
echo "输入数据: $FEATURES_FILE"
echo "模型保存: $MODEL_FILE"

# 调用 src/train_model.py 并传入参数
python src/train_model.py \
    --input "$FEATURES_FILE" \
    --save-model "$MODEL_FILE"

echo ""
echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   ✅ 流水线运行成功！任务已完成。            ${NC}"
echo -e "${GREEN}==============================================${NC}"
