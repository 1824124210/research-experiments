import pefile
import lief
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

print("【成功】所有库已成功导入！")

# 简单的随机森林训练演示（验证 sklearn 正常）
X = np.array([[0,1],[1,0],[1,1],[0,0]])
y = np.array([0,1,1,0])
clf = RandomForestClassifier()
clf.fit(X, y)

print("【模型预测正常】预测结果：", clf.predict([[1,1]])[0])

