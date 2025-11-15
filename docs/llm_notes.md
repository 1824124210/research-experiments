# LLM 越狱综述笔记

[cite_start]**文献:** 《面向大语言模型的越狱攻击与防御综述》(梁思源) [cite: 1]

---

## 宏观理解

### 摘要 (Abstract)
* **作者如何定义越狱攻击?**
    * [cite_start]攻击者精心设计问题（越狱提示），让LLM回答，使其生成意想不到或者有害的内容。 [cite: 3]

### 1. 引言 (Introduction)
* **为什么越狱攻击是一个值得研究的严重问题?**
    * [cite_start]LLM被应用于各个领域，越狱攻击涉及AI安全性和伦理性，还直接影响LLM的可靠应用。 [cite: 4]

### 6. 未来研究方向 (Future Research)
* [cite_start]**作者认为未来的研究方向是什么?** [cite: 5]
    * [cite_start]**攻击上:** 趋于自动化，多模态，跨语种策略 [cite: 6]。
    * [cite_start]**防御上:** 趋于低成本，多阶段及端到端安全策略 [cite: 7]。
    * [cite_start]**理论上:** 对LLM越狱攻击及防御理论研究更深入 [cite: 8]。
    * [cite_start]**平台上:** 建立开源全面的攻防基准体系 [cite: 9]。

---

## [cite_start]核心分类：攻击 (Attacks) [cite: 10]

* [cite_start]**语言语义学攻击:** 攻击者通过精心设计的语言诱导LLM达成恶意目的 [cite: 11]。
    * [cite_start]**单步骤越狱攻击:** 一次交互就可以套出恶意输出 [cite: 12]。
    * [cite_start]**多步骤越狱攻击:** 通过多次交互，用上下文逐渐诱导LLM [cite: 13]。
* [cite_start]**基于优化的对抗攻击:** 使用数学优化技术，通过算法调整对LLM的输入，诱导LLM产生错误的输出 [cite: 14]。
    * [cite_start]**查询攻击:** 攻击者直接与LLM交互，实时探测LLM的弱点进行精确攻击 [cite: 15]。
    * [cite_start]**迁移攻击:** 现在类似的LLM上进行攻击，然后把相同的攻击手法迁移到目标LLM上 [cite: 16]。
* [cite_start]**混合攻击:** 结合人工提示和自动化工具 [cite: 17]。
    * [cite_start]人工提示+优化评估模型安全 [cite: 18]。
    * [cite_start]使用优化方法对人工提示进行扩充 [cite: 19]。

---

## [cite_start]核心分类：防御 (Defenses) [cite: 20]

* [cite_start]**训练阶段防御:** [cite: 21]
    * [cite_start]**核心:** 增强模型本身 [cite: 22]。
    * [cite_start]**对抗数据增强:** 将攻击者的对抗提示喂给LLM [cite: 23]。
    * [cite_start]**模型微调防御:** 对训练好的基础模型进行附加训练 [cite: 24]。
* [cite_start]**推理阶段防御:** [cite: 25]
    * [cite_start]**核心:** 输入/输出拦截 [cite: 26]。
    * [cite_start]**输入预处理防御:** 在LLM查询前，对用户输入进行检测 [cite: 27]。
    * [cite_start]**输出响应分析:** 在LLM生成响应后，对输出进行检查 [cite: 28]。
* [cite_start]**跨阶段防御:** [cite: 29]
    * [cite_start]**核心:** 全生命周期 [cite: 30]。
    * [cite_start]**混合防御:** 融合训练阶段和推理阶段的防御策略 [cite: 31]。
    * [cite_start]**模型对齐防御:** 让人类价值观内化于LLM [cite: 32]。
