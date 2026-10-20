# 选做1 要求与交付对照

本表区分已交付的复算成果与尚未取得的实验记录。主体项目完成不代表所有选做指标已测；本包也不以空白模板冒充实测完成。

“可交付完成”与“严格验收完成”的两级判定、逐条完成标志见 [报告第 7 节](report.md#7-完成标志)。本表只列逐项状态。

| 任务书要求 | 对应材料 | 状态 |
| --- | --- | --- |
| 至少三版全文及改动可追溯 | prompts/v1.md、v2.md、v3.md，input_manifest.csv，report.md | 已完成 |
| 使用主体实测反馈最终版 | v3对应final-wp4-v2；源change_requests保留 | 已完成，但含同集调优污染 |
| 同批样本与代码 | 14父样本，17数据区哈希校验 | 已完成 |
| 相同模型参数与工具权限 | experiment_config.md记录已知项与历史未知项 | 部分满足，无法追溯核验全部参数 |
| 完整输入输出、运行时间和失败 | raw_inputs、raw_outputs、protocol_failures及源预试验 | 输入输出已保留，历史运行器包装及耗时缺失 |
| 人工金标准与版本盲评 | ground_truth.csv及源17条条件证据 | 可复用标签；缺人工版本盲评及预先冻结时间证明 |
| 精确率、召回率、F1 | metrics.csv、labeled_results.csv | 已复算，限历史标签一致性 |
| 按类型报告 | metrics.csv与figures/04_by_type.png | 已完成 |
| POC可运行率 | poc_execution.csv、followup_poc_results.csv、followup/evidence/ | 已完成实测：40/40执行，37成功（v1 13/14、v2 11/13、v3 13/13） |
| 证据完整率 | metrics.csv，字段定义见experiment_config.md | 已完成显式字段口径，语义质量另议 |
| 成本 | costs.csv、figures/03_text_cost.png | 任务记录数和字符量已统计；时延、Token、内部调用数未记录 |
| 代表案例及局限 | error_analysis.md、report.md | 已完成 |
| 核心表格与图表可复现 | tools/、runbook.md、checks/ | 已完成 |

## 完整验收前的剩余工作

1. ~~在固定授权隔离环境执行三版40份原稿~~：已完成（2026-10-20，WSL2 固定靶场）。原稿未改代码，仅用既有CLI参数配置URL、会话与专用账号；逐条命令、耗时、输出、证据与恢复见 `followup_poc_results.csv` 和 `followup/evidence/`。
2. 原始历史耗时不能补造。如课程要求严格记录单次运行时间和同参控制，应另开固定参数的模型批次，并保存时延与用量。补测的POC耗时是脚本执行耗时，不是模型生成耗时。
3. 由课程成员完成代表案例与标签的独立复核，记录实际复核人、日期与依据。历史“先冻结再盲评”无法事后倒签；新批次应在运行前冻结。本包中的 `reviewer` 为自动执行者，不替代人工复核。

以上条件满足前，本包可作为选做1的历史对比分析与POC补测成果，不能写成所有实验验收项已经通过。
