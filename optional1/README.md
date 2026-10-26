# 选做1 多版本 Prompt 效果对比

基于完成版主体项目整理的历史横向评测：14个父样本，三版主比较42份响应，另保留42份中间版本响应。复算、图表和错误分析已提供；40份POC原稿已在固定WSL靶场补测，成功率为v1 13/14、v2 11/13、v3 13/13，逐条证据可追溯。

- [完整报告](report.md) / [浏览器阅读版](report.html)
- [四个必做工作包与本任务的衔接](project_analysis.md)
- [任务要求与验收状态](acceptance.md)
- [实验配置与版本对应](experiment_config.md)
- [指标](metrics.csv)、[逐条标注](labeled_results.csv)、[差值](deltas.csv)、[成本](costs.csv)
- [错误分析](error_analysis.md)
- [复现手册](runbook.md)
- [原稿POC补测交接](poc_followup.md)、[补测结果](followup_poc_results.csv)、[可运行率汇总](followup_poc_metrics.csv)
- [补测环境实录](followup/environment.md)、[清理记录](followup/cleanup.md)

v3明确对应`final-wp4-v2`，不覆盖原项目的`final`。本目录不修改主体样本、Prompt、模型原文或验证证据。重新生成分析不会调用模型或执行脚本。
