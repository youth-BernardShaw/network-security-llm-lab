# 选做1 复算手册

在项目根目录执行下列命令。统计脚本只读历史输入输出、做Python语法编译并生成分析文件，不调用模型、不执行POC、不连接靶场。

## 环境

Python 3.10或更高。核心统计仅使用标准库；图表使用matplotlib，HTML转换使用Markdown。依赖版本见`requirements-analysis.txt`。建议独立虚拟环境：

```powershell
python -m venv .venv-optional1
.\.venv-optional1\Scripts\python.exe -m pip install -r optional1\requirements-analysis.txt
```

## 核对来源与复算

```powershell
.\.venv-optional1\Scripts\python.exe optional1\tools\build_analysis.py --verify-sources
.\.venv-optional1\Scripts\python.exe optional1\tools\build_analysis.py
.\.venv-optional1\Scripts\python.exe optional1\tools\render_report.py
.\.venv-optional1\Scripts\python.exe -m unittest discover -s optional1\tests -v
```

打开`optional1/report.html`阅读排版报告。`report.md`用于合入总报告，`figures/`含PNG与SVG；`metrics.csv`、`deltas.csv`、`costs.csv`可直接导入表格工具。

## 预期检查

- 6个比较组×14父样本=84条，主比较42条。
- 17个审计数据区在所有版本一致；84条历史输入包哈希与各原始脚本的算法一致。
- 严格协议通过数：v1=5、v2=8、v3=14、historical-final=4、wp4-baseline-final=5、wp4-intermediate=4。
- 主比较分类均为TP12、FP0、FN0、TN2、U0。
- 三版生成POC为14、13、13，共40份；40份原稿均已实测，成功37份（v1 13、v2 11、v3 13）。历史台账 `poc_execution.csv` 仍保持 `not_run`，补测结果另存 `followup_poc_results.csv`。

历史有协议失败是实验结果，不能通过修改原始输出让它“全通过”。`checks/rebuild_checks.json`的pass只表示复算和完整性检查通过，不代表原始84份响应全合规，更不代表选做1全部实验要求满足。

## POC 补测复现

补测在 WSL2 固定靶场执行，环境见 `followup/environment.md`。POC 源码不改，仅通过既有 CLI 参数配置本地 URL、会话与专用账号：

```powershell
python optional1\followup\tools\run_batch.py
python optional1\followup\tools\browser_batch.py
python optional1\followup\tools\build_followup_results.py
python optional1\tools\summarize_poc_followup.py optional1\followup_poc_results.csv
```

`run_batch.py` 会重置专用账号与留言；XSS 的浏览器证据必须在 `browser_batch.py` 中单独生成，不能只看 HTTP 反射。逐条证据在 `followup/evidence/`，清理记录在 `followup/cleanup.md`。

## 原始数据变更保护

首次复算生成`checks/source_manifest.json`。后续运行先校验源文件哈希，源变化即停止，不默默覆盖冻结结果。若确需引入新实验，应另建分析目录或明确的新批次与清单。

三版逐包输入、原始输出和抽取代码是可再生副本；不要在那里手工修正模型结果。新实测写入独立文件，格式见`poc_followup.md`。
