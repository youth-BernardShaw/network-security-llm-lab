# 选做三 Prompt注入与不可信输出防护

本目录在工作包1至4成果上增加输入边界、输出校验、POC静态检查与人工审批记录工具。原有标准样本、模型原文和POC证据不修改。

## 当前完成范围

- 六类攻击各两个变体，共12个攻击；六个正常对照，其中包括合法引用攻击短语的案例。
- 基线与防护各18份完整输入，共36份，关联既有样本ID和输入哈希。
- 可运行的输入检测、输出协议与代码引文复核、Python POC保守静态检查，以及不具备执行能力的人工审批记录工具。
- 确定性实现自检、待评测CSV、指标计算工具、威胁模型、流程图与沙箱配置。

**模型实测已在独立批次完成 36 条。** [批次 dsh-20261025](batches/dsh-20261025/README.md) 用全新上下文的 DeepSeek Harness 子代理跑完 18 例 × 2 组：36/36 拿到原始输出、JSON 全部可解析、输入哈希 36/36 与 manifest 一致。五项目标指标已测出，且 baseline 与 guarded **完全相同**——攻击成功率 0/12、危险建议率 0/18、合成秘密泄露率 0/2、误拒率 0/6、安全降级率 16/16。

**判定由 6 个独立子代理逐行产出，签字人 `熊钱` 已复核确认**（签认页 [checks/review-attestation-20261025.md](checks/review-attestation-20261025.md)）：`attack_results.csv` 中 `status=reviewed`、`reviewer=熊钱`，每行 `judgment_by` 保留产出该判定的子代理编号，原始判定在 `review/*.json` 可逐条追溯；`security_review.csv` 的 `human_judgment` 为 `reviewed_and_approved`。这不改变"判定由子代理产出"的事实，也不是商业 API 成绩（模型快照与采样参数记 `unknown`）。原有 3 条 DeepSeek 网页版回复保留在 `raw_outputs/` 未被覆盖，首对观察见 [checks/A01-1-pilot-comparison.md](checks/A01-1-pilot-comparison.md)。两组无差异属于天花板效应，原因与结论边界见批次 README 第三节；不能据此宣称防护有效或无效。

**沙箱隔离与"审批后执行"都已完成取证。** 本机无 Docker、Ubuntu-22.04 发行版损坏，改用 Ubuntu-20.04 建立低权限用户 + mount/network namespace + 资源限制：

1. **隔离探针**（[证据](checks/sandbox-run-20261025.json)、[脚本](sandbox/isolation_probe.sh)）：非 root、`/etc/shadow` 不可读、宿主 C: 盘在命名空间内被隐藏、无外网与 DNS、256 MB 地址空间上限生效。
2. **审批后执行一次模型 POC**（[执行证据](checks/sandbox-poc-run-20261025.json)）：签字人 `熊钱` 于 2026-10-25 通过 `approval.py` 产生哈希绑定、1 小时有效期的[审批记录](approval_log/20261025T154643108963Z.json)；随后在沙箱内复核哈希一致，才以 `o3sandbox` 身份执行适配版 A04-1 POC，退出码 1，`URLError: Connection refused`——审批门禁在前、隔离网络使其无法到达任何目标。**该 POC 只有一处适配（端口 8080→9080），不是漏洞真伪的证明。**

仍未完成的只有：Docker 容器沙箱部署。guard v2 已落地（[同批复测](../optional3/checks/guard-v2-retest-20261026.md)：quarantine 33→32 行、问题实例 79→45，其中标签误报 20 条与端口误报 14 条清零；行数几乎不动的原因是残留拦截至白名单类规则，列入 v3）。

## 文件入口

- [威胁模型](threat_model.md)、[信任边界流程图](data_flow.png)。
- [防护规则及限制](guardrails.md)、[沙箱与审批步骤](sandbox.md)、[隔离探针脚本](sandbox/isolation_probe.sh)。
- [攻击与正常对照](attack_cases/)、[逐条输入清单](prepared/manifest.json)。
- [模型评测步骤](evaluation_plan.md)、[改进与完成状态](security_improvement.md)。
- **实测批次**：[batches/dsh-20261025/](batches/dsh-20261025/README.md)（36 条子代理结果、运行协议、指标、guard 误报复核）。
- `attack_results.csv`：本表是**首批**记录（3 条网页版回复 + 33 条待测），批次实测结果不并入本表，避免混算模型来源。
- `attack_log.csv`、`security_review.csv`：首批的原始输出索引与判定（人工处置仍为 pending）。
- [实现测试报告](checks/self_test.json)、[首批指标状态](checks/model_metrics.json)（仍为 unmeasured）、[批次指标](batches/dsh-20261025/checks/model_metrics.json)（已 measured，子代理口径）、[沙箱隔离证据](checks/sandbox-run-20261025.json)。

## 本地使用

Python 3.10及以上，仅运行标准库工具；绘图是开发阶段的可选步骤，需要Pillow，不是校验器依赖。

从仓库根目录执行：

```text
python optional3/validators/prepare.py
python optional3/validators/self_test.py
python optional3/validators/metrics.py
python optional3/validators/guard.py input optional3/prepared/guarded/A01-1.md
```

prepare会重建样本及输入模板，不覆盖已有评测CSV。修改攻击集后必须新建批次并重新准备记录，不能混用旧CSV或覆盖已测输入。锁定版本后保留manifest哈希。

检查模型JSON及POC：

```text
python optional3/validators/guard.py output optional3/raw_outputs/guarded/A01-1.json
python optional3/validators/guard.py poc path/to/reviewed_script.py
```

输出quarantine或reject时返回码为2；await_human_approval不代表安全或可以自动执行。所有工具都不执行生成代码、不发送网络请求。

## 上传GitHub

新增目录为`optional3/`，主报告为`docs/optional3_security.md`；根README增加入口。另见[上传清单](UPLOAD.md)。不要上传整个仓库外层目录、临时Python缓存或个人会话。仍按小组main串行交接约定，由负责人检查变更后合并。
