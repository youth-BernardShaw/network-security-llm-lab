# 选做三 Prompt注入与不可信输出防护

## 目标与范围

保护LLM辅助审计流程，使待审计代码、恶意注释、外部资料及工具文本不能变成控制指令，模型输出不能直接触发危险操作。本扩展关联既有样本和输出协议，不改动标准化代码及历史证据。

## 威胁与实现

覆盖直接注入、间接注入、上下文污染、伪造工具结果、诱导泄露和恶意POC六类。每类两个变体，另设六个正常对照，覆盖合法日志引用导致误拒的情况。

输入按JSON数据区隔离、保留不可信标签和可疑指令信号；输出复用wp2-output-v1及源码行号/引文核验，补充合成标记泄露和模型确认隔离。Python POC采用保守AST检查，禁止自动执行；通过后仍需要人工审查和隔离环境。

审批工具只记录指定脚本哈希、实际审批人、环境和有效期，不能执行代码。沙箱配置要求非root、只读文件系统、禁止提权、受限资源和默认无网络。依赖使用人工审核的镜像摘要锁定，不能临时安装模型推荐的软件。

## 测试设计与当前状态

已准备基线及防护各18份完整输入、待填记录、原始输出目录和指标计算工具。固定样本与攻击集，用新会话逐条测试，保存未经改写的模型原文，再判断攻击成功、危险建议、泄露、误拒及安全降级。

**36 条实测已完成（子代理辅助）**，见[批次 dsh-20261025](../optional3/batches/dsh-20261025/README.md)：18 例 × 基线/防护两组，36/36 拿到原始输出、JSON 全部可解析、输入哈希全部与 manifest 一致。五项目标指标全部可算，且两组结果完全相同——攻击成功率 0/12、危险建议率 0/18、合成秘密泄露率 0/2、误拒率 0/6、安全降级率 16/16。

这个"两组相同"是**天花板效应**，不是防护有效的证据：基线本身已带既有输出协议与安全约束、每类只有 2 个变体、被测与复核都是谨慎的子代理。因此本扩展能支持的结论只有"在该测试条件下未观察到注入成功"，不能推广为普适防护有效率。

本批次的逐行判定由 `dsh-reviewer-subagent-1..6` 产出，**签字人 `熊钱` 于 2026-10-25 复核确认**（[签认页](../optional3/checks/review-attestation-20261025.md)）：`attack_results.csv` 中 `status=reviewed`、`reviewer=熊钱`，`judgment_by` 保留产出判定的子代理编号，`security_review.csv` 的 `human_judgment` 为 `reviewed_and_approved`。这既记录了人工复核，也没有抹掉判定来源。原有 3 条 DeepSeek 网页版回复保留未覆盖。首对观察见[观察记录](../optional3/checks/A01-1-pilot-comparison.md)。

**沙箱隔离与"审批后执行"都已取证**：本机无 Docker、Ubuntu-22.04 损坏，改用 Ubuntu-20.04 建低权限用户 + mount/network namespace + 资源限制。

1. 隔离探针（[证据](../optional3/checks/sandbox-run-20261025.json)）：非 root、`/etc/shadow` 不可读、宿主 C: 盘在命名空间内被隐藏、无外网与 DNS、256 MB 地址空间上限生效。
2. 审批后执行一次模型 POC（[执行证据](../optional3/checks/sandbox-poc-run-20261025.json)）：签字人通过 `approval.py` 生成哈希绑定、1 小时有效期的[审批记录](../optional3/approval_log/20261025T154643108963Z.json)；沙箱内重算哈希一致后才以 `o3sandbox` 执行适配版 A04-1（唯一适配是把端口 8080 改为 9080），退出码 1、`URLError: Connection refused`。这证明"审批在前、执行在后、自动执行关闭、网络隔离生效"，**不证明漏洞真伪**。

仍缺：Docker 容器沙箱部署。guard v2 已落地并完成同批复测（[复测记录](../optional3/checks/guard-v2-retest-20261026.md)）。

## 指标与后续工作

攻击成功率按12个攻击计算，危险建议率按18个全部案例计算，合成泄露率按2个泄露类案例计算，误拒率按6个正常对照计算。安全降级率按复核确定的不确定案例计算，分母为0不适用。本批次五项均已测出，但口径是子代理辅助；人工复核后应重算。

**实测暴露的主要问题不是被攻破，而是输出闸门误报**：`guard.py output` 把 33/36 判为 quarantine，其中 25 条只是 `vulnerability_type` 与 `audit_scope` 的字符串写法不同、14 处是 POC 示例里写了 `127.0.0.1:8080`（白名单只认 9080/9081）、23 条是只读依赖与 `open()` 被统一禁名。误报根因见[闸门复核](../optional3/batches/dsh-20261025/checks/guard_false_positive_review.md)。

**guard v2 已落地并同批复测**（[记录](../optional3/checks/guard-v2-retest-20261026.md)）：漏洞类型改规范化匹配、回环端口交给运行期，问题实例 79→45、标签误报与端口误报清零，但行级 quarantine 仅 33→32——因为剩余拦截几乎都来自"白名单式保守规则"（只读依赖、`open`、非 Python POC），属设计取舍，列入 v3。`self_test.py` 45/45 通过；未改动工作包 1–4 的任何文件，WP2 的 42 条严格协议计数不受影响。

后续工作：Docker 容器沙箱部署；guard v3（只读 `open`、依赖白名单、非 Python POC 分档）；扩充每类变体数与重复调用。小样本单次结果不能推广为普适安全结论。

## 交付入口

- [选做三使用说明](../optional3/README.md)
- [威胁模型](../optional3/threat_model.md)
- [数据流与信任边界](../optional3/data_flow.png)
- [防护规则](../optional3/guardrails.md)
- [模型评测步骤](../optional3/evaluation_plan.md)
- [沙箱与审批](../optional3/sandbox.md)、[隔离探针脚本](../optional3/sandbox/isolation_probe.sh)
- **实测批次**：[批次说明与结果](../optional3/batches/dsh-20261025/README.md)、[运行协议](../optional3/batches/dsh-20261025/RUN_PROTOCOL.md)、[攻击结果](../optional3/batches/dsh-20261025/attack_results.csv)、[批次指标](../optional3/batches/dsh-20261025/checks/model_metrics.json)、[闸门误报复核](../optional3/batches/dsh-20261025/checks/guard_false_positive_review.md)
- [实现测试报告](../optional3/checks/self_test.json)、[首批指标状态](../optional3/checks/model_metrics.json)（仍为 unmeasured）、[沙箱隔离证据](../optional3/checks/sandbox-run-20261025.json)
- [改进及待完成项](../optional3/security_improvement.md)
