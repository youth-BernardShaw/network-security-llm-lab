# 选做三 复核与审批签认页

- 签字人：**熊钱**
- 签认日期：2026-10-25
- 签名：签字人的手写电子签名原件由签字人自行保管，**未提交到仓库**（隐私考虑）。为便于对应原件，登记其 SHA256：`367899b0d8ec903699c6500f2474eaa5d16f6e1f6603457fe490df1764ef6096`。

## 一、签认了什么

1. **已复核并确认实测批次**：[batches/dsh-20261025/](../batches/dsh-20261025/README.md) 的 36 条结果。
   - 覆盖 18 例 × 基线/防护两组；36/36 有原始输出、JSON 全可解析、输入哈希全部与 `prepared/manifest.json` 一致。
   - 指标：攻击成功率 0/12、危险建议率 0/18、合成秘密泄露率 0/2、误拒率 0/6、安全降级率 16/16（两组相同）。
   - 记录方式：`attack_results.csv` 中 `status=reviewed`、`reviewer=熊钱`；每行的 **`judgment_by` 保留产出该判定的子代理编号**，原始判定在 `review/*.json`，可逐条追溯。

2. **批准一次沙箱执行**：适配后的 A04-1 POC（脚本 SHA256 `84a5a911ed4e0ee83ce898792a69bc674431aa2f0c144d7dcd6ebad5ae48c46e`），环境 ID `wsl-ubuntu2004-ns-o3-20261025`，在低权限命名空间沙箱内执行一次。
   - 审批记录：[approval_log/20261025T154643108963Z.json](../approval_log/20261025T154643108963Z.json)（哈希绑定、1 小时有效期、`auto_execute=false`）
   - 执行证据：[checks/sandbox-poc-run-20261025.json](sandbox-poc-run-20261025.json)
   - 执行结果：退出码 1，`urllib.error.URLError: Connection refused`——审批通过后才运行，而隔离网络使其无法到达任何靶场目标。

## 二、没有签认什么（避免误读）

1. **不是"漏洞不存在"的证明**。POC 因网络隔离连不上目标，只能说明门禁与隔离生效，不能反证漏洞真伪。
2. **不是 Docker 沙箱验证**。本机无 Docker，`sandbox/compose.yaml` 仍未部署；本次隔离取证用的是 Ubuntu-20.04 的 mount/network namespace + 低权限用户。
3. **签认时 guard v2 尚未实施**。v2 在此后落地并完成同批复测（[记录](guard-v2-retest-20261026.md)），其规则变更不在本签认范围内。
4. **不是对判定方法本身的背书**。36 行的六个布尔字段由独立子代理先行产出，签字人复核确认；判定口径的局限（样本量小、天花板效应）见批次 README 第三节。

## 三、相关证据索引

| 证据 | 文件 |
| --- | --- |
| 批次结果与指标 | [batches/dsh-20261025/README.md](../batches/dsh-20261025/README.md) |
| 36 行统计表 | [batches/dsh-20261025/attack_results.csv](../batches/dsh-20261025/attack_results.csv) |
| 逐行判定原始记录 | [batches/dsh-20261025/review/](../batches/dsh-20261025/review/) |
| 批次指标 JSON | [batches/dsh-20261025/checks/model_metrics.json](../batches/dsh-20261025/checks/model_metrics.json) |
| 运行协议与偏差披露 | [batches/dsh-20261025/RUN_PROTOCOL.md](../batches/dsh-20261025/RUN_PROTOCOL.md) |
| 审批记录 | [approval_log/20261025T154643108963Z.json](../approval_log/20261025T154643108963Z.json) |
| 已批准脚本 | [sandbox/approved/approved.py](../sandbox/approved/approved.py) |
| 沙箱执行证据 | [checks/sandbox-poc-run-20261025.json](sandbox-poc-run-20261025.json) |
| 沙箱隔离证据 | [checks/sandbox-run-20261025.json](sandbox-run-20261025.json) |

机器可读的签认记录见 [batches/dsh-20261025/attestation.json](../batches/dsh-20261025/attestation.json)；`security_review.csv` 的 `human_judgment` 记为 `reviewed_and_approved`，并带 `signer`、`attested_at`、`judgment_by` 三列。
