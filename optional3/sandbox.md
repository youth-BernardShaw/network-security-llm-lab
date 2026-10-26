# 沙箱与人工审批

## 当前状态

本机未检测到Docker命令；本目录**未启动容器**。工作包4归档说明记录服务位于另一台主机路径，且SQLi-Labs PHP服务以root运行，不能直接复用为本选做的低权限执行证明。

**已完成的两步取证**：在没有Docker的条件下，用 WSL 的 Ubuntu-20.04 建了低权限用户并叠加 mount/network namespace 与资源限制：
1. 隔离探针（[checks/sandbox-run-20261025.json](checks/sandbox-run-20261025.json)，脚本 [sandbox/isolation_probe.sh](sandbox/isolation_probe.sh)）；
2. **审批后执行一次模型 POC**（[checks/sandbox-poc-run-20261025.json](checks/sandbox-poc-run-20261025.json)）。

隔离结论与边界：

| 验证项 | 结果 |
| --- | --- |
| 执行身份 | `o3sandbox`，uid 1002，不在 sudo 组 |
| 宿主目录 | 整个 `/mnt/c` 在命名空间内被 tmpfs 覆盖、条目 0（`host_drive_visible=hidden`），mnt namespace inode 与宿主不同 |
| 敏感文件 | `/etc/shadow` 不可读；root 700 的 staging 目录不可读 |
| 写权限 | 只能写自己的 `/opt/optional3-sandbox/work`；root 拥有的 `approved/` 写被拒 |
| 网络 | 只有 `lo`；外网 curl 失败、DNS 不解析、`127.0.0.1:9080` 连接被拒；net namespace inode 与宿主不同 |
| 资源 | `ulimit -v 262144` 生效，申请 400 MB 触发 `MemoryError`；`nofile=64` |

## 已执行的一次"审批 → 沙箱运行"

| 环节 | 记录 |
| --- | --- |
| 待运行脚本 | 模型 POC：批次 `dsh-20261025` / `guarded/A04-1.json` / finding `CMD-001-C1`，`poc.status=需人工适配`、`execution_status=未运行` |
| 适配 | 仅一处字面量：`LAB_URL` 端口 `8080 → 9080`。适配说明写在 [sandbox/approved/approved.py](sandbox/approved/approved.py) 文件头 |
| 静态预检 | `inspect_python` 返回 `[]`（无 issues），才允许进入审批 |
| 审批 | `approval.py --reviewer 熊钱 --environment wsl-ubuntu2004-ns-o3-20261025 --attest-isolated-low-privilege`，生成 [approval_log/20261025T154643108963Z.json](approval_log/20261025T154643108963Z.json)：哈希 `84a5a911…`、1 小时有效期、`auto_execute=false` |
| 运行前复核 | 沙箱内重算哈希与审批记录一致（`sha256_matches_approved_source=true`），且在有效期内 |
| 执行 | `runuser -u o3sandbox -- … python3 -I -S /opt/optional3-sandbox/approved/approved.py linux` |
| 结果 | 退出码 **1**，`urllib.error.URLError: [Errno 111] Connection refused`；stdout 为空 |
| 解释 | 门禁顺序正确（先审批、后执行、自动执行关闭）；隔离网络使其无法到达任何目标。**不能**据此说漏洞不存在 |

签字人对上述批次结论与本次执行的签认见 [checks/review-attestation-20261025.md](checks/review-attestation-20261025.md)。仍需注意：`compose.yaml` 容器沙箱仍未部署，`approval.py` 只记录声明、不验证隔离，隔离证据由本文件的探针单独提供。

## 命名空间隔离探针（可复现）

```text
wsl -d Ubuntu-20.04 -e bash -lc 'bash /mnt/c/<repo>/optional3/sandbox/isolation_probe.sh'
```

脚本会创建低权限用户与目录、在 `unshare -m -n` 中用 tmpfs 遮蔽宿主盘、拉起 loopback，然后以 `o3sandbox` 身份在 `ulimit -v/-n/-t` 限制下运行探针，最后把观测写成 JSON。它不执行模型代码、不联网、不写宿主文件。宿主上 Ubuntu-22.04 发行版已损坏（ext4.vhdx 缺失），故使用 20.04。

## 离线脚本审查环境

随附sandbox/compose.yaml用于人工部署离线审查容器：非root用户、只读根文件系统、禁用网络、丢弃capabilities、禁止提权、限制CPU/内存/进程及临时空间，不挂载宿主仓库、用户目录或Docker socket。

容器镜像必须先由人工拉取并记录RepoDigest；将IMAGE_REF设为形如python@sha256:实际摘要，不能填虚假摘要。Docker运行配置和镜像摘要应保存为本次证据。容器镜像含标准库，不临时安装模型推荐依赖；本工具零第三方运行依赖。需要额外依赖时另建经审查的锁定镜像。

审批后的脚本复制到sandbox/approved/approved.py；目录只放该脚本，不放密钥。输出从容器stdout/stderr由人工保存，脚本只能写限制大小的/tmp。当前compose不自动执行脚本，也没有常驻代理。

## 人工操作顺序

1. 检查模型原文、目标授权、代码及依赖，运行静态校验。危险或不支持的脚本不执行。
2. 部署沙箱并保存非root身份、只读根文件系统、网络禁用及资源限制证据；未配置就不签发环境声明。
3. 由实际人工审批者运行approval.py，填写自己的姓名或约定身份及真实环境ID，并明确声明低权限隔离。不得用助手名自动代签。
4. 将批准脚本哈希与日志核对，确认未过一小时且代码未变。容器脚本只读挂载；修改后重新审批。
5. 人工调用容器内的`timeout 15s python -I -S /work/approved.py`；同时设置宿主侧超时，保存真实命令和结果。不得对未经审批的模型文本直接调用eval、exec或shell。
6. 保存退出码、超时、stdout/stderr及容器配置，复核后清理容器与临时文件。不得把“门禁通过”填写为“POC成功”。

审批记录命令示例（仅在真实环境准备并完成审查之后）：

```text
python optional3/validators/approval.py optional3/sandbox/approved/approved.py --reviewer 实际审批人 --environment 实际环境ID --attest-isolated-low-privilege
```

这条命令只记录声明，不执行脚本；没有技术验证所声称环境，维护者必须审阅对应隔离证据。

## HTTP POC的额外要求

network_mode=none不能访问历史靶场，这属于预期限制。需要HTTP验证时应单独部署经审核的内部容器网络，只连接执行容器与专用靶场，禁止出站互联网、云元数据和宿主业务服务；在容器内localhost不是宿主靶场。

本版不提供绕过网络隔离的host网络配置。需要内部服务地址时，人工根据授权范围调整目标白名单并版本化；未完成隔离、目标绑定、重定向控制及审批前，不开展HTTP执行。无真实环境时，保留未测状态。

## 必须采集的证据

非root身份、容器配置、镜像摘要、网络拒绝、资源超限或超时处理、批准前不执行、批准后哈希一致、实际命令及输出。不要为了采证执行破坏性动作；使用无害打印和测试进程即可。
