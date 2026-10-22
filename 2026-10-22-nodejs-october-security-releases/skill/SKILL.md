---
name: check-nodejs-october-2026
description: 对自有 Node.js 服务核对 2026 年 10 月四项 High 及六项 Medium/Low CVE 的运行版本、DNS/TLS/Brotli 等数据流和既有日志。用于 22.23.4、24.22.1、26.12.1 安全版本的离线台账自查和回补证据整理，不执行漏洞探测或载荷。
---

# Node.js 2026 年 10 月安全漏洞自查

## 基准与边界

- 以 [Node.js 安全公告](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)及 [22.x](https://nodejs.org/en/blog/release/v22.23.4/)、[24.x](https://nodejs.org/en/blog/release/v24.22.1/)、[26.x](https://nodejs.org/en/blog/release/v26.12.1/) 发布说明为准。**本轮最高评级 High，没有 Critical**。关注四项：CVE-2026-105482（DNS 名称 NUL 截断，22/24/26）、CVE-2026-105483（全角数字 IP 的 TLS 主机名校验，24/26）、CVE-2026-106069（非规范 IP 字符串的 TLS 主机名校验，22/24/26）、CVE-2026-111497（Brotli 越界写与潜在 RCE，22/24/26）。
- 同批次还包括 Medium：CVE-2026-105481（keep-alive 响应错配）、CVE-2026-106072（非规范 IPv4 证书校验）、CVE-2026-106074（快照/SEA 随机值重复），均涉及 22/24/26；Low：CVE-2026-106070（ZIP 头校验后返回前缀字节）、CVE-2026-106071（权限模型通配符过度授权），仅 26.x，以及 CVE-2026-106073（`fs.realpathSync` 权限模型绕过），涉及 22/24/26。具体内容见 [../case.md](../case.md)。
- 只对自有或授权资产处理既有证据；不发送探测请求、不生成恶意压缩数据、不关闭 TLS 验证、不执行未知二进制。脚本只读本地 CSV，既不联网也不运行 Node。

## 1. 收集正在运行的版本与输入面

针对每个服务采集入口、资产 ID、进程/容器、Node 可执行文件实际路径与版本、镜像或供应商包来源、互联网暴露、负责人。重点核查传入 `dns.resolve` 的名称、HTTPS/TLS 连接目标和不可信 Brotli 内容解码路径。对前端代理、Webhook、上传/队列和软件内嵌 Node 一并列出；按程序输入流确认可达性，不把代码库中出现 API 名称等同于真实触发。

```bash
# Linux：既有服务/进程信息；PID 要先经业务负责人确认
ps -eo pid,ppid,user,args | grep '[n]ode'
readlink -f /proc/<PID>/exe
# 记录容器版本和镜像摘要，确认所有副本已经滚动更新
kubectl get pods -n <NAMESPACE> -o wide
```

```powershell
# Windows：进程与可执行文件路径
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'node.exe' } | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine
```

生产环境命令行可能包含秘密，采集时限制导出与传播；不要把原始命令行贴入共享台账。默认 `node -v` 可能来自另一套安装，不能替代运行服务的版本。若由可信管理员读取已确认路径的版本，应保留节点、采集时间和包/镜像依据。

## 2. 离线盘点

按 [references/inventory-schema.md](references/inventory-schema.md) 准备 UTF-8 CSV，不包含令牌、完整 URL 或敏感请求体：

```bash
python3 scripts/check_node.py inventory /path/to/node-assets.csv
```

脚本按 **22.x、24.x、26.x 各自修复门槛**返回上游发行号的初步判断，并为服务列出适用高危 CVE。结果 `below_fixed_upstream_version` 表示原版发行号低于门槛；如包含安全回补，须以厂商修复证据人工覆盖。`at_or_above_fixed_verify_running_build` 表示发行号达到门槛，仍需验证正在运行的构建及所有节点；`unknown_or_other_line` 不作安全结论。退出码 0 仅表示 CSV 已处理；2 表示输入错误或字段/版本覆盖不足，均不代表实例安全。

工具仅枚举高危 CVE；中低危六项需结合上方适用分支和实际功能人工核查，不能因为输出未列出某项就判定不受影响。

## 3. 核对配置、日志与优先级

- **Brotli：** 找出外部可控压缩输入的解码位置（`zlib`、代理层、应用依赖），关联已有解码错误、进程崩溃、worker 重启、异常子进程/外联。不要用真实服务试投压缩样本。
- **TLS：** 审查可控 URL/主机输入、证书验证策略、代理及异常证书日志。关注非规范 IP 文本与宽松解析，但现有日志常没有原始目标或不会记录证书验证成功，未命中不能推断安全。
- **DNS：** 审查调用路径与 NUL 输入可能性，关注日志规范化后不可见的字节差异。业务校验不一致是风险线索，需要开发团队按真实数据流确认。
- **中低危：** 顺带排查 keep-alive 客户端响应对应关系、非规范 IPv4 目标、用户态启动快照/SEA 中对随机值的使用、处理不可信 ZIP 文件的路径，以及启用 Permission Model 的服务及 `fs.realpathSync` 调用；按公告适用分支确认优先级。
- **优先级：** 公网服务与不可信 Brotli 解码、动态 DNS/TLS 目标优先；内网、消息队列、供应商打包产品仍需核查。软件包里安装了 Node 但未运行对应服务，应单独注明。

## 4. 更新与回报

按分支升级到 **22.23.4 / 24.22.1 / 26.12.1** 或后续受支持安全版本，核对来源、滚动更新、多节点进程和回滚方案。厂商回补要保存公告、包修订号和构建依据；EOL 版本应制定迁移。用“上游版本判断、实际运行构建、回补证据、输入面、日志覆盖、待人工核验”分别列结果；单个异常 DNS、TLS 失败或解码错误不证明利用。若有入侵迹象，遵循隔离与取证流程。

离线行为验证和结果解释见 [references/validation.md](references/validation.md)；更详细机制与官方链接见 [../case.md](../case.md)。
