---
name: check-php2shell-exposure
description: 对自有 PHP 服务开展 CVE-2026-109618 和 CVE-2026-109619 版本、暴露面与既有进程行为自查。用于核查 8.2.35/8.3.36/8.4.27/8.5.12 修复门槛和厂商回补证据，不执行漏洞探测或载荷。
---

# PHP 两项严重漏洞：版本、暴露与行为自查

## 判定边界

- 核验基准：2026-10-21 [PHP 正式公告](https://www.php.net/archive/2026.php#2026-10-21-5)与 [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)、[CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) 两项上游通告。两项均可导致未授权 RCE、CVSS v4.0 均为 9.2。
- 上游维护分支修复门槛：**8.2.x ≥8.2.35、8.3.x ≥8.3.36、8.4.x ≥8.4.27、8.5.x ≥8.5.12**。同分支低于门槛的上游版本需修复。PHP 8.1 及更早已不获得正常上游安全版本；7.4/8.0/8.1 有最小**源码回补分支**，不是正式修复发行包。发行版回补、自定义构建、预发布版与 8.6 开发分支需单独核对修复来源。**任何单独版本字符串都不是实例已修复的证明。**
- 官方确认 mod_php 上的未授权 RCE；CVE-2026-109619 的 FPM 会话生命周期路径也已验证。CVE-2026-109618 的 FPM 风险有源码分析支持，但尚无完整 FPM 利用验证；所有服务 Web 请求的 PHP 都应核查。具体机制与差异见 [../case.md](../case.md)。
- 仅在用户自有或授权资产上采集。所有命令只读已有证据；不提交测试请求或运行 PoC。离线脚本**不执行 PHP 或资产二进制**。

## 1. 盘点服务与运行时

为每项服务记录资产 ID、业务负责人、入口与可达性、PHP 所在节点和部署方式、实际运行时路径与版本、版本证据时间、包/镜像来源、日志保留范围、更新负责人。通过网关/负载均衡和部署清单确认暴露；枚举 FPM/CGI/Apache 模块/Windows 服务、定时任务、容器与供应商软件内部 PHP。可参考以下只读采集示例，路径和权限按自有环境调整：

```bash
# Linux：进程与可执行路径；/proc 仅反映当前快照，权限不足要记录
ps -eo pid,ppid,user,args | grep -E '[p]hp-fpm|[p]hp-cgi|[a]pache2|[h]ttpd'
readlink -f /proc/<PID>/exe
# 包来源（按发行版择一）；上游版本与发行版修复记录需同时保留
dpkg-query -W 'php*' 2>/dev/null
rpm -qa 'php*' 2>/dev/null
# 容器编排：先由业务清单指定命名空间与工作负载
kubectl get pods -n <NAMESPACE> -o wide
```

```powershell
# Windows：只读查看进程对应路径与服务；需有相应权限
Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(php|php-cgi|httpd)\.exe$' } | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'php|httpd' } | Select-Object Name,PathName,State
```

在可信管理环境中，对**已确认属于目标服务**的 PHP 可执行文件读取版本或包元数据，并记录执行位置与时间。命令行默认 `php -v` 可能来自另一套安装；镜像 tag、Web 响应头、Composer 依赖也不能证明当前工作进程版本。若不便运行任何二进制，仅采集包管理器/镜像摘要及供应商公告，把版本标“待核实”。

## 2. 离线检查台账

将现有 CMDB/人工盘点导出为 UTF-8 CSV，表头参见 [references/inventory-schema.md](references/inventory-schema.md)。不填密钥、个人数据或完整请求内容。缺字段可以留空，缺失必须呈现在结果中。

```bash
python3 scripts/check_php.py inventory /path/to/inventory.csv
```

脚本输出 JSON。维护分支中严格形如 `8.5.12` 的纯上游版本号可得 `affected_upstream_release` 或 `at_or_above_fixed_release_verify_build`，后者仍须核对运行时及补丁来源；`8.1.x` 和更早版本返回 `unsupported_review_vendor_backport`，其他、自定义或预发布版本返回 `unknown_version_or_build`。`priority` 只用于安排核验顺序，`internet_exposed=yes` 较高；`unknown` 要补证据。退出码 0 表示解析完成，2 表示输入错误或覆盖不完整，**均不表示资产安全**。

## 3. 关联已有进程事件

从内部 EDR/系统审计导出经归一化的进程创建 CSV（字段见同一 schema），离线筛出 PHP/FPM/CGI/Web 服务进程启动 shell、解释器和下载工具的**通用调查线索**：

```bash
python3 scripts/check_php.py processes /path/to/process-events.csv
```

输出仅含资产、时间、父/子进程名与规则标签，不回显命令行及请求内容。正常维护、应用插件、队列任务也可能触发；父进程名称缺失、记录缺口和缺少命令行上下文可能漏检。先用内网日志与业务变更关联，再查看命令行、进程树、外联与文件变更。**这些规则不是两个 CVE 的专属 IOC。**

核查反向代理、Web/PHP 错误日志、服务重启、内存耗尽、请求初始化前的配置诊断及应用可达的致命错误，关联进程遥测、异常文件及任务。记录日志文件/来源和起止时间；单个 500、FPM 重启、无匹配事件或 WAF 未告警都不能证明是否曾被利用。需要现场调查时遵循组织的保全流程。

## 4. 整理结果与准备处置

报告每项服务的台账、运行时与版本证据、暴露与权限、日志覆盖、关联线索、证据缺口。公网 mod_php 优先，其余对外 PHP 服务同样需要修复。按对应分支升级或安装经供应商确认的回补包，并复核所有节点和 worker 的实际代码。PHP 8.1 及更早版本优先迁移至受支持分支；将官方最小源码回补分支交由维护人员核对，不要把它当成可直接安装的发行包。

不能立刻升级时，评估 VPN/白名单/网络隔离和业务影响。上游所述 `memory_limit=-1` 只减少 CVE-2026-109618 的部分路径，可能增加资源耗尽风险；`session.upload_progress.enabled=0`、PHP 8.5 的 `fatal_error_backtraces=0` 只减少 CVE-2026-109619 的已验证路径，需在请求解析之前生效并重启 worker。**以上均非完整缓解；修复版本/补丁是唯一完整处置。** 不要把 WAF 或没有异常日志视为安全证明。

脚本离线验证与局限见 [references/validation.md](references/validation.md)。
