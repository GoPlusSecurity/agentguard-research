---
id: GSI-2026-NODE-OCT
title: Node.js 2026 年 10 月安全更新：四项高危与六项中低危漏洞分析及自查
date: 2026-10-22
updated: 2026-10-22
as_of: 2026-10-22
status: confirmed
confidence: "高：Node.js 官方安全公告和三个分支的发布说明；具体利用链/在野状态未验证"
severity: high
cve: [CVE-2026-105481, CVE-2026-105482, CVE-2026-105483, CVE-2026-106069, CVE-2026-106070, CVE-2026-106071, CVE-2026-106072, CVE-2026-106073, CVE-2026-106074, CVE-2026-111497]
affected_versions: "官方标注：22.x、24.x、26.x 中各 CVE 适用分支的本轮修复前发行版；CVE-2026-105483 不涉及 22.x"
fixed_versions: "22.23.4、24.22.1、26.12.1；按分支核对；供应商回补另核实"
check_skill: ./skill/SKILL.md
references:
  - https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
  - https://nodejs.org/en/blog/release/v22.23.4/
  - https://nodejs.org/en/blog/release/v24.22.1/
  - https://nodejs.org/en/blog/release/v26.12.1/
---

# Node.js 2026 年 10 月安全更新：漏洞分析与自查

> Node.js 于 2026-10-21 发布 22.23.4、24.22.1、26.12.1 三个安全版本。本批次**最高评级为 High，没有 Critical 条目**。下文重点分析官方列出的四项高危 CVE；“Brotli 越界写允许远程代码执行”是该漏洞的潜在后果，不意味着任何 Node.js HTTP 服务均存在可直接调用的入口。本文未运行利用或扫描目标。

## 影响和修复版本

| 运行分支 | 本次修复版 | 高危漏洞 |
|---|---:|---|
| 22.x | **22.23.4** | CVE-2026-105482、CVE-2026-106069、CVE-2026-111497 |
| 24.x | **24.22.1** | 上述三项，另含 CVE-2026-105483 |
| 26.x | **26.12.1** | 上述四项 |

上述分支中，低于同分支对应修复版的上游发行版需要升级；生产上要核对**实际运行进程及镜像/包来源**。22.x 不在 CVE-2026-105483 的官方影响范围；不要因公告中的“所有过期版本始终有安全风险”就推断某个 EOL 分支精确命中哪项 CVE。EOL、自定义/嵌入构建、发行版回补、预发布版或非本轮列出的分支，应由供应商公告与修复提交判定。Node 自身的版本与 `package.json`/锁文件中的 npm 包版本也不是一回事。

## 四项高危漏洞

| CVE | 官方描述与实际风险 | 适用分支 | 自查重点 |
|---|---|---|---|
| [CVE-2026-105482](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases#dnsresolve-truncates-names-containing-nul-char-cve-2026-105482---high) | `dns.resolve` 在域名含 NUL 字符时发生名称截断。应用若把不可信名称传入 DNS 查询，前后的业务校验与实际解析对象可能出现偏差；具体认证绕过、SSRF 等后果需以应用的数据流确认，不能仅凭 Node 版本断言 | 22/24/26 | 检查调用 `dns.resolve` 及其应用封装的输入来源、域名校验与 DNS 结果用途；查找异常 NUL/编码输入的现有日志，不发送主动探测请求 |
| [CVE-2026-105483](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases#tls-certificate-hostname-bypass-when-the-ip-is-written-fullwidth-digits-cve-2026-105483---high) | 当 IP 地址以**全角数字**表示时，TLS 证书主机名校验可能绕过；属于出站客户端对证书标识的错误判定，不是“服务端对所有访问者开放登录” | 24/26 | 盘点由用户或上游数据控制的 HTTPS/TLS 目标，审查非标准 IP 文本、证书验证配置及中间人风险；确认未主动禁用证书验证 |
| [CVE-2026-106069](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases#tls-certificate-hostname-bypass-when-the-host-loosely-resolves-to-an-ip-address-cve-2026-106069---high) | 主机字符串可被宽松地识别/解析为 IP 时，TLS 证书主机名校验可能绕过。风险依赖应用能否使用此类非规范目标、调用 TLS 客户端及攻击者对连接的控制；官方修复摘要为拒绝非规范 IP 地址 | 22/24/26 | 审查代理、Webhook、回调、动态 API 目标等可控主机输入；核对标准化和证书验证策略 |
| [CVE-2026-111497](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases#nodejs-brotli-decoder-out-of-bounds-write-permits-remote-code-execution-cve-2026-111497---high) | Node.js 使用的 Brotli 解码器存在**越界写**，公告指出可导致 RCE。官方页面未说明对每种服务的触发前提和稳定性；应用必须实际处理不可信的 Brotli 压缩数据，才能形成相应输入面 | 22/24/26 | 盘点 `zlib` Brotli 解码、代理转发/自动解压、上传文件处理及第三方库中的不可信压缩数据入口；优先升级可由外部提供压缩数据的服务 |

这四项都是 **High**，官方并未在这篇公告中提供可复用的请求级 IOC、利用成功率或“已在野利用”的肯定结论。`dns.resolve` 的 NUL、TLS 非规范 IP 和 Brotli 越界写是**漏洞类别与输入线索**，不是可直接据此在访问日志中判定入侵的签名。DNS/TLS 两类尤其需要确认应用实际使用相关 API 与不可信数据流；Brotli 的恶意压缩流检测不能代替更新运行时。

## 同批次中低危漏洞（简述）

| 等级 | CVE | 官方描述简述 | 适用分支 |
|---|---|---|---|
| Medium | CVE-2026-105481 | Keep-alive 套接字可能处理请求发送前已写入的响应，需关注响应与请求的对应关系 | 22/24/26 |
| Medium | CVE-2026-106072 | 非规范 IPv4 主机名的证书验证不当，DNS 类型 SAN 可能被用于验证 IP 端点 | 22/24/26 |
| Medium | CVE-2026-106074 | `crypto.randomUUID()`/`randomInt()` 的熵缓存进入用户态启动快照或单文件应用（SEA），导致不同进程重复取值 | 22/24/26 |
| Low | CVE-2026-106070 | `ZipFile` 在 ZIP 头校验失败后仍可能返回由攻击者控制的前缀字节 | 26 |
| Low | CVE-2026-106071 | Permission Model 的通配符路径查找可能过度授予文件系统权限 | 26 |
| Low | CVE-2026-106073 | `fs.realpathSync` 可绕过 Permission Model 的限制 | 22/24/26 |

以上按[官方公告](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)的标题、评级和适用分支概述；具体可达性取决于应用是否使用相应功能与不可信输入。自查时顺带核对 keep-alive 客户端、非常规 IPv4 目标、启动快照/SEA 中的随机值、ZIP 文件处理，以及是否依赖 Permission Model 的文件访问限制。安全发布同时更新 c-ares、CA 根证书、Undici，以及部分分支中的 OpenSSL/SQLite。升级应使用**整套安全版本**，不能只更换某个 npm 包或依赖版本来代替 Node 主程序更新。

## 安全自查与处置

1. **盘点实际运行时。** 从工作负载、进程、容器镜像、打包产物和供应商产品中核对 Node 可执行文件、版本、路径、hash/来源、启动参数、服务和负责人。`node -v` 可能指向不同于服务实际运行的二进制；基础镜像已升级也不保证部署节点已切换或滚动更新完成。
2. **按分支升级。** 22.x → 22.23.4 或同分支更高的受支持安全版本；24.x → 24.22.1；26.x → 26.12.1。对于 EOL 分支，迁移到受支持分支并进行兼容性验证；厂商回补以厂商安全公告与包修订号为准。保存变更窗口、镜像摘要及升级前后进程版本证据。
3. **审查数据流。** 优先梳理可由请求、Webhook、上传、消息队列及外部服务控制的 DNS 目标、TLS 目标和 Brotli 解码输入。无对应输入面可降低该服务对某项漏洞的直接暴露，但不等于运行时版本已修复或没有其他应用风险。
4. **审查历史证据。** 关联已有 DNS 查询与响应、出站 TLS 失败/证书告警、Brotli 解码错误、进程异常崩溃/重启、子进程及外联。异常记录只作为调查线索；缺日志或没有命中并不能排除漏洞或入侵。
5. **缩小暴露与应急响应。** 无法及时升级时，收紧不可信压缩流与可控目标地址的入口，并在业务允许下隔离敏感目标、加强监控；这些是风险控制，不是通用完整缓解。如果多源证据支持失陷，保全日志与内存/文件证据，按内部流程隔离和检查凭据。

配套只读离线台账检查器和使用步骤见 [skill/SKILL.md](skill/SKILL.md)。

