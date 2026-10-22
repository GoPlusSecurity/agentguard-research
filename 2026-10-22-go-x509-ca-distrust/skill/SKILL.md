---
name: check-go-x509-ca-distrust
description: 对自有 Go 服务核查 CVE-2026-111943 的构建版本、证书链验证用途和重新编译部署状态。用只读命令及离线 CSV 工具比较 go1.26.10 和 go1.27.3 修复门槛，不主动探测 TLS 服务。
---

# Go CVE-2026-111943 构建与证书验证自查

## 基准和范围

依据 [Go 问题 #82345](https://go.dev/issue/82345)及[发布历史](https://go.dev/doc/devel/release)：Go 1.26.10 / 1.27.3 修复 `crypto/x509` 对部分中间 CA 的信任问题；官方称相关 CA 的运作存在特定安全疑虑，并未在该问题单确认“私钥泄露”。此问题是紧急安全修复；不要另行推断 CVSS 等级。

检查自有资产的**运行二进制**和应用证书验证用途。不生成伪造证书，不主动向未授权服务建立连接。工具仅读用户提供的本地 CSV，不执行任何待查二进制。

## 1. 收集运行产物证据

按服务和每个部署副本记录资产、路径、hash、构建 Go 版本、构建来源、证书验证用途和负责人。在目标主机只读查看进程路径；将实际产物交由可信工具分析：

```bash
ps -eo pid,ppid,user,args | grep -E '[g]o-service-name'
readlink -f /proc/<PID>/exe
go version -m /path/to/confirmed/go-binary
```

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'myservice.exe' } | Select-Object ProcessId,ExecutablePath
go version -m 'C:\path\to\confirmed\myservice.exe'
```

`go version -m` 不执行目标二进制，但本例调用的 `go` 必须来自可信已安装工具链。若路径或权限不确定，记录“无法判定”。`go version`（单独运行）只报告当前工具链；`go.mod` 中的 `go` 指令不能证明已部署产物用哪个编译器构建。使用镜像或供应商构建时同时保存镜像摘要/构建证明。

## 2. 离线台账

按照 [references/inventory-schema.md](references/inventory-schema.md) 创建 UTF-8 CSV：

```bash
python3 scripts/check_go.py inventory /path/to/go-assets.csv
```

脚本只比较稳定的 **go1.26.x、go1.27.x** 构建版本，返回 `before_fix_upstream_build`、`at_or_above_fix_verify_deployment` 或 `unknown_or_unsupported_review`。后一类包括旧分支、预发布版及无法解析的供应商版本；前一类如被厂商回补也需要人工核对。版本号到达门槛不证明所有正在运行的副本已更新。退出码 0 只代表解析成功；2 代表输入或证据不完整。

## 3. 业务影响与更新复核

- 列出出站 TLS/HTTPS、mTLS 服务端客户端证书验证、内部 PKI、证书管理与调用 `crypto/x509.Certificate.Verify` 的业务；核对自定义 `tls.Config`/验证回调是否替代或跳过标准链验证。存在自定义逻辑时单独评估，不能仅用构建版本结论覆盖。
- 使用可信来源的 Go 1.26.10、1.27.3 或后续含修复版本**重新编译、重新部署并重启**服务，核对运行进程关联的实际文件、构建信息、镜像摘要和所有节点。更新开发机工具链本身不会自动修补既有二进制。
- 关联既有证书错误、TLS 握手和证书链配置变更，检查业务是否依赖被拦截的中间证书。升级后若部分链不再通过，应联系对应服务/CA 获取可信替代链；不得通过关闭证书校验恢复连接。
- 输出“构建版本、运行文件、用途、供应商回补、日志覆盖、升级与重新部署状态、待核实项”。不以无异常日志证明未受影响。

验证方法及覆盖局限见 [references/validation.md](references/validation.md)；事件分析见 [../case.md](../case.md)。
