# Node.js 资产 CSV 格式

UTF-8（可带 BOM），必需列名：`asset,service,node_version,version_source,internet_exposed,owner`。可加 `dns_untrusted,tls_dynamic_host,brotli_untrusted` 三个可选列，值为 `yes` / `no` / `unknown`；缺列或未知值将按 `unknown` 输出，不会将未检查的输入面默认为 `no`。

```csv
asset,service,node_version,version_source,internet_exposed,owner,dns_untrusted,tls_dynamic_host,brotli_untrusted
svc-01,api,v24.22.0,容器摘要及进程路径 2026-10-22,yes,platform,unknown,yes,unknown
svc-02,worker,v22.23.4,节点进程与包清单 2026-10-22,no,backend,no,no,yes
```

版本只接受官方稳定发行格式 `v22.23.4` 或 `22.23.4` 等；发行版修订号、预发布、自定义构建标记为未知，须人工核查供应商补丁。纯版本比较不验证运行二进制和依赖源码；`version_source` 应写明节点、采集时间及来源。多节点使用多行，不能用一个服务名代表全部副本。
