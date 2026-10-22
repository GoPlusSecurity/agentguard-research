# 离线 CSV 证据格式

使用 UTF-8（可含 BOM），首行是列名。两个模式均不会访问网络或执行输入路径。

## `inventory`：PHP 资产台账

必需表头：`asset,service,php_version,version_source,internet_exposed,owner`。字段可以为空，但会被报告为证据缺口；至少一个有效资产行。`internet_exposed` 填 `yes` / `no` / `unknown`，其他值会被标记为无效证据（不会假定 `no`）。`php_version` 若为纯上游三段式版本（如 `8.5.12`），工具只按**该分支**门槛作初步比较；无法识别的版本及厂商回补另行核实。`version_source` 应指明采集时间、工作进程/包来源和节点。相同 `asset` 的多条服务记录分别保留。

```csv
asset,service,php_version,version_source,internet_exposed,owner
web-01,storefront,8.5.11,节点 web-01 的发行版包清单 2026-10-21,yes,web-team
job-02,batch,,,unknown,platform-team
```

示例版本只是演示字段；发行版包若回补了安全修复，应以其公告及包修订号复核，不得仅凭 `php_version` 列宣布安全或脆弱。

## `processes`：已有进程创建事件

必需表头：`asset,timestamp,parent_image,child_image`；其余列允许存在但不读取或回显。文件需由可信内部日志系统导出，时间保留源时区。工具基于**可执行文件 basename** 做通用线索筛选，支持 Windows 与 POSIX 路径；不识别自定义进程名、脚本包装、容器父子关系丢失等情况。

```csv
asset,timestamp,parent_image,child_image
web-01,2026-10-21T10:00:00Z,/usr/sbin/php-fpm,/usr/bin/sh
web-01,2026-10-21T10:01:00Z,/usr/sbin/php-fpm,/usr/bin/convert
```

第一行只表示应关联调查，第二行不命中不代表良性或无风险。不要将真实完整命令行、令牌、请求体写入共享台账。
