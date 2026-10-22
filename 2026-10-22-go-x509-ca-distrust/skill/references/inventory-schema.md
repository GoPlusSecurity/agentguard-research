# Go 构建产物离线台账

UTF-8（可带 BOM）CSV，必需列：`asset,service,build_go_version,build_evidence,binary_path,cert_verify_usage,owner`。所有列可为空，缺失会作为证据缺口输出。`cert_verify_usage` 填 `yes`、`no` 或 `unknown`，须基于代码与运行路径确认；不要把 `go.mod` 中的 `go` 指令写入 `build_go_version`。每个实际运行副本单独一行。

```csv
asset,service,build_go_version,build_evidence,binary_path,cert_verify_usage,owner
edge-01,api,go1.27.2,运行进程文件的 go version -m 结果 2026-10-22,/opt/app/api,yes,platform
edge-02,api,go1.27.3,运行进程文件的 go version -m 结果 2026-10-22,/opt/app/api,unknown,platform
```

文件路径只是示例。构建版本比较不能发现自定义补丁、替代证书校验逻辑或某个具体证书链是否被信任。
