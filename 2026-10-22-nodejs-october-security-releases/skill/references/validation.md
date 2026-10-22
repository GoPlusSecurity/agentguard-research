# 离线验证与边界

在 `skill/` 目录执行：

```bash
python3 -B -m unittest discover -s scripts -p 'test_*.py' -v
```

覆盖三个上游分支修复门槛前后、22.x 不涉及 CVE-2026-105483、未知版本不判定、缺失证据不输出安全结论、缺列报错。脚本不调用 Node、DNS、TLS 或 Brotli，不联网。合成 CSV 测试不能证明生产服务真实运行版本或不存在入侵。分支以外的版本、供应商回补、自定义二进制与代码调用可达性均需人工核对。
