# Offline Go Build Inventory

Use UTF-8 CSV (a BOM is accepted) with these required columns: `asset,service,build_go_version,build_evidence,binary_path,cert_verify_usage,owner`. Empty values are reported as evidence gaps. Set `cert_verify_usage` to `yes`, `no`, or `unknown` based on code and runtime behavior. Do not use the `go` directive from `go.mod` as the build version. Record each deployed replica separately.

```csv
asset,service,build_go_version,build_evidence,binary_path,cert_verify_usage,owner
edge-01,api,go1.27.2,go version -m on running binary 2026-10-22,/opt/app/api,yes,platform
edge-02,api,go1.27.3,go version -m on running binary 2026-10-22,/opt/app/api,unknown,platform
```

Paths are illustrative. Build-version comparison cannot detect custom backports, alternative certificate verification, or whether a particular chain was accepted.
