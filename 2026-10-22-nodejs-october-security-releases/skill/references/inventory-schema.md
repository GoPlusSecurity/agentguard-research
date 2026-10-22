# Node.js Asset Inventory CSV

Use UTF-8 CSV (a BOM is accepted) with required columns `asset,service,node_version,version_source,internet_exposed,owner`. Optional columns are `dns_untrusted,tls_dynamic_host,brotli_untrusted`; use `yes`, `no`, or `unknown`. Missing columns and unrecognized values are treated as `unknown`, never silently as `no`.

```csv
asset,service,node_version,version_source,internet_exposed,owner,dns_untrusted,tls_dynamic_host,brotli_untrusted
svc-01,api,v24.22.0,container digest and process path 2026-10-22,yes,platform,unknown,yes,unknown
svc-02,worker,v22.23.4,node process and package inventory 2026-10-22,no,backend,no,no,yes
```

Only stable upstream version formats such as `v22.23.4` or `22.23.4` are recognized. Distribution revisions, prereleases, and custom builds require manual verification of vendor fixes. Version comparison does not inspect the running binary or source. In `version_source`, record the node, collection time, and evidence source; use one row per deployed replica.
