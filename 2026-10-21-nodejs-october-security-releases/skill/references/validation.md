# Offline Validation and Limitations

Run from `skill/`:

```bash
python3 -B -m unittest discover -s scripts -p 'test_*.py' -v
```

Tests cover the fixed-version boundary for each supported line, the exclusion of 22.x from CVE-2026-105483, unknown builds, missing evidence, and invalid CSV headers. The script does not execute Node or use DNS, TLS, Brotli, or the network. Synthetic CSV tests do not establish a production runtime version or rule out compromise. Check other lines, vendor backports, custom binaries, and reachable application calls manually.
