# Offline Checker Validation and Limitations

Run from `skill/`:

```bash
python3 -B -m unittest discover -s scripts -p 'test_*.py' -v
```

Tests cover releases immediately below, at, and above each of four upstream thresholds; conservative handling of older and unknown builds; public-exposure priority; invalid or missing evidence; Windows and POSIX process paths; unmatched child processes; missing events; and invalid CSV headers. The checker reads local CSV only. It does not execute asset binaries, connect to the network, or send PHP requests. Passing synthetic tests does not establish that real assets are safe.

Limitations: Version comparison supports plain three-part releases on four upstream branches. It cannot verify package signatures, vendor backports, source fixes, worker rollout, or custom builds; it has no issue-specific IOC. Asset inventories may omit vendor-embedded runtimes or other nodes, and process evidence depends on collection and retention. A rule match is a generic investigative lead; no match means only that the supplied events contained no matching record.
