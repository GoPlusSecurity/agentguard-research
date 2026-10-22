# Offline Checker Validation

Run from `skill/`:

```bash
python3 -B -m unittest discover -s scripts -p 'test_*.py' -v
```

Tests cover fixed-version boundaries, conservative handling of older or custom builds and prereleases, unknown certificate-verification use, and the distinction between a fixed build number and completed deployment. The checker reads CSV only; it does not execute binaries, scan certificates, or connect to the network. Review running builds, certificate chains, and application configuration separately.
