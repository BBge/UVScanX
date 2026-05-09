# UVScanX

UVScanX is an upgraded UVScan-style firmware API-usage violation scanner.  See the full project documentation in [README_UVSCANX.md](README_UVSCANX.md).

Quick start:

```bash
python3 -m uvscanx rules validate data/rules/api_rules.json
./scripts/build_synthetic.sh
python3 -m uvscanx scan examples/synthetic/bin --out runs/smoke --firmware-id synthetic-regression --engine datalog
python3 -m uvscanx report runs/smoke/summary.json
```

Generated outputs such as `runs/`, firmware downloads, extracted rootfs trees, local toolchains, and synthetic ELF binaries are intentionally ignored by git.

## Disclaimer

UVScanX reports potential API usage violations for research and defensive analysis. Findings are not confirmed vulnerabilities or CVEs without manual validation. Do not upload proprietary firmware images or extracted rootfs trees to this repository.

