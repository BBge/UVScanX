# UVScanX

UVScanX is an upgraded firmware API-usage violation scanner inspired by UVScan.  It is designed for firmware analysis and keeps the final finding decision deterministic:

```text
firmware download -> firmware unpack -> ELF/component evidence -> RAG/LLM API-rule extraction -> ddisasm-style facts -> Soufflé Datalog rules -> reports
```

Key design choices:

- The original NLP sentiment/document-distillation stage is replaced by RAG/LLM-assisted API usage rule extraction.
- FirmSec-style third-party library version identification is **not used**.
- UVScanX no longer reports or infers third-party component versions; it only identifies component/library names when useful for context.
- Usage-violation findings are produced by deterministic checkers over binary facts and Datalog rules.
- Findings are labeled as `potential_usage_violation`, not confirmed vulnerabilities or CVEs.

## Repository layout

```text
uvscanx/                         Python package and CLI
data/rules/api_rules.json        Extracted/curated checker rules
data/datalog/uvscan_ddisasm_rules.dl
                                  Checked-in Soufflé Datalog rules
 data/rag/api_usage/             Curated API-usage RAG seed JSON
data/rag/documents/              Drop documentation files here before indexing
data/manifests/firmware_manifest.json
                                  Public firmware metadata manifest
examples/synthetic/              Synthetic assembly regression fixtures
examples/firmware/dlink-dir880l-a1-1.07/
                                  Small representative real firmware example
examples/reports/dlink-dir880l-a1-1.07/
                                  Pre-generated report for the example firmware
scripts/                         Bootstrap/build helper scripts
tests/                           Unit/regression tests
```

Generated analysis data is intentionally ignored by git:

```text
runs/
data/firmware/
data/rootfs/
data/rootfs-*/
data/rootfs-unblob-*/
examples/synthetic/bin/
tools/
artifacts/
archive_unrelated/
```

A local pre-commit hook runs `scripts/precommit_check.sh` to block accidental staging of generated outputs, oversized files, and common secret patterns.  The only large firmware file intentionally allowed in git is the representative D-Link example under `examples/firmware/dlink-dir880l-a1-1.07/`.

## Install dependencies

Minimal Python dependencies:

```bash
python3 -m pip install --user -r requirements.txt
```

System tools for real firmware unpacking and cross-architecture analysis:

```bash
./scripts/install_system_deps.sh
```

If sudo is unavailable, use the local bootstrap path:

```bash
./scripts/install_local_deps.sh
```

Important tools include `file`, `binutils-multiarch`, cross-`objdump`, `unsquashfs`, `sasquatch`, `binwalk`, `unblob`, `ubi-reader`, `p7zip`, and Python packages such as `pyelftools`, `capstone`, `pydantic`, `openai`, and `pytest`.

## Quick synthetic smoke test

This does not require an API key:

```bash
python3 -m uvscanx rules extract --out data/rules/api_rules.json
./scripts/build_synthetic.sh
python3 -m uvscanx scan examples/synthetic/bin \
  --out runs/smoke \
  --firmware-id synthetic-regression \
  --engine datalog
python3 -m uvscanx report runs/smoke/summary.json
```

The synthetic test generates ddisasm-compatible fact files and checks return-value, argument, causality/deprecated-API, and resource-lifecycle rules.

## Representative real firmware example

This repository includes one small public firmware sample for reproducibility:

```text
examples/firmware/dlink-dir880l-a1-1.07/DIR-880L_A1_FW_1.07.zip
```

A pre-generated report is included here:

```text
examples/reports/dlink-dir880l-a1-1.07/report.html
examples/reports/dlink-dir880l-a1-1.07/report.md
examples/reports/dlink-dir880l-a1-1.07/summary.json
examples/reports/dlink-dir880l-a1-1.07/findings.csv
examples/reports/dlink-dir880l-a1-1.07/tpc_components.json
```

To regenerate it locally:

```bash
rm -rf runs/example-dlink
python3 -m uvscanx firmware unpack \
  examples/firmware/dlink-dir880l-a1-1.07/DIR-880L_A1_FW_1.07.zip \
  --out runs/example-dlink/rootfs-zip

BIN=$(find runs/example-dlink/rootfs-zip -type f -name '*.bin' | head -1)
python3 -m uvscanx firmware unpack "$BIN" --out runs/example-dlink/rootfs-image

python3 -m uvscanx tpc identify \
  runs/example-dlink/rootfs-zip runs/example-dlink/rootfs-image \
  --out runs/example-dlink/tpc --limit 1000

python3 -m uvscanx scan \
  runs/example-dlink/rootfs-zip runs/example-dlink/rootfs-image \
  --out runs/example-dlink/scan \
  --firmware-id dlink-dir880l-a1-1.07 \
  --tpc-summary runs/example-dlink/tpc/tpc_summary.json \
  --engine datalog --priority-only

python3 -m uvscanx report runs/example-dlink/scan/summary.json --serve --port 8000
```

Then open:

```text
http://127.0.0.1:8000/report.html
```

The checked-in example report currently scans 335 input ELF paths, de-duplicates and filters them to 17 priority binaries, and reports 87 potential usage violations for review.

## Firmware manifest workflow

The manifest contains public metadata for a larger router/camera test set:

```bash
python3 -m uvscanx firmware download --profile full --out data/firmware
python3 -m uvscanx firmware unpack data/firmware --out data/rootfs
python3 -m uvscanx tpc identify data/rootfs --out runs/tpc-full --limit 5000
python3 -m uvscanx scan data/rootfs \
  --out runs/full-scan \
  --firmware-id full-test \
  --tpc-summary runs/tpc-full/tpc_summary.json \
  --engine datalog --priority-only
python3 -m uvscanx report runs/full-scan/summary.json
```

Do not commit `data/firmware/`, `data/rootfs*`, or `runs/`; they are local/generated artifacts.

## RAG API-usage knowledge base

Curated API-usage knowledge lives under:

```text
data/rag/api_usage/*.json
```

Drop additional documents into:

```text
data/rag/documents/
```

Then build/search the local lexical index:

```bash
python3 -m uvscanx rag index
python3 -m uvscanx rag list
python3 -m uvscanx rag search SSL_write
python3 -m uvscanx rules extract --out data/rules/api_rules.json
```

Current rule coverage includes OpenSSL, SQLite, libpcap, libcurl, libxml2, mbedTLS, wolfSSL, OpenSSH internal APIs when symbols are recoverable, uClibc/glibc APIs, libupnp, dnsmasq, dropbear, BusyBox, and zlib context.

## Datalog and facts backend

`uvscanx scan --engine datalog` emits ddisasm-style fact subsets plus UVScanX rule facts, then evaluates them with Soufflé when available or a Python fallback over the same facts.

Important generated relations include:

```text
instruction.facts
direct_call.facts
cfg_edge_to_symbol.facts
function_symbol.facts
next.facts
call_context.facts
api_call.facts
rule_return_value.facts
rule_argument.facts
rule_deprecated.facts
rule_causality.facts
return_check.facts
argument_value.facts
api_returns_handle.facts
api_consumes_handle.facts
handle_alias.facts
handle_escape.facts
string_literal.facts
```

The checked-in Datalog program is:

```text
data/datalog/uvscan_ddisasm_rules.dl
```

Generate facts for one binary:

```bash
python3 -m uvscanx facts generate /path/to/binary \
  --out runs/facts/example \
  --write-dl runs/facts/example/uvscan.dl
```

Engine modes:

- `--engine datalog`: generate facts and use Soufflé if available, otherwise Python fallback.
- `--engine souffle --require-souffle`: require a working Soufflé binary.
- `--engine python`: use the built-in Python checker directly.

## LLM configuration

No API key is required for tests or the included example.  Without `OPENAI_API_KEY`, UVScanX uses deterministic local/mock extraction and component-name heuristics.

To use an OpenAI-compatible endpoint for API-rule extraction:

```bash
export OPENAI_API_KEY=...
export OPENAI_BASE_URL=https://api.openai.com/v1   # optional
export UVSCAN_LLM_MODEL=gpt-4o-mini               # optional
```

Do not commit keys.  LLM cache files are generated under `runs/cache/llm` and ignored.

## Before pushing

Run:

```bash
make distclean
./scripts/precommit_check.sh
python3 -m pytest -q tests
git status --short --ignored
```

`make distclean` removes generated firmware downloads, extracted rootfs trees, run outputs, local tools, caches, and synthetic binaries.  It does not remove the checked-in representative firmware/report under `examples/`.

## Disclaimer

UVScanX is for research and defensive firmware analysis.  A finding means a potential API usage violation requiring manual review; it is not a confirmed vulnerability, exploitability claim, or CVE assignment.
