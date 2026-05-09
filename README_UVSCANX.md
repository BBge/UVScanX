# UVScanX

UVScanX provides a self-contained, end-to-end, local-first upgrade pipeline:

```text
firmware download -> firmware unpack -> ELF/TPC evidence -> LLM rule/TPC extraction -> deterministic scan -> reports
```

The NLP sentiment/document-distillation stage from the paper is intentionally replaced with an
OpenAI-compatible LLM rule extractor. FirmSec-based TPC/version identification is intentionally
replaced with evidence collection plus LLM/heuristic identification. The final usage-violation
judgment is still deterministic and evidence-based.


## Repository hygiene

The GitHub repository intentionally tracks only source code, rules, curated RAG seeds, manifests, and assembly fixtures.  Large/generated artifacts are ignored and should be regenerated locally:

- `runs/` reports and Datalog fact outputs
- `data/firmware/` downloaded firmware
- `data/rootfs/` and `data/rootfs-*` unpacked firmware trees
- `examples/synthetic/bin/` generated ELF fixtures
- `tools/` local dependency/toolchain caches
- `data/rag/index/` generated lexical RAG index, except `.gitkeep`

Use `make clean` for normal generated outputs and `make distclean` before packaging or uploading a clean tree.

## Quick local smoke test

This host does not need an API key for the synthetic regression smoke test:

```bash
python3 -m uvscanx rules extract --out data/rules/api_rules.json
./scripts/build_synthetic.sh
python3 -m uvscanx scan examples/synthetic/bin --out runs/smoke --firmware-id synthetic-regression
python3 -m uvscanx report runs/smoke/summary.json
```

Expected result: 25 synthetic ELF files scanned and 17 potential findings, including one TLS verification-disabled argument finding and same-handle lifecycle findings for return-owned, pointer-out, and arg-owned handles.


## Local RAG API-usage knowledge base

UVScanX now keeps curated API-usage knowledge in `data/rag/api_usage/*.json`.  These JSON files are the local RAG store used by offline rule extraction and by the LLM prompt context.  Each entry records library/component aliases, version hints, source URLs, rule type, expected usage, confidence, and whether the rule is active for deterministic checkers.

Expanded coverage currently includes:

- OpenSSL, SQLite, libpcap, libcurl, libxml2, mbedTLS, wolfSSL
- uClibc / glibc C runtime APIs
- libupnp
- OpenSSH internal APIs when symbols are recoverable
- dnsmasq and dropbear as component/version-identification RAG entries; they are intentionally not converted into API-misuse checker rules unless concrete build-specific internal API rules are added.

Drop-in document indexing:

```text
data/rag/documents/   # put vendor/API docs here
data/rag/index/       # generated chunks/keyword index
```

Supported source formats for the lightweight local index are `.md`, `.txt`, `.rst`, `.json`, `.html`, `.pdf`, `.c/.h`, and `.cpp/.hpp`.  After adding files, run:

```bash
python3 -m uvscanx rag index
# or
make rag-index
```

Useful commands:

```bash
python3 -m uvscanx rag list
python3 -m uvscanx rag index --docs data/rag/documents --out data/rag/index
python3 -m uvscanx rag search curl_easy_perform
python3 -m uvscanx rag search mbedtls_ssl_read
python3 -m uvscanx rules extract --out data/rules/api_rules.json
```

`rag search` searches both curated API-rule JSON files and generated document chunks.  The generated checker rules in `data/rules/api_rules.json` are derived from active curated RAG rules plus any LLM extraction output; indexed document chunks are used as retrieval context for extraction.  Non-active RAG items remain retrieval/review context and are not reported as deterministic usage violations.

## LLM configuration

If `OPENAI_API_KEY` is unset, the pipeline uses deterministic mock extraction/identification so
CI and local smoke tests work offline. To use a real OpenAI-compatible service:

```bash
export OPENAI_API_KEY=...
export OPENAI_BASE_URL=https://api.openai.com/v1   # optional for compatible gateways
export UVSCAN_LLM_MODEL=gpt-4o-mini               # or another compatible model
```

LLM responses are cached under `runs/cache/llm` by default.


## Local dependency bootstrap / system dependencies

If the host lacks cross-architecture binutils, Python helper packages, `binwalk`, `7z`, or UBI/JFFS tools and sudo is unavailable, run:

```bash
./scripts/install_local_deps.sh
```

This downloads Debian packages with `apt-get download`, extracts them under `tools/local/`, and installs small Python-only helpers such as `ubi-reader` and `jefferson` into the user site.  UVScanX auto-activates `tools/local/usr/bin`, `tools/local/usr/lib/x86_64-linux-gnu`, and `tools/local/usr/lib/python3/dist-packages` at runtime via `uvscanx/deps.py`, so sudo is not required.

On this development host, passwordless sudo has also been used to install the normal system toolchain and cross-objdump packages, plus `binwalk`, `p7zip`, `squashfs-tools`, `ubi-reader`, and `jefferson`.  `sasquatch` has been built from source under `tools/src/sasquatch` and installed as `/usr/local/bin/sasquatch`; UVScanX now tries standard `unsquashfs` first and then `sasquatch` for vendor-modified SquashFS.

The system setup is captured in:

```bash
./scripts/install_system_deps.sh
```

## CLI examples

```bash
# Rules
python3 -m uvscanx rules extract --out data/rules/api_rules.json
python3 -m uvscanx rules validate data/rules/api_rules.json

# Firmware test set
python3 -m uvscanx firmware download --profile smoke --out data/firmware
python3 -m uvscanx firmware unpack data/firmware --out data/rootfs

# TPC/version identification
python3 -m uvscanx tpc identify data/rootfs --out runs/tpc-smoke --limit 50

# Scan and report
python3 -m uvscanx scan data/rootfs --out runs/firmware-smoke \
  --firmware-id smoke --tpc-summary runs/tpc-smoke/tpc_summary.json --max-binaries 100
python3 -m uvscanx report runs/firmware-smoke/summary.json

# Faster full-rootfs triage: de-duplicate identical ELF files and scan only
# priority rules/candidate binaries (OpenSSL/libcurl/libxml2/SQLite/etc.).
python3 -m uvscanx scan data/rootfs-ax73-test --out runs/ax73-priority-fast \
  --firmware-id ax73-v1-1.3.6 --tpc-summary runs/ax73-tpc/tpc_summary.json \
  --engine datalog --priority-only
```

## Outputs

`uvscanx scan` writes:

- `summary.json` with findings and evidence-insufficient observations
- `findings.csv`
- `report.md`
- `report.html`
- per-binary Datalog/ELF facts under `facts/` for supported call-site scans. x86/x86_64 work with system objdump; ARM/MIPS/AArch64 require the corresponding cross-objdump or `UVSCAN_OBJDUMP(_ARCH)` override.

Findings are labeled `potential_usage_violation`, not confirmed vulnerabilities.

For large firmware images, scanning defaults to content-hash ELF de-duplication because router rootfs trees often contain hundreds of BusyBox hardlinks/copies.  The summary records:

- `num_input_binaries`
- `num_binaries`
- `num_duplicate_binaries_skipped`
- `num_non_candidate_binaries_skipped`

Use `--no-dedupe` if you need one report entry per ELF path.  Use `--priority-only` for fast triage: it removes low-severity/high-noise rules such as libc `malloc/free` and only scans binaries that import/export or path-match priority libraries/components.

## Datalog / ddisasm facts backend

The default scanner now uses a Datalog backend:

```bash
python3 -m uvscanx scan examples/synthetic/bin --out runs/datalog-smoke \
  --firmware-id synthetic-regression --engine datalog
```

For each binary it writes a ddisasm-compatible fact subset plus UVScan rule facts under:

```text
runs/datalog-smoke/datalog/<binary>/facts/
```

Important generated relations include:

- `instruction.facts` using the ddisasm-style 10-column instruction relation
- `direct_call.facts`
- `cfg_edge_to_symbol.facts`
- `function_symbol.facts`
- `next.facts`
- `call_context.facts`, `api_call.facts`
- `binary_arch.facts`, `calling_convention.facts`, `return_register.facts`, `call_mnemonic.facts`, `branch_mnemonic.facts`
- `rule_return_value.facts`, `rule_argument.facts`, `rule_deprecated.facts`, `rule_causality.facts`
- `return_check.facts`, `argument_value.facts`
- v2 facts for richer rules: `return_value.facts`, `argument_symbol.facts`, `api_returns_handle.facts`, `api_consumes_handle.facts`, `handle_alias.facts`, `handle_escape.facts`, `string_literal.facts`

The lifecycle checker now has two layers:

1. a call-order/window rule for init/free and order-only APIs; and
2. a same-handle rule for:
   - return-owned handles such as `curl_easy_init -> curl_easy_cleanup`, `xmlReadFile -> xmlFreeDoc`, and similar APIs;
   - pointer-out handles such as `sqlite3_open(..., &db) -> sqlite3_close(db)`;
   - arg-owned initialized objects such as `mbedtls_x509_crt_init(ctx) -> mbedtls_x509_crt_free(ctx)`.

The same-handle layer follows simple architecture-aware register copies, LEA pointer expressions, stack spills/loads, and memory loads from known out-pointer slots.  Return-owned example:

```bash
python3 -m uvscanx scan \
  examples/synthetic/bin/lifecycle_return_handle_good \
  examples/synthetic/bin/lifecycle_return_handle_bad \
  examples/synthetic/bin/lifecycle_wrong_handle_bad \
  --out runs/lifecycle-handle-test --firmware-id lifecycle-handle-test --engine datalog
python3 -m uvscanx report runs/lifecycle-handle-test/summary.json
```

Expected result: the good binary is clean; the missing-cleanup and wrong-handle binaries produce `resource_lifecycle_violation` findings.

Pointer-out / arg-owned example:

```bash
python3 -m uvscanx scan \
  examples/synthetic/bin/sqlite_handle_good \
  examples/synthetic/bin/sqlite_handle_bad \
  examples/synthetic/bin/sqlite_handle_wrong_bad \
  examples/synthetic/bin/mbedtls_arg_owned_good \
  examples/synthetic/bin/mbedtls_arg_owned_bad \
  --out runs/arg-owned-handle-test --firmware-id arg-owned-handle-test --engine datalog
python3 -m uvscanx report runs/arg-owned-handle-test/summary.json
```

Expected result: `sqlite_handle_good` and `mbedtls_arg_owned_good` are clean; the missing-close/missing-free and wrong-handle cases produce `resource_lifecycle_violation` findings.

The Soufflé program is emitted as:

```text
runs/datalog-smoke/datalog/uvscan_ddisasm_rules.dl
```

and a checked-in copy is available at:

```text
data/datalog/uvscan_ddisasm_rules.dl
```

You can generate facts explicitly without scanning:

```bash
python3 -m uvscanx facts generate examples/synthetic/bin/ssl_write_bad \
  --out runs/facts/ssl_write_bad \
  --write-dl runs/facts/ssl_write_bad/uvscan.dl
```

Engine modes:

- `--engine datalog`: generate ddisasm-compatible facts and run Soufflé if available; if the host Soufflé cannot run, use a Python evaluator over the same Datalog facts so smoke tests still work.
- `--engine souffle --require-souffle`: require a working Soufflé binary and fail otherwise.
- `--engine python`: use the built-in Python checker directly.

If no system `souffle` binary is available, `--engine datalog` still generates facts and runs the fallback evaluator, while `--engine souffle --require-souffle` fails clearly.

## Disclaimer

UVScanX reports potential API usage violations for research and defensive analysis. Findings are not confirmed vulnerabilities or CVEs without manual validation. Do not upload proprietary firmware images or extracted rootfs trees to this repository.

