from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .firmware import download as firmware_download
from .firmware import unpack as firmware_unpack
from .datalog import generate_facts, write_program
from .rules import load_rules
from .rules import DEFAULT_RULES, extract_rules
from .schemas import validate_rules
from .scanner import scan as scan_inputs
from .tpc import identify as tpc_identify
from .util import read_json, write_json
from .rag import DEFAULT_DOCS_DIR, DEFAULT_INDEX_DIR, build_index as rag_build_index
from .rag import list_libraries as rag_list_libraries, search as rag_search


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="uvscanx", description="UVScanX upgraded firmware usage-violation pipeline")
    parser.add_argument("--version", action="version", version=f"uvscanx {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rules = sub.add_parser("rules", help="Rule extraction and validation")
    rs = p_rules.add_subparsers(dest="rules_cmd", required=True)
    p = rs.add_parser("extract", help="Extract API usage rules with LLM or offline mock")
    p.add_argument("--docs", nargs="*", type=Path, help="Local documentation files; defaults to data/docs/*.md")
    p.add_argument("--out", type=Path, default=DEFAULT_RULES)
    p.set_defaults(func=cmd_rules_extract)
    p = rs.add_parser("validate", help="Validate a rules JSON file")
    p.add_argument("rules", type=Path, nargs="?", default=DEFAULT_RULES)
    p.set_defaults(func=cmd_rules_validate)

    p_fw = sub.add_parser("firmware", help="Firmware download/unpack")
    fs = p_fw.add_subparsers(dest="fw_cmd", required=True)
    p = fs.add_parser("download", help="Download firmware according to manifest")
    p.add_argument("--manifest", type=Path)
    p.add_argument("--profile", default="smoke", help="manifest profile: smoke, full, all")
    p.add_argument("--out", type=Path, default=Path("data/firmware"))
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_firmware_download)
    p = fs.add_parser("unpack", help="Unpack firmware archives/images")
    p.add_argument("inputs", nargs="+", type=Path)
    p.add_argument("--out", type=Path, default=Path("data/rootfs"))
    p.add_argument("--no-recursive", action="store_true")
    p.set_defaults(func=cmd_firmware_unpack)

    p_facts = sub.add_parser("facts", help="Generate ddisasm-compatible facts")
    fss = p_facts.add_subparsers(dest="facts_cmd", required=True)
    p = fss.add_parser("generate", help="Generate ddisasm-compatible fact subset and UVScan rule facts")
    p.add_argument("binary", type=Path)
    p.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--write-dl", type=Path, help="Also write the Soufflé Datalog program to this path")
    p.set_defaults(func=cmd_facts_generate)


    p_rag = sub.add_parser("rag", help="Local API-usage RAG knowledge base")
    rags = p_rag.add_subparsers(dest="rag_cmd", required=True)
    p = rags.add_parser("list", help="List libraries/components in the local RAG store")
    p.set_defaults(func=cmd_rag_list)
    p = rags.add_parser("index", help="Build a local RAG index from data/rag/documents")
    p.add_argument("--docs", type=Path, default=DEFAULT_DOCS_DIR, help="directory containing dropped documentation files")
    p.add_argument("--out", type=Path, default=DEFAULT_INDEX_DIR, help="index output directory")
    p.add_argument("--chunk-size", type=int, default=1400)
    p.add_argument("--overlap", type=int, default=180)
    p.set_defaults(func=cmd_rag_index)
    p = rags.add_parser("search", help="Search curated API rules and indexed documentation chunks")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--rules-only", action="store_true", help="do not search generated document chunks")
    p.add_argument("--index", type=Path, default=DEFAULT_INDEX_DIR, help="RAG index directory")
    p.set_defaults(func=cmd_rag_search)

    p_tpc = sub.add_parser("tpc", help="Third-party component identification")
    ts = p_tpc.add_subparsers(dest="tpc_cmd", required=True)
    p = ts.add_parser("identify", help="Identify TPC names from ELF evidence")
    p.add_argument("inputs", nargs="+", type=Path)
    p.add_argument("--out", type=Path, default=Path("runs/tpc"))
    p.add_argument("--limit", type=int, default=200)
    p.set_defaults(func=cmd_tpc_identify)

    p_scan = sub.add_parser("scan", help="Scan ELF files or unpacked firmware directories")
    p_scan.add_argument("inputs", nargs="+", type=Path)
    p_scan.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    p_scan.add_argument("--out", type=Path, default=Path("runs/scan"))
    p_scan.add_argument("--firmware-id")
    p_scan.add_argument("--tpc-summary", type=Path)
    p_scan.add_argument("--max-binaries", type=int)
    p_scan.add_argument("--priority-only", action="store_true", help="scan only priority rules/candidate binaries; skips low-severity/high-noise rules such as libc allocation checks")
    p_scan.add_argument("--no-dedupe", action="store_true", help="disable content-hash ELF de-duplication")
    p_scan.add_argument("--engine", choices=["datalog", "souffle", "python"], default="datalog", help="analysis engine: datalog uses ddisasm facts + Soufflé rules with Python Datalog fallback; souffle requires Soufflé; python uses built-in checker")
    p_scan.add_argument("--require-souffle", action="store_true", help="fail if Soufflé cannot execute")
    p_scan.set_defaults(func=cmd_scan)

    p_report = sub.add_parser("report", help="Print or serve a compact report summary")
    p_report.add_argument("summary", type=Path, nargs="?", default=Path("runs/scan/summary.json"))
    p_report.add_argument("--serve", action="store_true", help="serve the report directory over HTTP")
    p_report.add_argument("--host", default="0.0.0.0")
    p_report.add_argument("--port", type=int, default=8000)
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"[UVScanX] error: {exc}", file=sys.stderr)
        return 1


def cmd_rules_extract(args: argparse.Namespace) -> int:
    rules = extract_rules(args.docs, args.out)
    print(f"[UVScanX] wrote {args.out} with {sum(len(rules.get(k, [])) for k in ('return_value','argument','causality','deprecated','resource_lifecycle'))} rules")
    return 0


def cmd_rules_validate(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    res = validate_rules(rules)
    for w in res.warnings:
        print(f"[warn] {w}")
    if not res.ok:
        for e in res.errors:
            print(f"[error] {e}", file=sys.stderr)
        return 2
    print(f"[UVScanX] rules valid: {args.rules}")
    return 0


def cmd_firmware_download(args: argparse.Namespace) -> int:
    obj = firmware_download(args.manifest, args.out, args.profile, args.force)
    print(f"[UVScanX] firmware download report: {args.out / 'download_report.json'} ({obj['num_selected']} selected)")
    return 0 if all(x.get("status") != "error" and x.get("status") != "sha256_mismatch" for x in obj["firmware"]) else 2


def cmd_firmware_unpack(args: argparse.Namespace) -> int:
    obj = firmware_unpack(args.inputs, args.out, recursive=not args.no_recursive)
    print(f"[UVScanX] unpack report: {args.out / 'unpack_report.json'} ({len(obj['items'])} item attempts)")
    return 0 if all(x.get("status") == "ok" for x in obj["items"]) else 2



def cmd_rag_list(args: argparse.Namespace) -> int:
    rows = rag_list_libraries()
    for r in rows:
        aliases = ", ".join((r.get("aliases") or [])[:4])
        print(f"{r.get('library')}: {r.get('component_type')} | active {r.get('num_active_rules')}/{r.get('num_rules')} | {aliases}")
    print(f"[UVScanX] RAG libraries/components: {len(rows)}")
    return 0


def cmd_rag_index(args: argparse.Namespace) -> int:
    manifest = rag_build_index(args.docs, args.out, chunk_size=args.chunk_size, overlap=args.overlap)
    print(f"[UVScanX] RAG index: {args.out} ({manifest['num_documents']} documents, {manifest['num_chunks']} chunks)")
    print(f"[UVScanX] chunks: {args.out / 'chunks.jsonl'}")
    return 0


def cmd_rag_search(args: argparse.Namespace) -> int:
    rows = rag_search(args.query, limit=args.limit, include_index=not args.rules_only, index_dir=args.index)
    for r in rows:
        if r.get("kind") == "doc_chunk":
            chunk = r.get("chunk") or {}
            print(f"[{r.get('score')}] doc :: {chunk.get('relative_path')}#{chunk.get('chunk_index')}")
            print(f"    preview: {chunk.get('preview')}")
            print(f"    id: {chunk.get('id')}")
            continue
        rule = r.get("rule") or {}
        api = rule.get("api") or rule.get("open_api") or rule.get("id")
        print(f"[{r.get('score')}] {r.get('library')} :: {rule.get('type')} :: {api}")
        print(f"    expected: {rule.get('expected')}")
        print(f"    source: {rule.get('source_url')} | active={rule.get('active')} confidence={rule.get('confidence')}")
    print(f"[UVScanX] RAG hits: {len(rows)}")
    return 0

def cmd_tpc_identify(args: argparse.Namespace) -> int:
    obj = tpc_identify(args.inputs, args.out, limit=args.limit)
    print(f"[UVScanX] TPC summary: {args.out / 'tpc_summary.json'} ({len(obj['components'])} component groups)")
    return 0


def cmd_facts_generate(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    meta = generate_facts(args.binary, rules, args.out)
    if args.write_dl:
        write_program(args.write_dl)
    print(f"[UVScanX] generated ddisasm-compatible facts: {args.out} ({meta['num_instructions']} instructions, {meta['num_calls']} calls)")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    summary = scan_inputs(
        args.inputs,
        args.out,
        args.rules,
        args.firmware_id,
        args.tpc_summary,
        args.max_binaries,
        engine=args.engine,
        require_souffle=args.require_souffle,
        dedupe=not args.no_dedupe,
        priority_only=args.priority_only,
    )
    print(f"[UVScanX] scan summary: {args.out / 'summary.json'} ({summary['num_findings']} findings, {summary['num_observations']} observations)")
    if summary.get("dedupe_enabled"):
        print(f"[UVScanX] dedupe skipped {summary.get('num_duplicate_binaries_skipped', 0)} duplicate ELF paths")
    if summary.get("priority_only"):
        print(f"[UVScanX] priority-only skipped {summary.get('num_non_candidate_binaries_skipped', 0)} non-candidate ELF files")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    obj = read_json(args.summary)
    report_dir = args.summary.resolve().parent
    html_path = report_dir / "report.html"
    print(f"Firmware: {obj.get('firmware_id')}")
    print(f"Binaries: {obj.get('num_binaries')} | Findings: {obj.get('num_findings')} | Priority: {obj.get('num_priority_findings', 'n/a')} | Auxiliary: {obj.get('num_auxiliary_findings', 'n/a')} | Observations: {obj.get('num_observations')}")
    display_findings = obj.get("priority_findings") or obj.get("findings", [])
    for f in display_findings[:50]:
        print(f"- {f.get('checker')}: {f.get('api')} {f.get('binary')} {f.get('call_addr')} {f.get('reason')}")
    if html_path.exists():
        print(f"HTML: {html_path}")
    if args.serve:
        import functools
        import http.server
        import socketserver
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(report_dir))
        with socketserver.TCPServer((args.host, args.port), handler) as httpd:
            print(f"Serving {report_dir} at http://127.0.0.1:{args.port}/report.html")
            print("Press Ctrl-C to stop.")
            httpd.serve_forever()
    return 0
