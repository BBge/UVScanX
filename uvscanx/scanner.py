from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .elf import elf_metadata, iter_elfs
from .rules import load_rules
from .schemas import apis_from_rules, normalize_api
from .util import sha256_file, write_json
from .datalog import datalog_scan_binary


def _load_core():
    from . import binary_analysis
    return binary_analysis


def _python_specs(rules: Dict[str, Any]) -> Dict[str, Any]:
    from .schemas import python_checker_specs
    return python_checker_specs(rules)

def scan(
    inputs: Sequence[Path],
    out: Path,
    rules_path: Path | None = None,
    firmware_id: str | None = None,
    tpc_summary: Path | None = None,
    max_binaries: int | None = None,
    engine: str = "datalog",
    require_souffle: bool = False,
    *,
    dedupe: bool = True,
    priority_only: bool = False,
) -> Dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    raw_rules = load_rules(rules_path)
    rules = _filter_rules_for_priority(raw_rules) if priority_only else raw_rules
    core = _load_core()
    input_binaries = list(iter_elfs(inputs))
    binaries, duplicate_rows = _dedupe_binaries(input_binaries) if dedupe else (input_binaries, [])
    skipped_non_candidates: List[Dict[str, Any]] = []
    candidate_api_set = apis_from_rules(rules)
    if priority_only:
        selected: List[Path] = []
        for binary in binaries:
            meta = elf_metadata(binary)
            if _is_priority_candidate(binary, meta, candidate_api_set):
                selected.append(binary)
            else:
                skipped_non_candidates.append({
                    "binary": str(binary),
                    "reason": "no priority API symbols, library names, or path hints",
                    "needed_libraries": meta.get("needed_libraries", []),
                })
        binaries = selected
    if max_binaries:
        binaries = binaries[:max_binaries]
    tpc = _load_tpc(tpc_summary)
    findings: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    binaries_meta: List[Dict[str, Any]] = []
    for binary in binaries:
        meta = elf_metadata(binary)
        binaries_meta.append({k: meta.get(k) for k in ("path", "file", "machine", "needed_libraries")})
        bin_tpc = _tpc_for_binary(tpc, str(binary))
        if core.has_callsite_disassembler(binary):
            try:
                if engine in {"datalog", "souffle"}:
                    dl = datalog_scan_binary(binary, rules, out / "datalog", firmware_id=firmware_id, tpc=bin_tpc, require_souffle=(require_souffle or engine == "souffle"))
                    findings.extend(dl.get("findings", []))
                elif engine == "python":
                    res = core.scan_binary(binary, _python_specs(rules), out / "facts")
                    for v in res.get("violations", []):
                        findings.append(_finding_from_python(v, firmware_id, bin_tpc, rules))
                else:
                    raise ValueError(f"unknown scan engine: {engine}")
            except Exception as exc:
                if require_souffle or engine == "souffle":
                    raise
                observations.append(_observation(binary, firmware_id, f"{engine}_x86_scan_failed", str(exc), bin_tpc, meta))
                _append_symbol_results(findings, observations, binary, firmware_id, meta, rules, bin_tpc)
        else:
            _append_symbol_results(findings, observations, binary, firmware_id, meta, rules, bin_tpc)
    for f in findings:
        _ensure_tpc_candidate(f)
        _annotate_rule_metadata(f, rules)
    for o in observations:
        _ensure_tpc_candidate(o)

    priority_findings = [f for f in findings if _is_priority_finding(f)]
    auxiliary_findings = [f for f in findings if not _is_priority_finding(f)]

    summary = {
        "firmware_id": firmware_id,
        "input_paths": [str(p) for p in inputs],
        "output_dir": str(out),
        "num_input_binaries": len(input_binaries),
        "num_binaries": len(binaries),
        "dedupe_enabled": dedupe,
        "num_duplicate_binaries_skipped": len(duplicate_rows),
        "duplicate_binaries_skipped": duplicate_rows[:1000],
        "priority_only": priority_only,
        "num_non_candidate_binaries_skipped": len(skipped_non_candidates),
        "non_candidate_binaries_skipped": skipped_non_candidates[:1000],
        "num_findings": len(findings),
        "num_priority_findings": len(priority_findings),
        "num_auxiliary_findings": len(auxiliary_findings),
        "num_observations": len(observations),
        "binaries": binaries_meta,
        "findings": findings,
        "priority_findings": priority_findings,
        "auxiliary_findings": auxiliary_findings,
        "observations": observations,
        "rules_metadata": rules.get("metadata", {}),
        "raw_rules_metadata": raw_rules.get("metadata", {}),
        "engine": engine,
    }
    write_json(out / "summary.json", summary)
    _write_csv(out / "findings.csv", findings)
    _write_markdown(out / "report.md", summary)
    _write_html(out / "report.html", summary)
    return summary


def _is_rule_priority(r: Dict[str, Any]) -> bool:
    if r.get("default_enabled") is False:
        return False
    if r.get("noise_profile") == "high":
        return False
    if r.get("severity") == "low":
        return False
    return True


def _filter_rules_for_priority(rules: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"metadata": dict(rules.get("metadata", {}))}
    out["metadata"]["filtered"] = "priority_only"
    for sec in ("return_value", "argument", "causality", "deprecated", "resource_lifecycle"):
        out[sec] = [r for r in rules.get(sec, []) if _is_rule_priority(r)]
    return out


def _dedupe_binaries(binaries: List[Path]) -> tuple[List[Path], List[Dict[str, Any]]]:
    """Deduplicate identical ELF inputs by content hash.

    Real firmware rootfs trees contain many hardlinks/symlinks/copies of BusyBox
    applets.  Re-disassembling each duplicate dominates scan time and repeats the
    same findings.  The canonical path is the first occurrence in sorted order.
    """
    selected: List[Path] = []
    seen: Dict[tuple[int, str], Path] = {}
    duplicates: List[Dict[str, Any]] = []
    for p in binaries:
        try:
            st = p.stat()
            key = (st.st_size, sha256_file(p))
        except Exception:
            selected.append(p)
            continue
        if key in seen:
            duplicates.append({"binary": str(p), "canonical_binary": str(seen[key]), "size": key[0], "sha256": key[1]})
            continue
        seen[key] = p
        selected.append(p)
    return selected, duplicates


_PRIORITY_PATH_HINTS = (
    "ssl", "crypto", "curl", "xml", "sqlite", "pcap", "upnp", "mbedtls", "wolfssl",
    "ssh", "dropbear", "dnsmasq", "libssl", "libcrypto", "libcurl", "libxml",
)


def _is_priority_candidate(binary: Path, meta: Dict[str, Any], api_set: set[str]) -> bool:
    dyn = {normalize_api(x) for x in (meta.get("dynamic_symbols") or [])}
    sym = {normalize_api(x) for x in (meta.get("symbols") or [])}
    names = {x for x in dyn | sym if x}
    if names & api_set:
        return True
    hay = " ".join([str(binary).lower(), " ".join(meta.get("needed_libraries") or []).lower()])
    return any(h in hay for h in _PRIORITY_PATH_HINTS)


def _load_tpc(path: Path | None) -> Dict[str, Any] | None:
    if not path or not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _tpc_for_binary(tpc: Dict[str, Any] | None, binary: str) -> List[Dict[str, Any]]:
    if not tpc:
        return []
    for r in tpc.get("binaries", []):
        if r.get("binary") == binary:
            return r.get("llm", {}).get("components", [])
    return []


def _rule_confidence(api: str | None, rules: Dict[str, Any]) -> float | None:
    api = normalize_api(api)
    for sec in ("return_value", "argument", "causality", "deprecated"):
        for r in rules.get(sec, []):
            if normalize_api(r.get("api")) == api:
                return r.get("llm_confidence")
    for r in rules.get("resource_lifecycle", []):
        if normalize_api(r.get("open_api")) == api or normalize_api(r.get("close_api")) == api:
            return r.get("llm_confidence")
    return None




def _candidate_rules_for_api(api: str | None, rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    api = normalize_api(api)
    out: List[Dict[str, Any]] = []
    if not api:
        return out
    for sec in ("return_value", "argument", "causality", "deprecated"):
        for r in rules.get(sec, []):
            if normalize_api(r.get("api")) == api:
                rr = dict(r)
                rr["_section"] = sec
                out.append(rr)
    for r in rules.get("resource_lifecycle", []):
        if normalize_api(r.get("open_api")) == api or normalize_api(r.get("close_api")) == api:
            rr = dict(r)
            rr["_section"] = "resource_lifecycle"
            out.append(rr)
    return out


def _select_rule_for_finding(item: Dict[str, Any], rules: Dict[str, Any]) -> Dict[str, Any] | None:
    api = item.get("api")
    checker = str(item.get("checker") or "")
    candidates = _candidate_rules_for_api(api, rules)
    if not candidates:
        return None
    preferred_sections: List[str]
    if "tls_verification" in checker or "argument" in checker:
        preferred_sections = ["argument"]
    elif "deprecated" in checker:
        preferred_sections = ["deprecated"]
    elif "return" in checker:
        preferred_sections = ["return_value"]
    elif "causality" in checker:
        preferred_sections = ["causality", "resource_lifecycle"]
    else:
        preferred_sections = []
    for sec in preferred_sections:
        for r in candidates:
            if r.get("_section") == sec:
                return r
    return candidates[0]


def _infer_rule_metadata(api: str | None, checker: str | None) -> Dict[str, Any]:
    a = (api or "").lower()
    c = (checker or "").lower()
    libc_noisy = {"malloc", "calloc", "realloc", "strdup", "fopen", "popen", "dlopen", "pthread_mutex_init"}
    if a in libc_noisy:
        return {"severity": "low", "noise_profile": "high", "default_enabled": False, "rule_priority": "auxiliary"}
    if "tls" in c or a.startswith("ssl") or a.startswith("wolfssl") or a.startswith("mbedtls") or a.startswith("rand_"):
        return {"severity": "high", "noise_profile": "low", "default_enabled": True, "rule_priority": "priority"}
    return {"severity": "medium", "noise_profile": "medium", "default_enabled": True, "rule_priority": "priority"}


def _annotate_rule_metadata(item: Dict[str, Any], rules: Dict[str, Any]) -> None:
    rule = _select_rule_for_finding(item, rules)
    inferred = _infer_rule_metadata(item.get("api"), item.get("checker"))
    item["rule_id"] = (rule or {}).get("rule_id") or item.get("rule_id")
    item["rule_library"] = (rule or {}).get("library") or item.get("rule_library")
    item["severity"] = (rule or {}).get("severity") or item.get("severity") or inferred["severity"]
    item["noise_profile"] = (rule or {}).get("noise_profile") or item.get("noise_profile") or inferred["noise_profile"]
    if "default_enabled" in (rule or {}):
        item["default_enabled"] = bool((rule or {}).get("default_enabled"))
    elif "default_enabled" not in item:
        item["default_enabled"] = bool(inferred["default_enabled"])
    item["report_priority"] = "priority" if _is_priority_finding(item) else "auxiliary"


def _is_priority_finding(item: Dict[str, Any]) -> bool:
    if item.get("default_enabled") is False:
        return False
    if item.get("noise_profile") == "high":
        return False
    if item.get("severity") == "low":
        return False
    return True

def _finding_from_python(v: Dict[str, Any], firmware_id: str | None, tpc: List[Dict[str, Any]], rules: Dict[str, Any]) -> Dict[str, Any]:
    api = v.get("api")
    return {
        "status": "potential_usage_violation",
        "firmware_id": firmware_id,
        "binary": v.get("binary"),
        "function": v.get("function"),
        "call_addr": v.get("call_addr"),
        "api": api,
        "checker": v.get("kind"),
        "reason": v.get("reason"),
        "expected": v.get("expected"),
        "rule_source": v.get("source"),
        "llm_rule_confidence": _rule_confidence(api, rules),
        "tpc_candidates": tpc,
        "binary_evidence": {
            "call_instruction": v.get("call_instruction"),
            "check_instruction": v.get("check_instruction"),
            "branch_instruction": v.get("branch_instruction"),
            "observed_following_calls": v.get("observed_following_calls"),
        },
        "review_recommendation": "Review the call site in a disassembler/source if available; UVScanX reports potential usage violations, not confirmed CVEs.",
    }



def _append_symbol_results(findings: List[Dict[str, Any]], observations: List[Dict[str, Any]], binary: Path, firmware_id: str | None, meta: Dict[str, Any], rules: Dict[str, Any], tpc: List[Dict[str, Any]]) -> None:
    for item in _symbol_observations(binary, firmware_id, meta, rules, tpc):
        if item.get("status") == "potential_usage_violation":
            findings.append(item)
        else:
            observations.append(item)

def _symbol_observations(binary: Path, firmware_id: str | None, meta: Dict[str, Any], rules: Dict[str, Any], tpc: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    names = {normalize_api(s) for s in (meta.get("dynamic_symbols") or []) + (meta.get("symbols") or [])}
    names = {n for n in names if n}
    out: List[Dict[str, Any]] = []
    api_set = apis_from_rules(rules)
    present = sorted(api_set & names)
    for api in present:
        # Deprecated API can be flagged from symbols alone; other classes need control-flow evidence.
        dep = any(normalize_api(r.get("api")) == api for r in rules.get("deprecated", []))
        if dep:
            out.append({
                "status": "potential_usage_violation",
                "firmware_id": firmware_id,
                "binary": str(binary),
                "api": api,
                "checker": "deprecated_api_symbol",
                "reason": "deprecated API appears in the symbol table/imports",
                "tpc_candidates": tpc,
                "binary_evidence": {"machine": meta.get("machine"), "symbols": [api]},
                "review_recommendation": "Confirm whether the deprecated API is actually called; symbol evidence alone may include unused imports.",
            })
        else:
            out.append(_observation(binary, firmware_id, "evidence_insufficient", f"API {api} is present, but this architecture/static state has no supported call-site checker yet", tpc, meta, api=api))
    # Coarse cross-architecture causality evidence: if a binary imports/exports the
    # start and sink APIs but the required API is absent, report a symbol-level
    # potential violation. This is weaker than call-site Datalog evidence but useful
    # for real ARM/MIPS firmware where ddisasm call recovery is unavailable.
    for r in rules.get("causality", []):
        api = normalize_api(r.get("api"))
        must = normalize_api(r.get("must_call_after"))
        before = normalize_api(r.get("before"))
        if api and must and api in names and must not in names and (not before or before in names):
            out.append({
                "status": "potential_usage_violation",
                "firmware_id": firmware_id,
                "binary": str(binary),
                "function": None,
                "call_addr": None,
                "api": api,
                "checker": "causality_violation_symbol",
                "reason": f"binary has {api}" + (f" and {before}" if before else "") + f" but no symbol/import for required {must}",
                "expected": r.get("expected"),
                "rule_source": r.get("source"),
                "llm_rule_confidence": r.get("llm_confidence"),
                "tpc_candidates": tpc,
                "binary_evidence": {"machine": meta.get("machine"), "present_symbols": sorted([x for x in (api, before) if x]), "missing_symbol": must, "engine": "symbol-datalog-crossarch"},
                "review_recommendation": "Confirm call order in Ghidra/ddisasm for this architecture; symbol-level evidence is a potential usage violation, not a confirmed CVE.",
            })

    if not present and meta.get("dynamic_symbols") == []:
        out.append(_observation(binary, firmware_id, "no_dynamic_symbols", "No dynamic symbols found; stripped/static binaries need deeper recovery before usage-rule checks", tpc, meta))
    return out


def _observation(binary: Path, firmware_id: str | None, kind: str, reason: str, tpc: List[Dict[str, Any]], meta: Dict[str, Any], api: str | None = None) -> Dict[str, Any]:
    return {
        "status": "needs_review",
        "firmware_id": firmware_id,
        "binary": str(binary),
        "api": api,
        "checker": kind,
        "reason": reason,
        "tpc_candidates": tpc,
        "binary_evidence": {"machine": meta.get("machine"), "file": meta.get("file"), "needed_libraries": meta.get("needed_libraries", [])},
        "review_recommendation": "Use ddisasm/Ghidra or add architecture-specific call-site rules for confirmation.",
    }



def _infer_component_from_api(api: str | None) -> Dict[str, Any] | None:
    if not api:
        return None
    a = api.lower()
    if a.startswith("ssl_") or a.startswith("asn1_") or a.startswith("rand_") or a.startswith("x509"):
        return {"name": "OpenSSL", "version": "unknown", "confidence": 0.55, "evidence": [f"API prefix indicates OpenSSL-family API: {api}; no version string was recovered from this binary evidence"]}
    if a.startswith("sqlite3_"):
        return {"name": "SQLite", "version": "unknown", "confidence": 0.55, "evidence": [f"API prefix indicates SQLite API: {api}"]}
    if a.startswith("pcap_"):
        return {"name": "libpcap", "version": "unknown", "confidence": 0.55, "evidence": [f"API prefix indicates libpcap API: {api}"]}
    if a.startswith("curl_"):
        return {"name": "libcurl", "version": "unknown", "confidence": 0.55, "evidence": [f"API prefix indicates libcurl API: {api}"]}
    if a.startswith("xml"):
        return {"name": "libxml2", "version": "unknown", "confidence": 0.55, "evidence": [f"API prefix indicates libxml2 API: {api}"]}
    if a.startswith("mbedtls_"):
        return {"name": "mbedTLS", "version": "unknown", "confidence": 0.55, "evidence": [f"API prefix indicates mbedTLS API: {api}"]}
    if a.startswith("wolfssl"):
        return {"name": "wolfSSL", "version": "unknown", "confidence": 0.55, "evidence": [f"API prefix indicates wolfSSL API: {api}"]}
    if a.startswith("upnp"):
        return {"name": "libupnp", "version": "unknown", "confidence": 0.55, "evidence": [f"API prefix indicates libupnp API: {api}"]}
    if a in {"fopen", "fclose", "malloc", "calloc", "realloc", "strdup", "free", "dlopen", "dlclose", "popen", "pclose", "pthread_mutex_init", "pthread_mutex_destroy"}:
        return {"name": "uClibc / glibc", "version": "unknown", "confidence": 0.45, "evidence": [f"API is a common C runtime API: {api}"]}
    if a.startswith("sshbuf_") or a.startswith("sshkey_"):
        return {"name": "OpenSSH", "version": "unknown", "confidence": 0.45, "evidence": [f"API prefix indicates OpenSSH internal API: {api}"]}
    if a.startswith("demo_"):
        return {"name": "synthetic regression fixture", "version": "not applicable", "confidence": 1.0, "evidence": [f"Synthetic demo API: {api}"]}
    return None


def _ensure_tpc_candidate(item: Dict[str, Any]) -> None:
    if item.get("tpc_candidates"):
        return
    inferred = _infer_component_from_api(item.get("api"))
    if inferred:
        item["tpc_candidates"] = [inferred]


def _tpc_label(item: Dict[str, Any]) -> str:
    comps = item.get("tpc_candidates") or []
    if not comps:
        return "unknown"
    labels = []
    for c in comps[:3]:
        name = c.get("name") or "unknown"
        ver = c.get("version") or "unknown"
        labels.append(f"{name} {ver}")
    return "; ".join(labels)

def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = ["status", "firmware_id", "report_priority", "severity", "noise_profile", "default_enabled", "rule_id", "rule_library", "binary", "function", "call_addr", "api", "tpc_components", "checker", "reason", "expected", "rule_source", "llm_rule_confidence", "review_recommendation"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            rr = dict(r)
            rr["tpc_components"] = _tpc_label(r)
            w.writerow(rr)


def _write_markdown(path: Path, summary: Dict[str, Any]) -> None:
    priority = summary.get("priority_findings") or []
    auxiliary = summary.get("auxiliary_findings") or []
    lines = [
        "# UVScanX Report",
        "",
        f"Firmware: `{summary.get('firmware_id')}`",
        f"Input ELF paths: {summary.get('num_input_binaries', summary.get('num_binaries'))}",
        f"Binaries scanned: {summary.get('num_binaries')}",
        f"Duplicate ELF paths skipped: {summary.get('num_duplicate_binaries_skipped', 0)}",
        f"Priority-only non-candidates skipped: {summary.get('num_non_candidate_binaries_skipped', 0)}",
        f"Priority findings: {summary.get('num_priority_findings', len(priority))}",
        f"Auxiliary/noisy findings: {summary.get('num_auxiliary_findings', len(auxiliary))}",
        f"Total potential findings: {summary.get('num_findings')}",
        f"Observations: {summary.get('num_observations')}",
        "",
    ]
    lines.append("## Priority Potential Usage Violations")
    if not priority:
        lines.append("No priority deterministic potential usage violations were found.")
    for f in priority[:500]:
        lines.append(f"- **{f.get('checker')}** `{f.get('api')}` severity={f.get('severity')} ({_tpc_label(f)}) in `{f.get('binary')}` at `{f.get('call_addr')}`: {f.get('reason')}")
    lines.append("\n## Auxiliary / High-noise Findings")
    if not auxiliary:
        lines.append("No auxiliary findings.")
    for f in auxiliary[:500]:
        lines.append(f"- **{f.get('checker')}** `{f.get('api')}` severity={f.get('severity')} noise={f.get('noise_profile')} in `{f.get('binary')}` at `{f.get('call_addr')}`: {f.get('reason')}")
    lines.append("\n## Needs Review / Evidence Insufficient")
    for o in summary.get("observations", [])[:200]:
        lines.append(f"- `{o.get('checker')}` `{o.get('api') or ''}` in `{o.get('binary')}`: {o.get('reason')}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_html(path: Path, summary: Dict[str, Any]) -> None:
    import html
    findings = summary.get("findings", [])
    priority = summary.get("priority_findings") or findings
    auxiliary = summary.get("auxiliary_findings") or []
    observations = summary.get("observations", [])

    def esc(v: Any) -> str:
        return html.escape("" if v is None else str(v))

    def finding_row(f: Dict[str, Any]) -> str:
        evidence = f.get("binary_evidence") or {}
        badge = "danger" if f.get("severity") == "high" else "warn"
        return (
            "<tr>"
            f"<td><span class='badge {badge}'>{esc(f.get('checker'))}</span></td>"
            f"<td><code>{esc(f.get('api'))}</code></td>"
            f"<td>{esc(f.get('severity'))}</td>"
            f"<td>{esc(f.get('noise_profile'))}</td>"
            f"<td>{esc(_tpc_label(f))}</td>"
            f"<td><code>{esc(f.get('call_addr'))}</code></td>"
            f"<td class='path'>{esc(f.get('binary'))}</td>"
            f"<td>{esc(f.get('reason'))}</td>"
            f"<td><code>{esc(evidence.get('datalog_evidence') or evidence.get('branch_instruction') or evidence.get('call_instruction'))}</code></td>"
            "</tr>"
        )

    finding_rows = [finding_row(f) for f in priority]
    if not finding_rows:
        finding_rows.append("<tr><td colspan='9'>No priority potential usage violations found.</td></tr>")
    aux_rows = [finding_row(f) for f in auxiliary[:1000]]
    if not aux_rows:
        aux_rows.append("<tr><td colspan='9'>No auxiliary/high-noise findings.</td></tr>")

    obs_rows = []
    for o in observations[:200]:
        obs_rows.append(
            "<tr>"
            f"<td><span class='badge warn'>{esc(o.get('checker'))}</span></td>"
            f"<td><code>{esc(o.get('api'))}</code></td>"
            f"<td>{esc(_tpc_label(o))}</td>"
            f"<td class='path'>{esc(o.get('binary'))}</td>"
            f"<td>{esc(o.get('reason'))}</td>"
            "</tr>"
        )
    if not obs_rows:
        obs_rows.append("<tr><td colspan='5'>No evidence-insufficient observations.</td></tr>")

    raw_json = esc(json.dumps(summary, indent=2, ensure_ascii=False))
    html_text = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>UVScan Report - {esc(summary.get('firmware_id'))}</title>
<style>
:root {{ --bg:#0f172a; --panel:#111827; --card:#1f2937; --text:#e5e7eb; --muted:#9ca3af; --accent:#38bdf8; --danger:#ef4444; --warn:#f59e0b; --ok:#22c55e; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background:linear-gradient(180deg,#0f172a,#111827); color:var(--text); }}
header {{ padding:32px 40px 18px; border-bottom:1px solid #334155; }}
h1 {{ margin:0 0 8px; font-size:28px; }}
.subtitle {{ color:var(--muted); }}
main {{ padding:24px 40px 48px; }}
.cards {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:24px; }}
.card {{ background:rgba(31,41,55,.9); border:1px solid #334155; border-radius:14px; padding:18px; box-shadow:0 8px 24px rgba(0,0,0,.25); }}
.card .num {{ font-size:30px; font-weight:700; color:var(--accent); }}
.card .label {{ color:var(--muted); margin-top:4px; }}
section {{ background:rgba(17,24,39,.82); border:1px solid #334155; border-radius:14px; margin:18px 0; overflow:hidden; }}
section h2 {{ margin:0; padding:16px 18px; border-bottom:1px solid #334155; font-size:18px; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ text-align:left; vertical-align:top; padding:12px 14px; border-bottom:1px solid #273449; }}
th {{ color:#cbd5e1; background:#172033; font-weight:600; }}
tr:hover td {{ background:#172033; }}
code {{ color:#bae6fd; background:#0b1220; padding:2px 5px; border-radius:5px; }}
.path {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; color:#d1d5db; word-break:break-all; }}
.badge {{ display:inline-block; padding:4px 8px; border-radius:999px; font-size:12px; font-weight:700; white-space:nowrap; }}
.badge.danger {{ background:rgba(239,68,68,.16); color:#fecaca; border:1px solid rgba(239,68,68,.45); }}
.badge.warn {{ background:rgba(245,158,11,.16); color:#fde68a; border:1px solid rgba(245,158,11,.45); }}
details {{ padding:0; }}
summary {{ cursor:pointer; padding:16px 18px; color:#cbd5e1; }}
pre {{ margin:0; padding:18px; overflow:auto; background:#020617; color:#d1d5db; font-size:12px; line-height:1.45; }}
.footer {{ color:var(--muted); margin-top:18px; font-size:13px; }}
</style>
</head>
<body>
<header>
  <h1>UVScanX Report</h1>
  <div class="subtitle">Firmware: <code>{esc(summary.get('firmware_id'))}</code> · Engine: <code>{esc(summary.get('engine'))}</code></div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="num">{esc(summary.get('num_binaries'))}</div><div class="label">Binaries scanned</div></div>
    <div class="card"><div class="num">{esc(summary.get('num_duplicate_binaries_skipped', 0))}</div><div class="label">Duplicates skipped</div></div>
    <div class="card"><div class="num">{esc(summary.get('num_non_candidate_binaries_skipped', 0))}</div><div class="label">Non-candidates skipped</div></div>
    <div class="card"><div class="num">{esc(summary.get('num_priority_findings', len(priority)))}</div><div class="label">Priority findings</div></div>
    <div class="card"><div class="num">{esc(summary.get('num_auxiliary_findings', len(auxiliary)))}</div><div class="label">Auxiliary/noisy findings</div></div>
    <div class="card"><div class="num">{esc(summary.get('num_observations'))}</div><div class="label">Needs-review observations</div></div>
  </div>

  <section>
    <h2>Priority Potential Usage Violations</h2>
    <table>
      <thead><tr><th>Checker</th><th>API</th><th>Severity</th><th>Noise</th><th>Component / Version</th><th>Address</th><th>Binary</th><th>Reason</th><th>Evidence</th></tr></thead>
      <tbody>{''.join(finding_rows)}</tbody>
    </table>
  </section>

  <section>
    <details open>
      <summary>Auxiliary / High-noise Findings</summary>
      <table>
        <thead><tr><th>Checker</th><th>API</th><th>Severity</th><th>Noise</th><th>Component / Version</th><th>Address</th><th>Binary</th><th>Reason</th><th>Evidence</th></tr></thead>
        <tbody>{''.join(aux_rows)}</tbody>
      </table>
    </details>
  </section>

  <section>
    <h2>Needs Review / Evidence Insufficient</h2>
    <table>
      <thead><tr><th>Checker</th><th>API</th><th>Component / Version</th><th>Binary</th><th>Reason</th></tr></thead>
      <tbody>{''.join(obs_rows)}</tbody>
    </table>
  </section>

  <section>
    <details>
      <summary>Raw JSON report</summary>
      <pre>{raw_json}</pre>
    </details>
  </section>

  <div class="footer">Findings are potential usage violations, not confirmed CVEs.</div>
</main>
</body>
</html>
"""
    path.write_text(html_text, encoding="utf-8")
