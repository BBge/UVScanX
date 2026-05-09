from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

RuleDict = Dict[str, Any]

RULE_SECTIONS = ["return_value", "argument", "causality", "deprecated", "resource_lifecycle"]


@dataclass
class ValidationResult:
    ok: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def normalize_api(api: str | None) -> str | None:
    if not api:
        return None
    s = str(api).strip()
    for sep in ("@@", "@", "+"):
        if sep in s:
            s = s.split(sep)[0]
    if s.endswith(".plt"):
        s = s[:-4]
    return s or None


def coerce_rules(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return a canonical rules object while preserving unknown metadata."""
    out: Dict[str, Any] = {"metadata": dict(raw.get("metadata", {}))}
    for sec in RULE_SECTIONS:
        out[sec] = list(raw.get(sec, []))
    return out


def validate_rules(raw: Dict[str, Any]) -> ValidationResult:
    errors: List[str] = []
    warnings: List[str] = []
    if not isinstance(raw, dict):
        return ValidationResult(False, ["rules root must be an object"], [])
    for sec in RULE_SECTIONS:
        if sec in raw and not isinstance(raw[sec], list):
            errors.append(f"{sec} must be a list")
    for i, r in enumerate(raw.get("return_value", [])):
        if not r.get("api"):
            errors.append(f"return_value[{i}] missing api")
        if r.get("constraint") not in {"error_le_zero", "error_lt_zero", "non_null_required", "must_check"}:
            warnings.append(f"return_value[{i}] has non-standard constraint {r.get('constraint')!r}")
    for i, r in enumerate(raw.get("argument", [])):
        if not r.get("api"):
            errors.append(f"argument[{i}] missing api")
        if "arg_index" not in r:
            errors.append(f"argument[{i}] missing arg_index")
    for i, r in enumerate(raw.get("causality", [])):
        if not r.get("api"):
            errors.append(f"causality[{i}] missing api")
        if not (r.get("must_call_after") or r.get("must_call_before")):
            errors.append(f"causality[{i}] missing must_call_after/must_call_before")
    for i, r in enumerate(raw.get("deprecated", [])):
        if not r.get("api"):
            errors.append(f"deprecated[{i}] missing api")
    for i, r in enumerate(raw.get("resource_lifecycle", [])):
        if not r.get("open_api") or not r.get("close_api"):
            errors.append(f"resource_lifecycle[{i}] missing open_api/close_api")
    return ValidationResult(not errors, errors, warnings)


def python_checker_specs(rules: Dict[str, Any]) -> Dict[str, Any]:
    """Convert canonical rules to the compact schema used by the optional Python checker."""
    out = {
        "metadata": rules.get("metadata", {}),
        "return_value": list(rules.get("return_value", [])),
        "argument": list(rules.get("argument", [])),
        "causality": list(rules.get("causality", [])),
        "deprecated": list(rules.get("deprecated", [])),
    }
    for r in rules.get("resource_lifecycle", []):
        out["causality"].append({
            "api": r.get("open_api"),
            "must_call_after": r.get("close_api"),
            "window": r.get("window", 30),
            "expected": r.get("expected") or f"{r.get('close_api')} should release resources acquired by {r.get('open_api')}",
            "source": r.get("source"),
        })
    return out


def apis_from_rules(rules: Dict[str, Any]) -> set[str]:
    apis: set[str] = set()
    for r in rules.get("return_value", []):
        if normalize_api(r.get("api")): apis.add(normalize_api(r.get("api")))  # type: ignore[arg-type]
    for r in rules.get("argument", []):
        if normalize_api(r.get("api")): apis.add(normalize_api(r.get("api")))  # type: ignore[arg-type]
    for r in rules.get("deprecated", []):
        if normalize_api(r.get("api")): apis.add(normalize_api(r.get("api")))  # type: ignore[arg-type]
    for r in rules.get("causality", []):
        for k in ("api", "must_call_after", "must_call_before", "before"):
            if normalize_api(r.get(k)): apis.add(normalize_api(r.get(k)))  # type: ignore[arg-type]
    for r in rules.get("resource_lifecycle", []):
        for k in ("open_api", "close_api", "alloc_api", "free_api"):
            if normalize_api(r.get(k)): apis.add(normalize_api(r.get(k)))  # type: ignore[arg-type]
    return apis
