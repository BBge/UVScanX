from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .elf import elf_metadata, iter_elfs
from .llm import LLMClient
from .util import safe_name, write_json


def identify(paths: Sequence[Path], out: Path, llm: LLMClient | None = None, limit: int = 200) -> Dict[str, Any]:
    client = llm or LLMClient()
    out.mkdir(parents=True, exist_ok=True)
    binaries = list(iter_elfs(paths))[:limit]
    results: List[Dict[str, Any]] = []
    for p in binaries:
        meta = elf_metadata(p)
        evidence = {
            "path": str(p),
            "file": meta.get("file"),
            "machine": meta.get("machine"),
            "needed_libraries": meta.get("needed_libraries", []),
            "symbols": (meta.get("dynamic_symbols") or meta.get("symbols") or [])[:250],
            "strings_sample": meta.get("strings_sample", [])[:120],
        }
        prompt = "Identify third-party components and versions in this firmware ELF evidence. Return JSON: {components:[{name,version,confidence,evidence:[]}]}\n" + json.dumps(evidence, ensure_ascii=False, indent=2)
        guess = client.json_completion("tpc.identify", prompt)
        results.append({"binary": str(p), "evidence": evidence, "llm": guess})
        write_json(out / "per_binary" / f"{safe_name(str(p))}.json", results[-1])
    summary = summarize(results)
    obj = {"num_binaries": len(binaries), "binaries": results, "components": summary}
    write_json(out / "tpc_summary.json", obj)
    return obj


def summarize(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_name: Dict[str, Dict[str, Any]] = {}
    for r in results:
        for c in r.get("llm", {}).get("components", []):
            name = c.get("name")
            if not name:
                continue
            item = by_name.setdefault(name, {"name": name, "versions": {}, "max_confidence": 0.0, "evidence_count": 0, "binaries": []})
            ver = c.get("version") or "unknown"
            item["versions"][ver] = item["versions"].get(ver, 0) + 1
            item["max_confidence"] = max(item["max_confidence"], float(c.get("confidence") or 0))
            item["evidence_count"] += len(c.get("evidence") or [])
            item["binaries"].append(r.get("binary"))
    return sorted(by_name.values(), key=lambda x: (-x["max_confidence"], x["name"]))
