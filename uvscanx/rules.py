from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .llm import LLMClient, mock_rules
from .schemas import coerce_rules, validate_rules
from .util import project_root, read_json, write_json
from .rag import load_documents, load_index_chunks

DEFAULT_RULES = project_root() / "data" / "rules" / "api_rules.json"
DEFAULT_DOCS = project_root() / "data" / "docs"


def seed_rules() -> Dict[str, Any]:
    return mock_rules()


def load_rules(path: Path | None = None) -> Dict[str, Any]:
    p = path or DEFAULT_RULES
    if p.exists():
        rules = read_json(p)
    else:
        rules = seed_rules()
    res = validate_rules(rules)
    if not res.ok:
        raise ValueError("invalid rules: " + "; ".join(res.errors))
    return coerce_rules(rules)


def extract_rules(docs: Iterable[Path] | None = None, out: Path | None = None, llm: LLMClient | None = None) -> Dict[str, Any]:
    docs = list(docs or DEFAULT_DOCS.glob("*.md"))
    snippets: List[str] = []
    for p in docs:
        if p.exists() and p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            snippets.append(f"# SOURCE: {p}\n{text[:12000]}")
    rag_docs = load_documents()
    for doc in rag_docs:
        # RAG docs are curated, compact JSON; include them as retrieval context for
        # LLM rule extraction while leaving the source files as the persistent KB.
        snippets.append(f"# RAG: {doc.get('library')} ({doc.get('component_type')})\n" + json.dumps(doc, ensure_ascii=False)[:12000])
    for chunk in load_index_chunks()[:120]:
        snippets.append(
            f"# INDEXED_DOC_CHUNK: {chunk.get('relative_path')}#{chunk.get('chunk_index')} id={chunk.get('id')}\n"
            + str(chunk.get('text') or '')[:4000]
        )
    if not snippets:
        snippets.append("No local documentation/RAG was provided; use known UVScanX seed APIs.")
    prompt = """
Extract third-party library API usage rules for firmware binary analysis.
Return JSON with keys: metadata, return_value, argument, causality, deprecated, resource_lifecycle.
Use constraints error_le_zero, error_lt_zero, non_null_required, must_check when applicable.
Each rule must include api/open_api/close_api, expected, source, and llm_confidence.
Prefer active=true RAG rules when RAG documents are present; component_only/configuration_heuristic entries are context and should not become checker rules.

DOCUMENTS_AND_RAG_CONTEXT:
""" + "\n\n".join(snippets)
    client = llm or LLMClient()
    rules = client.json_completion("rules.extract", prompt)
    rules = coerce_rules(rules)
    res = validate_rules(rules)
    if not res.ok:
        raise ValueError("LLM returned invalid rules: " + "; ".join(res.errors))
    target = out or DEFAULT_RULES
    write_json(target, rules)
    return rules
