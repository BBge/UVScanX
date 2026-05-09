from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .util import project_root, read_json, sha256_file, sha256_text, write_json

DEFAULT_RAG_DIR = project_root() / "data" / "rag" / "api_usage"
DEFAULT_DOCS_DIR = project_root() / "data" / "rag" / "documents"
DEFAULT_INDEX_DIR = project_root() / "data" / "rag" / "index"
SUPPORTED_DOC_SUFFIXES = {".md", ".markdown", ".txt", ".text", ".rst", ".json", ".html", ".htm", ".pdf", ".c", ".h", ".cpp", ".hpp"}


def load_documents(rag_dir: Path | None = None) -> List[Dict[str, Any]]:
    """Load curated API-usage RAG JSON documents."""
    base = rag_dir or DEFAULT_RAG_DIR
    docs: List[Dict[str, Any]] = []
    if not base.exists():
        return docs
    for path in sorted(base.glob("*.json")):
        obj = read_json(path)
        if isinstance(obj, dict):
            obj = dict(obj)
            obj.setdefault("_path", str(path))
            docs.append(obj)
    return docs


def list_libraries(rag_dir: Path | None = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for doc in load_documents(rag_dir):
        rules = doc.get("rules") or []
        out.append({
            "library": doc.get("library"),
            "component_type": doc.get("component_type"),
            "aliases": doc.get("aliases") or [],
            "num_rules": len(rules),
            "num_active_rules": sum(1 for r in rules if r.get("active")),
            "path": doc.get("_path"),
        })
    return out


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in re.findall(r"[A-Za-z0-9_./:+-]+", text) if len(t) >= 2}


def _read_text_document(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader  # type: ignore
        except Exception as exc:
            return f"[UVScanX could not extract PDF text from {path}: install pypdf. Error: {exc}]"
        reader = PdfReader(str(path))
        return "\n\n".join(page.extract_text() or "" for page in reader.pages)
    raw = path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".json":
        try:
            return json.dumps(json.loads(raw), ensure_ascii=False, indent=2)
        except Exception:
            return raw
    if suffix in {".html", ".htm"}:
        raw = re.sub(r"(?is)<(script|style).*?>.*?</\\1>", " ", raw)
        raw = re.sub(r"(?s)<[^>]+>", " ", raw)
        return html.unescape(raw)
    return raw


def iter_source_documents(docs_dir: Path | None = None) -> Iterable[Path]:
    base = docs_dir or DEFAULT_DOCS_DIR
    if not base.exists():
        return []
    return (
        p for p in sorted(base.rglob("*"))
        if p.is_file() and p.suffix.lower() in SUPPORTED_DOC_SUFFIXES and not p.name.startswith(".")
    )


def _chunk_text(text: str, chunk_size: int, overlap: int) -> List[str]:
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if not text:
        return []
    if chunk_size <= 0:
        return [text]
    overlap = max(0, min(overlap, chunk_size // 2))
    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + chunk_size)
        # Prefer a paragraph/sentence boundary near the end of the window.
        if end < len(text):
            window = text[start:end]
            cut = max(window.rfind("\n\n"), window.rfind(". "), window.rfind("。"), window.rfind("; "))
            if cut > chunk_size * 0.55:
                end = start + cut + 1
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


def build_index(docs_dir: Path | None = None, out_dir: Path | None = None, chunk_size: int = 1400, overlap: int = 180) -> Dict[str, Any]:
    """Build a simple local lexical RAG index from dropped documentation files.

    Put files under data/rag/documents/ and run `uvscanx rag index`.  The index is
    stored as JSONL chunks plus a small inverted keyword index, so it works in
    offline/local mode without a vector database.
    """
    src = docs_dir or DEFAULT_DOCS_DIR
    out = out_dir or DEFAULT_INDEX_DIR
    out.mkdir(parents=True, exist_ok=True)
    docs = list(iter_source_documents(src))
    chunks_path = out / "chunks.jsonl"
    keyword_index: Dict[str, List[str]] = {}
    manifest_docs: List[Dict[str, Any]] = []
    num_chunks = 0
    with chunks_path.open("w", encoding="utf-8") as f:
        for path in docs:
            rel = str(path.relative_to(src)) if path.is_relative_to(src) else str(path)
            text = _read_text_document(path)
            file_sha = sha256_file(path)
            chunk_ids: List[str] = []
            for i, chunk in enumerate(_chunk_text(text, chunk_size, overlap)):
                chunk_id = sha256_text(json.dumps({"path": rel, "i": i, "sha256": file_sha, "text": chunk}, ensure_ascii=False, sort_keys=True))[:24]
                rec = {
                    "id": chunk_id,
                    "source_path": str(path),
                    "relative_path": rel,
                    "chunk_index": i,
                    "text": chunk,
                    "tokens": sorted(_tokens(chunk))[:500],
                    "sha256": file_sha,
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                chunk_ids.append(chunk_id)
                for tok in _tokens(chunk):
                    if len(keyword_index.setdefault(tok, [])) < 200:
                        keyword_index[tok].append(chunk_id)
                num_chunks += 1
            manifest_docs.append({"path": str(path), "relative_path": rel, "sha256": file_sha, "num_chunks": len(chunk_ids), "chunk_ids": chunk_ids})
    write_json(out / "keyword_index.json", keyword_index)
    manifest = {
        "schema_version": "uvscanx-rag-index-v1",
        "docs_dir": str(src),
        "out_dir": str(out),
        "chunk_size": chunk_size,
        "overlap": overlap,
        "num_documents": len(manifest_docs),
        "num_chunks": num_chunks,
        "documents": manifest_docs,
    }
    write_json(out / "manifest.json", manifest)
    return manifest


def load_index_chunks(index_dir: Path | None = None) -> List[Dict[str, Any]]:
    path = (index_dir or DEFAULT_INDEX_DIR) / "chunks.jsonl"
    if not path.exists():
        return []
    chunks: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                chunks.append(obj)
    return chunks


def search_index(query: str, index_dir: Path | None = None, limit: int = 10) -> List[Dict[str, Any]]:
    qtokens = _tokens(query)
    scored: List[tuple[int, Dict[str, Any]]] = []
    qlower = query.lower()
    for chunk in load_index_chunks(index_dir):
        text = str(chunk.get("text") or "")
        toks = set(chunk.get("tokens") or []) or _tokens(text)
        score = len(qtokens & toks)
        if qlower and qlower in text.lower():
            score += 5
        if score:
            preview = re.sub(r"\s+", " ", text).strip()[:260]
            scored.append((score, {"score": score, "kind": "doc_chunk", "chunk": {**chunk, "preview": preview}}))
    scored.sort(key=lambda x: (-x[0], str((x[1].get("chunk") or {}).get("relative_path")), int((x[1].get("chunk") or {}).get("chunk_index") or 0)))
    return [x[1] for x in scored[:limit]]


def search(query: str, rag_dir: Path | None = None, limit: int = 10, include_index: bool = True, index_dir: Path | None = None) -> List[Dict[str, Any]]:
    qtokens = _tokens(query)
    scored: List[tuple[int, Dict[str, Any]]] = []
    for doc in load_documents(rag_dir):
        lib_blob = json.dumps({k: doc.get(k) for k in ("library", "aliases", "component_type", "version_hints")}, ensure_ascii=False)
        for rule in doc.get("rules") or []:
            blob = lib_blob + "\n" + json.dumps(rule, ensure_ascii=False)
            toks = _tokens(blob)
            score = len(qtokens & toks)
            lower_blob = blob.lower()
            if query.lower() in lower_blob:
                score += 5
            if score:
                scored.append((score, {
                    "score": score,
                    "kind": "api_rule",
                    "library": doc.get("library"),
                    "component_type": doc.get("component_type"),
                    "rule": rule,
                    "path": doc.get("_path"),
                }))
    if include_index:
        for item in search_index(query, index_dir=index_dir, limit=limit * 3):
            scored.append((int(item.get("score") or 0), item))
    scored.sort(key=lambda x: (-x[0], str(x[1].get("library") or (x[1].get("chunk") or {}).get("relative_path")), str((x[1].get("rule") or {}).get("id"))))
    return [x[1] for x in scored[:limit]]


def active_rules_from_rag(rag_dir: Path | None = None, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Convert active curated RAG rules into the checker JSON schema."""
    out: Dict[str, Any] = {
        "metadata": metadata or {
            "name": "UVScanX seed rules",
            "generated_by": "local RAG knowledge base",
            "note": "Rules are curated from data/rag/api_usage; LLM/RAG extraction can replace or augment them.",
        },
        "return_value": [],
        "argument": [],
        "causality": [],
        "deprecated": [],
        "resource_lifecycle": [],
    }
    key_fields = {
        "return_value": ["api", "constraint", "expected", "source", "llm_confidence", "library", "rule_id", "severity", "noise_profile", "default_enabled"],
        "argument": ["api", "arg_index", "operator", "value", "window", "expected", "source", "llm_confidence", "library", "rule_id", "severity", "noise_profile", "default_enabled"],
        "causality": ["api", "must_call_after", "must_call_before", "before", "window", "expected", "source", "llm_confidence", "library", "rule_id", "severity", "noise_profile", "default_enabled"],
        "deprecated": ["api", "expected", "source", "llm_confidence", "library", "rule_id", "severity", "noise_profile", "default_enabled"],
        "resource_lifecycle": ["open_api", "close_api", "window", "expected", "source", "llm_confidence", "library", "rule_id", "severity", "noise_profile", "default_enabled"],
    }
    for doc in load_documents(rag_dir):
        library = doc.get("library")
        for rule in doc.get("rules") or []:
            typ = rule.get("type")
            if not rule.get("active") or typ not in out:
                continue
            row: Dict[str, Any] = {
                "source": rule.get("source_url"),
                "llm_confidence": rule.get("confidence"),
                "library": library,
                "rule_id": rule.get("id"),
                "severity": rule.get("severity"),
                "noise_profile": rule.get("noise_profile"),
                "default_enabled": rule.get("default_enabled"),
            }
            for k, v in rule.items():
                if k in {"active", "type", "source_url", "confidence", "id", "evidence_summary", "tags"}:
                    continue
                row[k] = v
            row = {k: row.get(k) for k in key_fields[typ] if row.get(k) is not None}
            out[typ].append(row)
    return out
