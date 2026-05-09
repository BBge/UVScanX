from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List

from .util import ensure_dir, read_json, sha256_text, write_json


class LLMClient:
    """Small OpenAI-compatible JSON client with deterministic offline fallback."""

    def __init__(self, model: str | None = None, cache_dir: Path | None = None, mock: bool | None = None):
        self.model = model or os.getenv("UVSCAN_LLM_MODEL", "gpt-4o-mini")
        self.cache_dir = ensure_dir(cache_dir or Path(os.getenv("UVSCAN_CACHE_DIR", "runs/cache/llm")))
        self.mock = bool(mock) if mock is not None else not bool(os.getenv("OPENAI_API_KEY"))

    def json_completion(self, task: str, prompt: str, schema_hint: str = "Return JSON only.") -> Dict[str, Any]:
        key = sha256_text(json.dumps({"task": task, "model": self.model, "prompt": prompt, "schema": schema_hint}, sort_keys=True))
        cache_path = self.cache_dir / f"{key}.json"
        if cache_path.exists():
            return read_json(cache_path)
        if self.mock:
            result = self._mock(task, prompt)
        else:
            result = self._call_openai(prompt, schema_hint)
        write_json(cache_path, result)
        return result

    def _call_openai(self, prompt: str, schema_hint: str) -> Dict[str, Any]:
        try:
            from openai import OpenAI  # type: ignore
        except Exception as exc:
            raise RuntimeError("openai package is not installed; install requirements or unset OPENAI_API_KEY for mock mode") from exc
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"), base_url=os.getenv("OPENAI_BASE_URL") or None)
        resp = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You extract firmware-analysis facts. Return strict JSON only, with no markdown."},
                {"role": "user", "content": f"{schema_hint}\n\n{prompt}"},
            ],
            temperature=0,
        )
        text = resp.choices[0].message.content or "{}"
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            m = re.search(r"\{.*\}", text, re.S)
            if not m:
                raise
            return json.loads(m.group(0))

    def _mock(self, task: str, prompt: str) -> Dict[str, Any]:
        if task == "rules.extract":
            return mock_rules()
        if task == "tpc.identify":
            return {"components": heuristic_components(prompt), "mode": "mock"}
        return {"mode": "mock", "result": {}}


def mock_rules() -> Dict[str, Any]:
    """Return deterministic offline seed rules from the local RAG store.

    This keeps mock/no-API behavior aligned with the curated RAG knowledge base
    instead of maintaining a separate hard-coded rule copy in Python.
    """
    try:
        from .rag import active_rules_from_rag

        return active_rules_from_rag(metadata={
            "name": "UVScanX seed rules",
            "generated_by": "local RAG knowledge base / mock offline extractor",
            "note": "Deterministic fallback equivalent to LLM+RAG extraction; replace with cached API output when OPENAI_API_KEY is set.",
        })
    except Exception:
        # Tiny safety fallback used only if project data files are unavailable.
        return {
            "metadata": {"name": "UVScanX minimal fallback rules", "generated_by": "mock/offline extractor"},
            "return_value": [
                {"api": "SSL_write", "constraint": "error_le_zero", "expected": "Treat return <= 0 as error; success is > 0.", "source": "OpenSSL SSL_write documentation", "llm_confidence": 0.95},
                {"api": "SSL_read", "constraint": "error_le_zero", "expected": "Treat return <= 0 as error; success is > 0.", "source": "OpenSSL SSL_read documentation", "llm_confidence": 0.95},
            ],
            "argument": [],
            "causality": [],
            "deprecated": [],
            "resource_lifecycle": [],
        }


def heuristic_components(prompt: str) -> List[Dict[str, Any]]:
    """Deterministic TPC name guesser used when no LLM API key is set.

    It consumes the same local RAG documents as rule extraction: aliases provide
    library/component fingerprints, and a small symbol-prefix map catches common
    stripped-firmware evidence.  It intentionally does not infer versions.
    """
    low = prompt.lower()
    comps: List[Dict[str, Any]] = []

    def add(name: str, confidence: float, evidence: str) -> None:
        for c in comps:
            if c.get("name") == name:
                c.setdefault("evidence", []).append(evidence)
                c["confidence"] = max(float(c.get("confidence") or 0), confidence)
                return
        comps.append({"name": name, "confidence": confidence, "evidence": [evidence]})

    try:
        from .rag import load_documents
        rag_docs = load_documents()
    except Exception:
        rag_docs = []

    # RAG aliases and known symbol prefixes.  Application components such as
    # dnsmasq/dropbear are identified as components, not API-misuse rules.
    symbol_map = {
        "OpenSSL": ["ssl_write", "ssl_read", "ssl_connect", "rand_pseudo_bytes", "libssl", "libcrypto", "openssl"],
        "SQLite": ["sqlite3_open", "sqlite3_close", "libsqlite", "sqlite version"],
        "libpcap": ["pcap_activate", "pcap_open", "libpcap"],
        "libcurl": ["curl_easy", "curl_slist", "libcurl", "curl_global"],
        "libxml2": ["xmlreadfile", "xmlreadmemory", "xmlfreedoc", "xmlgetprop", "libxml2", "xmlparsefile"],
        "mbedTLS": ["mbedtls_ssl", "mbedtls_x509", "libmbedtls", "libmbedcrypto", "mbed tls"],
        "wolfSSL": ["wolfssl_read", "wolfssl_write", "wolfssl_new", "libwolfssl", "wolfssl"],
        "OpenSSH": ["openssh_", "sshd", "sshkey_", "sshbuf_", "ssh-keygen"],
        "uClibc / glibc": ["glibc_", "gnu c library", "uclibc", "ld-uclibc", "libc.so"],
        "libupnp": ["upnpinit", "upnpregister", "upnpfinish", "libupnp", "portable sdk for upnp"],
        "dnsmasq": ["dnsmasq", "dnsmasq version"],
        "dropbear": ["dropbear", "dropbearmulti", "dbclient"],
        "BusyBox": ["busybox"],
        "zlib": ["inflate", "deflate", "libz.so", "zlib"],
    }
    existing_names = {c["name"] for c in comps}
    for doc in rag_docs:
        name = str(doc.get("library") or "")
        symbol_map.setdefault(name, [])
        for alias in doc.get("aliases") or []:
            a = str(alias).strip().lower()
            if a and a not in symbol_map[name]:
                symbol_map[name].append(a)
    for name, needles in symbol_map.items():
        if name in existing_names:
            continue
        hits = [n for n in needles if n and n.lower() in low]
        if hits:
            add(name, 0.68, f"matched symbols/paths/aliases: {', '.join(hits[:8])}")
            existing_names.add(name)
    return comps
