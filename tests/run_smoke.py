from pathlib import Path
import json
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from uvscanx.rules import extract_rules
from uvscanx.schemas import validate_rules, python_checker_specs
from uvscanx.elf import iter_elfs
from uvscanx.tpc import identify
from uvscanx.scanner import scan
from uvscanx.firmware import load_manifest, select_entries, download
from uvscanx.rag import build_index, search_index


def main() -> int:
    import subprocess
    root = Path(__file__).resolve().parents[1]
    subprocess.run([str(root / "scripts" / "build_synthetic.sh")], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        rules = extract_rules([], tmp / "rules.json")
        assert validate_rules(rules).ok
        assert any(r["api"] == "SSL_write" for r in rules["return_value"])
        assert any(r["api"] == "sqlite3_open" for r in python_checker_specs(rules)["causality"])

        bins = list(iter_elfs([Path("examples/synthetic/bin")]))
        assert bins, "regression binaries missing; run scripts/build_synthetic.sh"
        docs = tmp / "rag_docs"
        docs.mkdir()
        (docs / "libfoo.md").write_text("libfoo_open returns NULL on failure. Call libfoo_close to release handles.", encoding="utf-8")
        idx = build_index(docs, tmp / "rag_index", chunk_size=80, overlap=10)
        assert idx["num_chunks"] >= 1
        assert search_index("libfoo_close", tmp / "rag_index")

        tpc = identify([Path("examples/synthetic/bin")], tmp / "tpc", limit=2)
        assert tpc["num_binaries"] >= 1
        summary = scan([Path("examples/synthetic/bin")], tmp / "scan", firmware_id="synthetic-test", engine="datalog")
        assert summary["num_binaries"] >= 10
        assert summary["num_findings"] >= 8
        assert list((tmp / "scan" / "datalog").glob("*/facts/binary_arch.facts"))
        assert list((tmp / "scan" / "datalog").glob("*/facts/api_call.facts"))

        m = load_manifest()
        full = select_entries(m, "full")
        assert len([e for e in full if e["device_type"] == "router"]) >= 2
        assert len([e for e in full if e["device_type"] == "camera"]) >= 2
        src = tmp / "sample.bin"
        src.write_bytes(b"firmware")
        manifest = tmp / "manifest.json"
        manifest.write_text(json.dumps({"firmware": [{"id":"local", "device_type":"router", "url":"https://example.invalid/x", "local_path":str(src), "filename":"sample.bin", "profiles":["smoke"]}]}), encoding="utf-8")
        dl = download(manifest, tmp / "fw", profile="smoke")
        assert dl["firmware"][0]["status"] in {"copied", "exists"}
    print("smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
