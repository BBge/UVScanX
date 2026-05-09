import json
from pathlib import Path

from uvscanx.firmware import load_manifest, select_entries, download


def test_manifest_profiles():
    m = load_manifest()
    full = select_entries(m, "full")
    assert len(full) >= 20
    assert len([e for e in full if e["device_type"] == "router"]) >= 2
    assert len([e for e in full if e["device_type"] == "camera"]) >= 2


def test_download_local_manifest(tmp_path):
    src = tmp_path / "sample.bin"
    src.write_bytes(b"firmware")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"firmware": [{
        "id": "local-sample", "device_type": "router", "url": "https://example.invalid/sample.bin",
        "local_path": str(src), "filename": "sample.bin", "profiles": ["smoke"]
    }]}), encoding="utf-8")
    obj = download(manifest, tmp_path / "out", profile="smoke", force=False)
    rec = obj["firmware"][0]
    assert rec["status"] in {"copied", "exists"}
    assert Path(rec["path"]).read_bytes() == b"firmware"
