from __future__ import annotations

import json
import shutil
import tarfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from .util import ensure_dir, project_root, run, safe_name, sha256_file, write_json

DEFAULT_MANIFEST = project_root() / "data" / "manifests" / "firmware_manifest.json"


def load_manifest(path: Path | None = None) -> Dict[str, Any]:
    p = path or DEFAULT_MANIFEST
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def select_entries(manifest: Dict[str, Any], profile: str = "smoke", device_type: str | None = None) -> List[Dict[str, Any]]:
    entries = list(manifest.get("firmware", []))
    if profile != "all":
        entries = [e for e in entries if profile in e.get("profiles", [])]
    if device_type:
        entries = [e for e in entries if e.get("device_type") == device_type]
    return entries



def _resolve_entry_url(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Optionally refresh firmware URL from a vendor page before download.

    The manifest still records a stable URL for traceability, but camera vendor pages
    frequently rotate asset links. For Hikvision DS-2CD samples we can re-parse the
    official firmware page and prefer a link matching the requested version.
    """
    if entry.get("resolver") != "hikvision_ds2cd":
        return entry
    page = entry.get("source_page")
    if not page:
        return entry
    try:
        req = urllib.request.Request(page, headers={"User-Agent": "uvscanx/0.1"})
        html = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "ignore")
        import re
        links = re.findall(r"https://assets\.hikvision\.com/[^\"']+?\.zip", html)
        version = str(entry.get("firmware_version") or "").replace("Firmware_", "").replace("V", "")
        chosen = None
        if version:
            chosen = next((u for u in links if version in u), None)
        chosen = chosen or next((u for u in links if "Firmware__" in u or "Firmware_" in u), None)
        if chosen:
            updated = dict(entry)
            updated["url"] = chosen
            updated["resolved_url_from_page"] = page
            return updated
    except Exception:
        return entry
    return entry

def _safe_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    path = urllib.parse.quote(parts.path, safe="/%")
    query = urllib.parse.quote(parts.query, safe="=&%:/?+")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))


def download(manifest_path: Path | None, out_dir: Path, profile: str = "smoke", force: bool = False) -> Dict[str, Any]:
    manifest = load_manifest(manifest_path)
    entries = select_entries(manifest, profile)
    ensure_dir(out_dir)
    results: List[Dict[str, Any]] = []
    for e in entries:
        e = _resolve_entry_url(e)
        filename = e.get("filename") or Path(urllib.parse.urlsplit(e["url"]).path).name or f"{e['id']}.bin"
        dest = out_dir / filename
        status = "exists"
        error = None
        try:
            if e.get("local_path"):
                src = (project_root() / e["local_path"]).resolve()
                if not dest.exists() or force:
                    shutil.copy2(src, dest)
                    status = "copied"
            elif not dest.exists() or force:
                headers = {"User-Agent": "uvscanx/0.1"}
                if e.get("source_page"):
                    # Some vendor CDNs (notably camera firmware portals) reject
                    # direct GET requests without the support-page referer even
                    # though HEAD works.  Keep the manifest source_page as the
                    # traceable origin and use it for downloads when present.
                    headers["Referer"] = str(e["source_page"])
                req = urllib.request.Request(_safe_url(e["url"]), headers=headers)
                with urllib.request.urlopen(req, timeout=120) as r, dest.open("wb") as f:
                    shutil.copyfileobj(r, f)
                status = "downloaded"
            digest = sha256_file(dest) if dest.exists() else None
            if e.get("sha256") and digest != e.get("sha256"):
                status = "sha256_mismatch"
                error = f"expected {e.get('sha256')}, got {digest}"
        except Exception as exc:
            status = "error"
            error = str(exc)
            digest = None
        rec = dict(e)
        rec.update({"path": str(dest), "status": status, "sha256_actual": digest, "error": error})
        results.append(rec)
    obj = {"profile": profile, "output_dir": str(out_dir), "num_selected": len(entries), "firmware": results}
    write_json(out_dir / "download_report.json", obj)
    return obj


def unpack(inputs: Sequence[Path], out_dir: Path, recursive: bool = True) -> Dict[str, Any]:
    ensure_dir(out_dir)
    results: List[Dict[str, Any]] = []
    queue: List[Path] = []
    for p in inputs:
        if p.is_dir():
            queue.extend([c for c in sorted(p.iterdir()) if c.is_file()])
        elif p.is_file():
            queue.append(p)
    seen: set[Path] = set()
    while queue:
        p = queue.pop(0).resolve()
        if p in seen:
            continue
        seen.add(p)
        target = ensure_dir(out_dir / safe_name(p.stem or p.name))
        rec = {"input": str(p), "output": str(target), "steps": [], "status": "ok", "error": None}
        try:
            extracted = _unpack_one(p, target, rec["steps"])
            if recursive:
                for child in extracted:
                    if child.is_file() and child.stat().st_size > 0 and _should_recurse_archive(child):
                        queue.append(child)
        except Exception as exc:
            rec["status"] = "error"
            rec["error"] = str(exc)
        results.append(rec)
    obj = {"output_dir": str(out_dir), "items": results}
    write_json(out_dir / "unpack_report.json", obj)
    return obj


def _looks_archive(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".bin", ".trx", ".img", ".dav"}:
        return True
    try:
        with path.open("rb") as f:
            sample = f.read(4096)
        magic = sample[:8]
        return magic.startswith(b"hsqs") or magic.startswith(b"sqsh") or magic.startswith(b"UBI#") or (not magic.startswith(b"\x7fELF") and b"hsqs" in sample)
    except Exception:
        return False


def _should_recurse_archive(path: Path) -> bool:
    # Do not recursively re-process UVScanX-created SquashFS tails.  The same
    # image is already tried in-place by _try_squashfs_extract; queueing it again
    # can create embedded_0/embedded_0/... loops.
    if path.name.startswith("embedded_") and path.suffix.lower() in {".squashfs", ".sqfs"}:
        return False
    # Binwalk extraction directories often contain synthetic copies named like
    # 0.squashfs/0.ubi; recursively queueing every synthetic copy can explode.
    # We still preserve the files for analysis; we just avoid unpack-looping them
    # unless the user invokes uvscanx firmware unpack on that exact file.
    if any(part == "binwalk" or part.endswith(".extracted") for part in path.parts):
        return False
    if any(part.startswith("ubi-images-") for part in path.parts):
        return False
    # For top-level user inputs, a .bin suffix is treated as firmware.  Inside an
    # extracted rootfs, however, many ordinary data files also end in .bin
    # (kernel module indexes, Wi-Fi blobs, calibration data).  Only recurse into
    # nested .bin files when they contain an actual filesystem/container magic.
    if path.suffix.lower() == ".bin":
        try:
            with path.open("rb") as f:
                sample = f.read(1024 * 1024)
        except Exception:
            return False
        if not any(m in sample for m in (b"UBI#", b"hsqs", b"sqsh")):
            return False
    return _looks_archive(path)


def _unpack_one(path: Path, target: Path, steps: List[Dict[str, Any]]) -> List[Path]:
    before = set(target.rglob("*")) if target.exists() else set()
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            z.extractall(target)
        steps.append({"tool": "python.zipfile", "status": "ok"})
    elif tarfile.is_tarfile(path):
        with tarfile.open(path) as t:
            t.extractall(target)
        steps.append({"tool": "python.tarfile", "status": "ok"})
    elif _try_squashfs_extract(path, target, steps):
        pass
    elif _try_ubireader(path, target, steps):
        pass
    elif _try_unblob(path, target, steps):
        pass
    elif _try_binwalk(path, target, steps):
        pass
    else:
        shutil.copy2(path, target / path.name)
        steps.append({"tool": "copy", "status": "fallback", "note": "no extractor recognized this file"})
    after = set(target.rglob("*"))
    return [p for p in sorted(after - before) if p.is_file()]


def _squashfs_offsets(path: Path) -> List[int]:
    """Return likely SquashFS offsets in a firmware blob.

    Standard SquashFS magic may appear as either little-endian ``hsqs`` or
    big-endian ``sqsh``.  Some vendor images contain more than one candidate, so
    return all unique offsets rather than only the first match.
    """
    offsets: List[int] = []
    with path.open("rb") as f:
        data = f.read()
    for magic in (b"hsqs", b"sqsh"):
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            offsets.append(idx)
            start = idx + 4
    return sorted(set(offsets))


def _run_squashfs_tool(tool: str, image: Path, dest: Path, timeout: int = 600):
    """Run unsquashfs/sasquatch with the shared command-line shape."""
    return run([tool, "-d", str(dest), str(image)], timeout=timeout)


def _try_squashfs_extract(path: Path, target: Path, steps: List[Dict[str, Any]]) -> bool:
    tools = [t for t in ("unsquashfs", "sasquatch") if shutil.which(t)]
    if not tools:
        return False
    ensure_dir(target)

    # Prefer the distro unsquashfs first for normal images.  Use sasquatch as a
    # second attempt for vendor-modified SquashFS variants common in routers.
    last_stderr = ""
    for tool in tools:
        dest = target / f"{tool}-root"
        cp = _run_squashfs_tool(tool, path, dest)
        last_stderr = cp.stderr[-1000:]
        ok = (cp.returncode == 0 or dest.exists()) and any(dest.rglob("*"))
        steps.append({"tool": tool, "status": "ok" if ok else "failed", "stderr": last_stderr})
        if ok:
            return True

    # Many router firmware images contain an embedded SquashFS at a non-zero
    # offset.  Slice each candidate tail and try both standard unsquashfs and
    # sasquatch.  This is deliberately before binwalk so UVScanX records the
    # exact extraction tool and offset in its unpack report.
    try:
        for off in _squashfs_offsets(path):
            embedded = target / f"embedded_{off}.squashfs"
            with path.open("rb") as src, embedded.open("wb") as dst:
                src.seek(off)
                shutil.copyfileobj(src, dst)
            for tool in tools:
                dest = target / f"{tool}-root-{off}"
                cp = _run_squashfs_tool(tool, embedded, dest)
                ok = (cp.returncode == 0 or dest.exists()) and any(dest.rglob("*"))
                steps.append({
                    "tool": tool,
                    "status": "ok" if ok else "failed",
                    "offset": off,
                    "image": str(embedded),
                    "stderr": cp.stderr[-1000:],
                })
                if ok:
                    return True
    except Exception as exc:
        steps.append({"tool": "squashfs", "status": "failed", "error": str(exc), "stderr": last_stderr})
    return False


def _try_ubireader(path: Path, target: Path, steps: List[Dict[str, Any]]) -> bool:
    files_tool = shutil.which("ubireader_extract_files")
    images_tool = shutil.which("ubireader_extract_images")
    if not files_tool and not images_tool:
        return False
    try:
        with path.open("rb") as f:
            data = f.read(8 * 1024 * 1024)
        offsets = []
        start = 0
        while True:
            off = data.find(b"UBI#", start)
            if off < 0:
                break
            offsets.append(off)
            start = off + 4
        if not offsets:
            return False
        for off in offsets[:4]:
            if files_tool:
                dest = target / f"ubi-root-{off}"
                cp = run([files_tool, "-o", str(dest), "-s", str(off), str(path)], timeout=600)
                ok = cp.returncode == 0 and dest.exists() and any(p.is_file() for p in dest.rglob("*"))
                steps.append({"tool": "ubireader_extract_files", "status": "ok" if ok else "failed", "offset": off, "stderr": cp.stderr[-1000:]})
                if ok:
                    return True

            # Some TP-Link firmwares wrap a SquashFS volume in UBI.  In that
            # case ubireader_extract_files creates only empty volume
            # directories; extract the raw volume image and pass it through the
            # SquashFS toolchain.
            if images_tool:
                img_dest = target / f"ubi-images-{off}"
                cp_img = run([images_tool, "-o", str(img_dest), "-s", str(off), str(path)], timeout=600)
                image_files = [p for p in img_dest.rglob("*") if p.is_file()] if img_dest.exists() else []
                img_ok = cp_img.returncode == 0 and bool(image_files)
                steps.append({"tool": "ubireader_extract_images", "status": "ok" if img_ok else "failed", "offset": off, "stderr": cp_img.stderr[-1000:]})
                if img_ok:
                    extracted_any = False
                    for img in image_files[:8]:
                        img_extract_target = target / f"{safe_name(img.stem)}-root"
                        if _try_squashfs_extract(img, img_extract_target, steps):
                            extracted_any = True
                    return extracted_any or img_ok
    except Exception as exc:
        steps.append({"tool": "ubireader_extract_files", "status": "failed", "error": str(exc)})
    return False

def _try_unblob(path: Path, target: Path, steps: List[Dict[str, Any]]) -> bool:
    if not shutil.which("unblob"):
        return False
    dest = target / "unblob"
    cp = run(["unblob", "-e", str(dest), str(path)], timeout=600)
    extracted_files = [p for p in dest.rglob("*") if p.is_file()] if dest.exists() else []
    ok = cp.returncode == 0 and bool(extracted_files)
    steps.append({
        "tool": "unblob",
        "status": "ok" if ok else "failed",
        "extracted_files": len(extracted_files),
        "stderr": cp.stderr[-1000:],
    })
    return ok


def _try_binwalk(path: Path, target: Path, steps: List[Dict[str, Any]]) -> bool:
    if not shutil.which("binwalk"):
        return False
    dest = target / "binwalk"
    dest.mkdir(exist_ok=True)
    cp = run(["binwalk", "-e", "--directory", str(dest), str(path)], timeout=600)
    steps.append({"tool": "binwalk", "status": "ok" if cp.returncode == 0 else "failed", "stderr": cp.stderr[-1000:]})
    return cp.returncode == 0
