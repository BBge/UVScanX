from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from .schemas import normalize_api
from .util import run


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def iter_elfs(paths: Sequence[Path]) -> Iterable[Path]:
    for p in paths:
        if p.is_dir():
            for c in sorted(p.rglob("*")):
                if c.is_file() and is_elf(c):
                    yield c
        elif p.is_file() and is_elf(p):
            yield p


def readelf_header(path: Path) -> Dict[str, str]:
    cp = run(["readelf", "-h", str(path)], check=False)
    info: Dict[str, str] = {}
    for line in cp.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    return info


def file_info(path: Path) -> str:
    cp = run(["file", "-b", str(path)], check=False)
    return cp.stdout.strip() or cp.stderr.strip()


def symbols(path: Path, dynamic: bool = True) -> List[str]:
    args = ["readelf", "-Ws" if not dynamic else "--dyn-syms", str(path)]
    cp = run(args, check=False)
    names: List[str] = []
    for line in cp.stdout.splitlines():
        # Num: Value Size Type Bind Vis Ndx Name
        parts = line.split()
        if len(parts) < 8 or not parts[0].rstrip(":").isdigit():
            continue
        name = parts[-1]
        n = normalize_api(name)
        if n and n not in names:
            names.append(n)
    return names


def needed_libraries(path: Path) -> List[str]:
    cp = run(["readelf", "-d", str(path)], check=False)
    libs: List[str] = []
    for m in re.finditer(r"Shared library: \[([^\]]+)\]", cp.stdout):
        libs.append(m.group(1))
    return libs


def strings_sample(path: Path, limit: int = 400, min_len: int = 5) -> List[str]:
    cp = run(["strings", f"-n{min_len}", str(path)], timeout=60, check=False)
    out: List[str] = []
    interesting = re.compile(r"openssl|sqlite|libpcap|libcurl|busybox|zlib|ssl_|ssl\b|pcap_|sqlite3_|curl_|version|copyright", re.I)
    for line in cp.stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        if interesting.search(s) or len(out) < 50:
            out.append(s[:300])
        if len(out) >= limit:
            break
    return out


def elf_metadata(path: Path) -> Dict[str, Any]:
    header = readelf_header(path)
    dyn = symbols(path, dynamic=True)
    # Only read static/full symbols when dynsym is tiny; it can be expensive on large files.
    full = [] if len(dyn) > 20 else symbols(path, dynamic=False)
    return {
        "path": str(path),
        "file": file_info(path),
        "class": header.get("Class"),
        "data": header.get("Data"),
        "machine": header.get("Machine"),
        "type": header.get("Type"),
        "needed_libraries": needed_libraries(path),
        "dynamic_symbols": dyn[:2000],
        "symbols": full[:2000],
        "strings_sample": strings_sample(path),
    }


def is_x86_64(meta: Dict[str, Any]) -> bool:
    machine = (meta.get("machine") or "").lower()
    return "x86-64" in machine or "advanced micro devices x86-64" in machine
