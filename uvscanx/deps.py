from __future__ import annotations

import os
import sys
from pathlib import Path


def local_prefix() -> Path:
    return Path(__file__).resolve().parents[1] / "tools" / "local"


def activate_local_deps() -> None:
    """Activate non-root dependencies extracted under tools/local.

    The development environment used for firmware experiments may not have sudo
    or pip.  We therefore support Debian packages extracted with dpkg-deb -x into
    tools/local and make their binaries/libs/Python modules visible to UVScanX.
    """
    prefix = local_prefix()
    if not prefix.exists():
        return
    bin_dir = prefix / "usr" / "bin"
    lib_dir = prefix / "usr" / "lib" / "x86_64-linux-gnu"
    py_dir = prefix / "usr" / "lib" / "python3" / "dist-packages"
    user_bin = Path.home() / ".local" / "bin"
    path_parts = []
    if bin_dir.exists():
        path_parts.append(str(bin_dir))
    if user_bin.exists():
        path_parts.append(str(user_bin))
    if path_parts:
        os.environ["PATH"] = os.pathsep.join(path_parts) + os.pathsep + os.environ.get("PATH", "")
    if lib_dir.exists():
        os.environ["LD_LIBRARY_PATH"] = f"{lib_dir}{os.pathsep}" + os.environ.get("LD_LIBRARY_PATH", "")
    if py_dir.exists():
        if str(py_dir) not in sys.path:
            sys.path.insert(0, str(py_dir))
        os.environ["PYTHONPATH"] = f"{py_dir}{os.pathsep}" + os.environ.get("PYTHONPATH", "")
    # Some extracted Python extension packages load shared libraries by soname
    # (for example capstone loads libcapstone.so.4).  Loading by absolute path
    # first makes those imports work even when LD_LIBRARY_PATH was not present at
    # Python process startup.
    cap = lib_dir / "libcapstone.so.4"
    if cap.exists():
        try:
            import ctypes

            ctypes.CDLL(str(cap), mode=getattr(ctypes, "RTLD_GLOBAL", 0))
        except Exception:
            pass
