#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEBS="$ROOT/tools/debs"
LOCAL="$ROOT/tools/local"
mkdir -p "$DEBS" "$LOCAL"
cd "$DEBS"
apt-get download \
  binutils-arm-linux-gnueabi binutils-arm-linux-gnueabihf binutils-aarch64-linux-gnu \
  binutils-mipsel-linux-gnu binutils-mips-linux-gnu \
  python3-pyelftools python3-capstone python3-pypdf libcapstone4 \
  binwalk python3-binwalk 7zip p7zip p7zip-full || true
for deb in ./*.deb; do
  [ -e "$deb" ] || continue
  dpkg-deb -x "$deb" "$LOCAL"
done
# Ubuntu's extracted 7z wrapper points to /usr/lib/7zip; rewrite it for local use.
if [ -x "$LOCAL/usr/lib/7zip/7z" ]; then
  cat > "$LOCAL/usr/bin/7z" <<'EOF'
#! /bin/sh
DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../lib/7zip" && pwd)"
export LD_LIBRARY_PATH="$(CDPATH= cd -- "$(dirname -- "$0")/../lib/x86_64-linux-gnu" 2>/dev/null && pwd):$LD_LIBRARY_PATH"
exec "$DIR/7z" "$@"
EOF
  chmod +x "$LOCAL/usr/bin/7z"
fi
if ! python3 -m pip --version >/dev/null 2>&1; then
  mkdir -p "$ROOT/tools/bootstrap"
  curl -L https://bootstrap.pypa.io/get-pip.py -o "$ROOT/tools/bootstrap/get-pip.py"
  python3 "$ROOT/tools/bootstrap/get-pip.py" --user --break-system-packages
fi
python3 -m pip install --user --break-system-packages ubi-reader jefferson unblob || true
cat <<EOF
[UVScanX] local deps installed under $LOCAL and ~/.local/bin.
[UVScanX] UVScanX auto-activates these paths via uvscanx/deps.py.
EOF
