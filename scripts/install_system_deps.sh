#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

sudo apt-get update
sudo apt-get install -y \
  build-essential git ca-certificates curl wget file \
  binutils binutils-multiarch \
  binutils-arm-linux-gnueabi binutils-arm-linux-gnueabihf \
  binutils-aarch64-linux-gnu binutils-mipsel-linux-gnu binutils-mips-linux-gnu \
  python3-pip python3-venv python3-pyelftools python3-capstone python3-pypdf \
  squashfs-tools p7zip-full unzip xz-utils bzip2 gzip tar \
  binwalk python3-binwalk \
  zlib1g-dev liblzma-dev liblzo2-dev

python3 -m pip install --user --break-system-packages -r "$ROOT/requirements.txt" 'typer>=0.12' ubi-reader jefferson

if ! command -v sasquatch >/dev/null 2>&1; then
  mkdir -p "$ROOT/tools/src"
  if [ ! -d "$ROOT/tools/src/sasquatch/.git" ]; then
    git clone --depth 1 https://github.com/devttys0/sasquatch.git "$ROOT/tools/src/sasquatch"
  fi
  cd "$ROOT/tools/src/sasquatch"
  ./build.sh || true
  cd "$ROOT/tools/src/sasquatch/squashfs4.3/squashfs-tools"
  perl -0pi -e 's/\s-Wall\s-Werror\s/# -Wall -Werror disabled by UVScanX bootstrap /' Makefile
  perl -0pi -e 's/CFLAGS \?= -g -O2/CFLAGS ?= -g -O2 -fcommon/' Makefile
  make clean >/dev/null 2>&1 || true
  make -j"$(nproc)"
  sudo make install
fi

printf '[UVScanX] system deps ready. sasquatch=%s\n' "$(command -v sasquatch || true)"
