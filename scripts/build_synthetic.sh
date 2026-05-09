#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/examples/synthetic"
BIN="$SRC/bin"
mkdir -p "$BIN"
for s in "$SRC"/*.s; do
  [ -e "$s" ] || continue
  base="$(basename "$s" .s)"
  as --64 "$s" -o "$BIN/$base.o"
  ld "$BIN/$base.o" -o "$BIN/$base"
  rm -f "$BIN/$base.o"
  echo "built $BIN/$base"
done
