#!/usr/bin/env bash
set -euo pipefail

# UVScanX repository hygiene guard. Source/rules/RAG seeds/tests/manifests
# belong in git; generated firmware/rootfs/analysis outputs do not.  The hook
# checks staged content so local ignored test data can remain on disk while you
# continue development.

MAX_BYTES=$((5 * 1024 * 1024))
ALLOWED_LARGE_RE='^examples/firmware/dlink-dir880l-a1-1\.07/DIR-880L_A1_FW_1\.07\.zip$'
SECRET_RE='sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY'
FORBIDDEN_RE='^(runs/|data/firmware/|data/rootfs/|data/rootfs-[^/]+/|data/rootfs-unblob-[^/]+/|tools/|artifacts/|archive_unrelated/|examples/synthetic/bin/)'

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  mapfile -t staged_files < <(git diff --cached --name-only --diff-filter=ACMR)

  echo "[check] forbidden generated paths staged"
  if ((${#staged_files[@]})); then
    if printf '%s\n' "${staged_files[@]}" | grep -E "$FORBIDDEN_RE"; then
      echo "[error] generated/test data is staged"
      exit 1
    fi
  fi

  echo "[check] staged files >5M"
  too_large=0
  for f in "${staged_files[@]}"; do
    if [ -f "$f" ]; then
      size=$(wc -c < "$f")
      if [ "$size" -gt "$MAX_BYTES" ] && ! [[ "$f" =~ $ALLOWED_LARGE_RE ]]; then
        printf '%s %s bytes\n' "$f" "$size"
        too_large=1
      fi
    fi
  done
  if [ "$too_large" -ne 0 ]; then
    echo "[error] large staged files found; do not commit firmware/rootfs/runs artifacts"
    exit 1
  fi

  echo "[check] secret-like tokens in staged text files"
  secret_hit=0
  for f in "${staged_files[@]}"; do
    if [ -f "$f" ]; then
      if grep -IEn "$SECRET_RE" -- "$f"; then
        secret_hit=1
      fi
    fi
  done
  if [ "$secret_hit" -ne 0 ]; then
    echo "[error] potential secret found in staged content"
    exit 1
  fi
else
  echo "[check] large files >5M"
  large_files="$(find . -type f -size +5M -not -path './.git/*' || true)"
  if [ -n "$large_files" ]; then
    echo "$large_files"
    echo "[error] large files found"
    exit 1
  fi
fi

echo "[ok] precommit check passed"
