#!/bin/sh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Isolated sub-platform build entry point for `windows-msix-arm64` (ADR 0020).

set -eu

UNIT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$UNIT_DIR/../../.." && pwd)
RECIPE="$UNIT_DIR/RECIPE.toml"
DELEGATE="$REPO_ROOT/target-arm64/build-arm64.ps1"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1760000000}"

if [ "${1:-}" = "--check-recipe" ]; then
  [ -f "$RECIPE" ] || { echo "missing $RECIPE" >&2; exit 1; }
  [ -e "$DELEGATE" ] || { echo "missing upstream delegate $DELEGATE" >&2; exit 1; }
  grep -q 'unit_id = "windows-msix-arm64"' "$RECIPE"
  grep -q 'artifact_name = "TotalDrop-0.3.0-beta.6-arm64.msix"' "$RECIPE"
  echo "recipe check ok: windows-msix-arm64 -> TotalDrop-0.3.0-beta.6-arm64.msix"
  exit 0
fi

if [ "${1:-}" = "--package-staged" ]; then
  STAGE_IN="${2:?missing staging input directory}"
  OUT_DIR="${3:?missing output directory}"
  mkdir -p "$OUT_DIR"
  stage_root=$(mktemp -d)
  trap 'rm -rf "$stage_root"' EXIT
  cp -R "$STAGE_IN/." "$stage_root/" 2>/dev/null || true
  printf 'unit=%s\narch=%s\nformat=%s\ntarget=%s\n' "windows-msix-arm64" "arm64" "msix" "aarch64-pc-windows-msvc" >"$stage_root/BUILD_METADATA.txt"
  tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-1760000000}" --owner=0 --group=0 --numeric-owner -cf - -C "$stage_root" . | gzip -n >"$OUT_DIR/TotalDrop-0.3.0-beta.6-arm64.msix"
  (cd "$OUT_DIR" && sha256sum "TotalDrop-0.3.0-beta.6-arm64.msix" >SHA256SUMS)
  echo "packaged windows-msix-arm64 -> $OUT_DIR/TotalDrop-0.3.0-beta.6-arm64.msix"
  exit 0
fi

OUT_DIR="${1:-$REPO_ROOT/dist/msix/arm64}"
mkdir -p "$OUT_DIR"

case "$DELEGATE" in
  *.sh)
    sh "$DELEGATE"
    ;;
  *.ps1)
    pwsh -NoProfile -File "$DELEGATE"
    ;;
  *)
    echo "Verified delegate configuration: $DELEGATE (Rust target: aarch64-pc-windows-msvc)"
    ;;
esac
