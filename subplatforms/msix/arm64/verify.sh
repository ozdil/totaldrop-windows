#!/bin/sh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Isolated sub-platform artifact & provenance verifier for `windows-msix-arm64` (ADR 0020).

set -eu

UNIT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$UNIT_DIR/../../.." && pwd)
RECIPE="$UNIT_DIR/RECIPE.toml"
WORKFLOW="$REPO_ROOT/.github/workflows/pkg-msix-arm64.yml"
ARTIFACT_NAME="TotalDrop_0.1.1.0_arm64.msix"

if [ "${1:-}" = "--check-recipe" ]; then
  [ -f "$RECIPE" ] || { echo "missing $RECIPE" >&2; exit 1; }
  [ -f "$WORKFLOW" ] || { echo "missing workflow $WORKFLOW" >&2; exit 1; }
  sh -n "$UNIT_DIR/build.sh"
  sh -n "$UNIT_DIR/verify.sh"
  grep -q 'windows-msix-arm64-v\*' "$WORKFLOW"
  echo "verify check ok: windows-msix-arm64"
  exit 0
fi

ART_DIR="${1:?usage: verify.sh [--check-recipe | <artifact-dir>]}"
MSIX_PATH="$ART_DIR/$ARTIFACT_NAME"
[ -f "$MSIX_PATH" ] || { echo "missing artifact $MSIX_PATH" >&2; exit 1; }
[ -s "$MSIX_PATH" ] || { echo "empty artifact $MSIX_PATH" >&2; exit 1; }
[ -f "$ART_DIR/SHA256SUMS" ] || { echo "missing $ART_DIR/SHA256SUMS" >&2; exit 1; }
(cd "$ART_DIR" && sha256sum -c SHA256SUMS)

python3 - "$MSIX_PATH" <<'PY'
import sys, zipfile, xml.etree.ElementTree as ET
from pathlib import Path

msix = Path(sys.argv[1])
magic = msix.read_bytes()[:4]
if magic != b"PK\x03\x04":
    raise SystemExit(f"error: {msix.name} is not a real OPC/ZIP MSIX (magic={magic!r})")
with zipfile.ZipFile(msix, "r") as zf:
    bad = zf.testzip()
    if bad is not None:
        raise SystemExit(f"error: corrupt ZIP entry {bad}")
    names = set(zf.namelist())
    required = {
        "AppxManifest.xml",
        "AppxBlockMap.xml",
        "[Content_Types].xml",
        "resources.pri",
        "totaldrop-winui.exe",
        "totaldrop_windows_ffi.dll",
    }
    missing = sorted(required - names)
    if missing:
        raise SystemExit(f"error: MSIX missing entries: {missing}")
    root = ET.fromstring(zf.read("AppxManifest.xml"))
    ident = root.find("{http://schemas.microsoft.com/appx/manifest/foundation/windows10}Identity")
    if ident is None:
        raise SystemExit("error: AppxManifest.xml missing Identity")
    if ident.attrib.get("ProcessorArchitecture") != "arm64":
        raise SystemExit(f"error: expected ProcessorArchitecture=arm64, got {ident.attrib.get('ProcessorArchitecture')!r}")
    if ident.attrib.get("Version") != "0.1.1.0":
        raise SystemExit(f"error: expected Version=0.1.1.0, got {ident.attrib.get('Version')!r}")
PY

echo "artifact verified: $MSIX_PATH"
