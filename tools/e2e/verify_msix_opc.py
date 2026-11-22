#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Pure-Python stdlib OPC/ZIP MSIX, resources.pri & subplatform container oracle.

Implements TEST_INFRA.md section 5.2 and cross-platform/windows-ci checks for
T1-F04-03, T1-F04-04, T1-F04-05, T2-F04-04, T2-F04-05, T1-F06-04, T1-F06-05,
T2-F06-01, T2-F06-02, T2-F06-03, and T2-F06-04.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CANONICAL_35_LOCALES: tuple[str, ...] = (
    "ar", "bn", "cs", "da", "de", "el", "en", "es", "fa", "fi",
    "fr", "he", "hi", "hu", "id", "it", "ja", "ko", "ms", "nb",
    "nl", "pl", "pt-BR", "pt-PT", "ro", "ru", "sv", "sw", "th", "tr",
    "uk", "ur", "vi", "zh-Hans", "zh-Hant",
)

REQUIRED_PRI_RESOURCE_KEYS: tuple[str, ...] = (
    "appTagline",
    "sendTitle",
    "receiveTitle",
    "desktopSendWith",
    "keepAwakeReason",
)


def resolve_recipe_artifact_name(repo_root: Path, arch: str = "x86_64") -> tuple[str, str]:
    """Read artifact_name and expected MSIX version from subplatforms/msix/<arch>/RECIPE.toml."""
    recipe_arch = "x86_64" if arch in ("x64", "x86_64") else "arm64"
    recipe_path = repo_root / "subplatforms" / "msix" / recipe_arch / "RECIPE.toml"
    data = tomllib.loads(recipe_path.read_text(encoding="utf-8"))
    artifact_name = data.get("artifact_name")
    if not isinstance(artifact_name, str) or not artifact_name.endswith(".msix"):
        raise ValueError(f"{recipe_path}: invalid or missing artifact_name: {artifact_name!r}")
    parts = artifact_name.split("_")
    msix_version = parts[1] if len(parts) >= 3 else "0.1.1.0"
    return artifact_name, msix_version


def verify_pri_bytes(pri_data: bytes, label: str = "resources.pri") -> None:
    if len(pri_data) <= 4096:
        raise ValueError(f"{label}: undersized PRI ({len(pri_data)} bytes <= 4096)")
    if pri_data[:8] != b"mrm_pri2":
        raise ValueError(f"{label}: invalid PRI magic {pri_data[:8]!r} (expected b'mrm_pri2')")


def verify_pri_file(pri_path: Path) -> None:
    if not pri_path.is_file():
        raise ValueError(f"missing PRI file: {pri_path}")
    verify_pri_bytes(pri_path.read_bytes(), label=pri_path.name)


def verify_pri_dump(pri_xml_path: Path) -> None:
    """Verify MakePri.exe XML dump contains all 35 BCP-47 languages and Kose asset qualifiers."""
    if not pri_xml_path.is_file():
        raise ValueError(f"missing pri.xml dump: {pri_xml_path}")
    tree = ET.parse(pri_xml_path)
    root = tree.getroot()

    # Collect language qualifiers per NamedResource and globally under Resources subtrees.
    lang_by_resource: dict[str, set[str]] = {}
    all_langs: set[str] = set()
    square44_quals: set[str] = set()
    asset_scales: set[str] = set()
    asset_targetsizes: set[str] = set()

    for nr in root.iter("NamedResource"):
        name = nr.attrib.get("name", "")
        langs: set[str] = set()
        for cand in nr.findall("Candidate"):
            quals_raw = cand.attrib.get("qualifiers", "")
            for part in quals_raw.split(";"):
                part = part.strip()
                if "=" not in part:
                    continue
                k, v = part.split("=", 1)
                k_up = k.strip().upper()
                v_clean = v.strip()
                if k_up == "LANGUAGE":
                    langs.add(v_clean.lower())
                    all_langs.add(v_clean.lower())
                elif k_up == "SCALE":
                    asset_scales.add(v_clean)
                elif k_up == "TARGETSIZE":
                    asset_targetsizes.add(v_clean)
                elif k_up == "ALTERNATEFORM":
                    if "square44x44logo" in name.lower():
                        square44_quals.add(v_clean.upper())
            if "square44x44logo" in name.lower():
                up_q = quals_raw.upper()
                if "LIGHTUNPLATED" in up_q:
                    square44_quals.add("LIGHTUNPLATED")
                if "ALTERNATEFORM=UNPLATED" in up_q or up_q.endswith("UNPLATED"):
                    square44_quals.add("UNPLATED")
        if name:
            lang_by_resource.setdefault(name, set()).update(langs)

    expected_lower = {tag.lower(): tag for tag in CANONICAL_35_LOCALES}
    missing_global = [orig for low, orig in sorted(expected_lower.items()) if low not in all_langs]
    if missing_global:
        present_count = len(expected_lower) - len(missing_global)
        raise ValueError(
            f"pri.xml language count mismatch ({present_count} != 35); missing: {missing_global}"
        )

    for key in REQUIRED_PRI_RESOURCE_KEYS:
        key_langs = lang_by_resource.get(key)
        if not key_langs:
            # MakePri may nest keys as Resources/<key>
            for res_name, r_langs in lang_by_resource.items():
                if res_name.endswith(f"/{key}") or res_name == key:
                    key_langs = r_langs
                    break
        if not key_langs:
            raise ValueError(f"pri.xml missing expected NamedResource key: {key}")
        missing_key = [orig for low, orig in sorted(expected_lower.items()) if low not in key_langs]
        if missing_key:
            raise ValueError(
                f"pri.xml key {key!r} missing languages ({35 - len(missing_key)} != 35): {missing_key}"
            )

    missing_scales = [s for s in ("100", "125", "150", "200", "400") if s not in asset_scales]
    if missing_scales:
        raise ValueError(f"pri.xml missing Scale asset candidates: {missing_scales}")
    missing_ts = [s for s in ("16", "24", "32", "48", "256") if s not in asset_targetsizes]
    if missing_ts:
        raise ValueError(f"pri.xml missing TargetSize asset candidates: {missing_ts}")
    for alt in ("UNPLATED", "LIGHTUNPLATED"):
        if alt not in square44_quals:
            raise ValueError(f"pri.xml Square44x44Logo.png missing AlternateForm={alt}")


def verify_msix_archive(
    msix_path: Path,
    arch: str = "x64",
    milestone: str = "M1",
    expect_signed: bool = False,
    pri_dump: Path | None = None,
) -> None:
    if not msix_path.is_file():
        raise ValueError(f"MSIX file not found: {msix_path}")
    raw_head = msix_path.read_bytes()[:4]
    if raw_head != b"PK\x03\x04":
        raise ValueError(
            f"{msix_path.name}: not a valid OPC/ZIP MSIX (magic={raw_head!r}, expected b'PK\\x03\\x04')"
        )

    expected_arch = "x64" if arch in ("x64", "x86_64") else "arm64"
    with zipfile.ZipFile(msix_path, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise ValueError(f"{msix_path.name}: corrupt ZIP member {bad!r}")

        names = zf.namelist()
        # Store ANSI-only path invariant (0x20..=0x7E) — T2-F06-04
        for member in names:
            if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in member):
                raise ValueError(
                    f"{msix_path.name}: non-ASCII ZIP entry violates Store ANSI-only path rule: {member!r}"
                )

        name_set = set(names)
        required = {
            "AppxManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
            "resources.pri",
            "totaldrop-winui.exe",
            "totaldrop_windows_ffi.dll",
        }
        if expect_signed:
            required.add("AppxSignature.p7x")
        missing = sorted(required - name_set)
        if missing:
            raise ValueError(f"{msix_path.name}: missing required OPC/MSIX entries: {missing}")

        if expect_signed and zf.getinfo("AppxSignature.p7x").file_size <= 0:
            raise ValueError(f"{msix_path.name}: AppxSignature.p7x is empty")

        asset_pngs = [n for n in names if n.startswith("Assets/") and n.lower().endswith(".png")]
        if not asset_pngs:
            raise ValueError(f"{msix_path.name}: missing Assets/*.png entries")

        # Validate AppxBlockMap.xml uses SHA-256
        blockmap_xml = zf.read("AppxBlockMap.xml").decode("utf-8", errors="replace")
        if "sha256" not in blockmap_xml.lower():
            raise ValueError(f"{msix_path.name}: AppxBlockMap.xml does not declare SHA-256 hash method")

        # Validate resources.pri magic and size
        verify_pri_bytes(zf.read("resources.pri"), label=f"{msix_path.name}:resources.pri")

        # Validate AppxManifest.xml identity & processor architecture
        root = ET.fromstring(zf.read("AppxManifest.xml"))
        appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
        ident = root.find(f"{appx_ns}Identity")
        if ident is None:
            raise ValueError(f"{msix_path.name}: AppxManifest.xml missing <Identity>")
        if ident.attrib.get("ProcessorArchitecture") != expected_arch:
            raise ValueError(
                f"{msix_path.name}: ProcessorArchitecture={ident.attrib.get('ProcessorArchitecture')!r} "
                f"!= expected {expected_arch!r}"
            )
        _ = milestone  # Reserved for M3+ extension checks

    if pri_dump is not None:
        verify_pri_dump(pri_dump)


def _create_valid_fixture_msix(target_path: Path, version: str, arch: str = "x64") -> None:
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">\n'
        f'  <Identity Name="TotalDrop.TotalDrop" Publisher="CN=TotalDrop" Version="{version}" '
        f'ProcessorArchitecture="{arch}" />\n'
        "</Package>\n"
    ).encode("utf-8")
    blockmap = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
        'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"></BlockMap>\n'
    ).encode("utf-8")
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>\n'
    ).encode("utf-8")
    pri = b"mrm_pri2" + (b"\x00" * 4100)
    with zipfile.ZipFile(target_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AppxManifest.xml", manifest)
        zf.writestr("AppxBlockMap.xml", blockmap)
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("resources.pri", pri)
        zf.writestr("totaldrop-winui.exe", b"MZ" + b"\x00" * 64)
        zf.writestr("totaldrop_windows_ffi.dll", b"MZ" + b"\x00" * 64)
        zf.writestr("Assets/StoreLogo.scale-100.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)


def _write_sha256sums(art_dir: Path, filename: str) -> None:
    digest = hashlib.sha256((art_dir / filename).read_bytes()).hexdigest()
    (art_dir / "SHA256SUMS").write_text(f"{digest}  {filename}\n", encoding="utf-8")


def run_cross_platform_tests(repo_root: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    artifact_name, msix_version = resolve_recipe_artifact_name(repo_root, "x86_64")
    build_sh = repo_root / "subplatforms" / "msix" / "x86_64" / "build.sh"
    verify_sh = repo_root / "subplatforms" / "msix" / "x86_64" / "verify.sh"

    def record(test_id: str, fn: Any) -> None:
        try:
            detail = fn()
            results[test_id] = {"status": "PASS", "detail": detail or "ok"}
        except Exception as exc:  # noqa: BLE001
            results[test_id] = {"status": "FAIL", "detail": str(exc)}

    def t1_f06_05() -> str:
        p_check = subprocess.run(
            ["sh", str(build_sh), "--check-recipe"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if p_check.returncode != 0:
            raise AssertionError(f"build.sh --check-recipe failed: {p_check.stdout}\n{p_check.stderr}")

        with tempfile.TemporaryDirectory(prefix="td-f06-05-") as tmp:
            tmp_root = Path(tmp)
            art_dir = tmp_root / "art"
            art_dir.mkdir()
            msix_path = art_dir / artifact_name
            _create_valid_fixture_msix(msix_path, msix_version, arch="x64")
            _write_sha256sums(art_dir, artifact_name)
            verify_msix_archive(msix_path, arch="x64", milestone="M1", expect_signed=False)

            p_ver = subprocess.run(
                ["sh", str(verify_sh), str(art_dir)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if p_ver.returncode != 0:
                raise AssertionError(f"verify.sh failed on valid OPC fixture: {p_ver.stdout}\n{p_ver.stderr}")

            empty_stage = tmp_root / "empty_stage"
            empty_stage.mkdir()
            out_dir = tmp_root / "out"
            p_empty = subprocess.run(
                ["sh", str(build_sh), "--package-staged", str(empty_stage), str(out_dir)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if p_empty.returncode == 0:
                raise AssertionError("build.sh --package-staged unexpectedly succeeded on empty staging dir")
        return f"verified recipe ({artifact_name}), verify.sh PASS on OPC fixture, build.sh refuses empty stage"

    def t2_f06_01() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f06-01-") as tmp:
            art_dir = Path(tmp)
            fake_msix = art_dir / artifact_name
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w") as tf:
                    info = tarfile.TarInfo("AppxManifest.xml")
                    payload = b"<Package/>"
                    info.size = len(payload)
                    tf.addfile(info, io.BytesIO(payload))
            data = buf.getvalue()
            assert data[:2] == b"\x1f\x8b"
            fake_msix.write_bytes(data)
            _write_sha256sums(art_dir, artifact_name)

            p = subprocess.run(
                ["sh", str(verify_sh), str(art_dir)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if p.returncode == 0:
                raise AssertionError("verify.sh accepted gzip tarball masquerading as .msix!")

            try:
                verify_msix_archive(fake_msix, arch="x64", milestone="M1")
            except ValueError:
                pass
            else:
                raise AssertionError("verify_msix_archive accepted gzip tarball!")
        return "gzipped tarball (1F 8B) rejected by both verify.sh and verify_msix_archive"

    def t2_f06_02() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f06-02-") as tmp:
            art_dir = Path(tmp)
            empty_zip = art_dir / artifact_name
            with zipfile.ZipFile(empty_zip, "w"):
                pass
            assert empty_zip.read_bytes()[:4] == b"PK\x05\x06"
            _write_sha256sums(art_dir, artifact_name)

            p = subprocess.run(
                ["sh", str(verify_sh), str(art_dir)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if p.returncode == 0:
                raise AssertionError("verify.sh accepted empty non-OPC ZIP (PK\\x05\\x06)!")

            try:
                verify_msix_archive(empty_zip, arch="x64", milestone="M1")
            except ValueError:
                pass
            else:
                raise AssertionError("verify_msix_archive accepted empty ZIP!")
        return "empty ZIP (50 4B 05 06) rejected by both verify.sh and verify_msix_archive"

    def t2_f06_03() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f06-03-") as tmp:
            art_dir = Path(tmp)
            msix_path = art_dir / artifact_name
            _create_valid_fixture_msix(msix_path, msix_version, arch="x64")
            _write_sha256sums(art_dir, artifact_name)
            raw = bytearray(msix_path.read_bytes())
            raw[-1] ^= 0x01
            msix_path.write_bytes(bytes(raw))

            p = subprocess.run(
                ["sh", str(verify_sh), str(art_dir)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if p.returncode == 0:
                raise AssertionError("verify.sh did not reject 1-byte tampered MSIX after SHA256SUMS!")
        return "1-byte MSIX tampering caught by SHA256SUMS verification"

    def t2_f06_04() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f06-04-") as tmp:
            msix_path = Path(tmp) / artifact_name
            _create_valid_fixture_msix(msix_path, msix_version, arch="x64")
            with zipfile.ZipFile(msix_path, "a") as zf:
                zf.writestr("Assets/k\u00f6\u015fe.png", b"\x89PNG\r\n\x1a\n")
            try:
                verify_msix_archive(msix_path, arch="x64", milestone="M1")
            except ValueError as exc:
                if "non-ascii" not in str(exc).lower() and "ansi" not in str(exc).lower():
                    raise AssertionError(f"unexpected rejection reason: {exc}") from exc
            else:
                raise AssertionError("non-ASCII ZIP entry Assets/kose-utf8.png was NOT rejected!")
        return "non-ASCII internal MSIX ZIP entry rejected (Store ANSI-only rule)"

    record("T1-F06-05", t1_f06_05)
    record("T2-F06-01", t2_f06_01)
    record("T2-F06-02", t2_f06_02)
    record("T2-F06-03", t2_f06_03)
    record("T2-F06-04", t2_f06_04)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OPC/ZIP MSIX, resources.pri, and subplatform verifier.")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="Repository root.")
    parser.add_argument("--msix", type=Path, default=None, help="Path to .msix archive to verify.")
    parser.add_argument("--arch", choices=("x64", "x86_64", "arm64"), default="x64")
    parser.add_argument("--milestone", choices=("M1", "M2"), default="M2")
    parser.add_argument("--expect-signed", action="store_true")
    parser.add_argument("--pri-dump", type=Path, default=None, help="Path to MakePri.exe XML dump.")
    parser.add_argument("--check-pri-file", type=Path, default=None, help="Verify standalone resources.pri file.")
    parser.add_argument("--resolve-recipe", action="store_true", help="Print artifact_name from RECIPE.toml.")
    parser.add_argument("--run-tests", action="store_true", help="Run cross-platform F06 tests (T1-F06-05, T2-F06-01..04).")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        if args.resolve_recipe:
            name, _ver = resolve_recipe_artifact_name(args.root, args.arch)
            print(name)
            return 0
        if args.run_tests:
            results = run_cross_platform_tests(args.root)
            if args.json_out is not None:
                args.json_out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            failed = [k for k, v in results.items() if v["status"] != "PASS"]
            for k, v in sorted(results.items()):
                print(f"[{v['status']}] {k}: {v['detail']}")
            return 1 if failed else 0
        if args.check_pri_file is not None:
            verify_pri_file(args.check_pri_file)
            print(f"verify_msix_opc PRI OK: {args.check_pri_file}")
            return 0
        if args.msix is not None:
            verify_msix_archive(
                args.msix,
                arch=args.arch,
                milestone=args.milestone,
                expect_signed=args.expect_signed,
                pri_dump=args.pri_dump,
            )
            print(f"verify_msix_opc MSIX OK: {args.msix}")
            return 0
        if args.pri_dump is not None:
            verify_pri_dump(args.pri_dump)
            print(f"verify_msix_opc PRI dump OK: {args.pri_dump}")
            return 0
        parser.error("specify one of --msix, --check-pri-file, --pri-dump, --resolve-recipe, or --run-tests")
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
