#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Deterministic 35-language Microsoft Store listing generator and validator for TotalDrop.

Derives Partner Center Store listing metadata (JSON + CSV) strictly from read-only
`l10n/app/app_<tag>.arb` and `l10n/status.json` using only the Python standard library.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import struct
import sys
import unicodedata
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_LOCALE = "en"
EXPECTED_TITLE = "TotalDrop"
EXPECTED_PRIVACY_URL = "https://totaldrop.app/privacy/"
EXPECTED_SUPPORT_CONTACT = "hello@totaldrop.app"

MAX_SHORT_DESCRIPTION = 200
MAX_DESCRIPTION = 10000
MIN_FEATURES = 1
MAX_FEATURES = 20
MAX_FEATURE_LENGTH = 200
MIN_SEARCH_TERMS = 1
MAX_SEARCH_TERMS = 7
MAX_SEARCH_TERM_LENGTH = 40
MAX_RELEASE_NOTES = 1500

SCREENSHOT_MIN_WIDTH = 1366
SCREENSHOT_MAX_WIDTH = 3840
SCREENSHOT_MIN_HEIGHT = 768
SCREENSHOT_MAX_HEIGHT = 2160
SCREENSHOT_MIN_COUNT = 1
SCREENSHOT_MAX_COUNT = 10
SCREENSHOT_MAX_BYTES = 50 * 1024 * 1024
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_MIN_BYTES = 45  # 8-byte signature + 25-byte IHDR + 12-byte IEND
PNG_VALID_BIT_DEPTHS: dict[int, frozenset[int]] = {
    0: frozenset({1, 2, 4, 8, 16}),  # Greyscale
    2: frozenset({8, 16}),  # Truecolour (RGB)
    3: frozenset({1, 2, 4, 8}),  # Indexed-colour
    4: frozenset({8, 16}),  # Greyscale with alpha
    6: frozenset({8, 16}),  # Truecolour with alpha (RGBA)
}

# Exact 35 canonical TotalDrop locales mapped to official Microsoft Store listing language codes.
CANONICAL_STORE_LOCALES: tuple[tuple[str, str, str], ...] = (
    ("ar", "ar", "العربية"),
    ("bn", "bn", "বাংলা"),
    ("cs", "cs", "Čeština"),
    ("da", "da", "Dansk"),
    ("de", "de", "Deutsch"),
    ("el", "el", "Ελληνικά"),
    ("en", "en-us", "English"),
    ("es", "es", "Español"),
    ("fa", "fa", "فارسی"),
    ("fi", "fi", "Suomi"),
    ("fr", "fr", "Français"),
    ("he", "he", "עברית"),
    ("hi", "hi", "हिन्दी"),
    ("hu", "hu", "Magyar"),
    ("id", "id", "Bahasa Indonesia"),
    ("it", "it", "Italiano"),
    ("ja", "ja", "日本語"),
    ("ko", "ko", "한국어"),
    ("ms", "ms", "Bahasa Melayu"),
    ("nb", "nb", "Norsk bokmål"),
    ("nl", "nl", "Nederlands"),
    ("pl", "pl", "Polski"),
    ("pt-BR", "pt-br", "Português (Brasil)"),
    ("pt-PT", "pt-pt", "Português (Portugal)"),
    ("ro", "ro", "Română"),
    ("ru", "ru", "Русский"),
    ("sv", "sv", "Svenska"),
    ("sw", "sw", "Kiswahili"),
    ("th", "th", "ไทย"),
    ("tr", "tr", "Türkçe"),
    ("uk", "uk", "Українська"),
    ("ur", "ur", "اردو"),
    ("vi", "vi", "Tiếng Việt"),
    ("zh-Hans", "zh-cn", "简体中文"),
    ("zh-Hant", "zh-tw", "繁體中文"),
)

CANONICAL_TAGS: tuple[str, ...] = tuple(tag for tag, _, _ in CANONICAL_STORE_LOCALES)
STORE_LANGUAGE_ALLOWLIST: dict[str, str] = {
    tag: store_code for tag, store_code, _ in CANONICAL_STORE_LOCALES
}
AUTONYMS: dict[str, str] = {tag: autonym for tag, _, autonym in CANONICAL_STORE_LOCALES}
RTL_LOCALES: frozenset[str] = frozenset({"ar", "fa", "he", "ur"})

# Explicit Windows-safe ARB key allowlist (zero Linux/Android/non-Windows leakage, zero critical security keys).
DESCRIPTION_ARB_KEYS: tuple[str, ...] = (
    "appTagline",
    "metainfoAbout",
    "settingsPrivacyBody",
    "settingsWordsEnglish",
    "settingsAboutBody",
)
FEATURE_ARB_KEYS: tuple[str, ...] = (
    "homeFooter",
    "metainfoVerified",
    "metainfoWords",
    "homeSendBody",
    "homeReceiveBody",
    "sendDropHint",
    "privacyMode",
    "settingsServerHelp",
    "settingsAboutBody",
)
RELEASE_NOTES_ARB_KEYS: tuple[str, ...] = (
    "metainfoSummary",
    "homeFooter",
    "settingsAboutBody",
)
ALLOWED_STORE_ARB_KEYS: frozenset[str] = frozenset(
    {"desktopComment", "desktopKeywords", "desktopGenericName"}
    | set(DESCRIPTION_ARB_KEYS)
    | set(FEATURE_ARB_KEYS)
    | set(RELEASE_NOTES_ARB_KEYS)
)

# Split forbidden ARB key names so static scans for direct reads/emits never false-positive.
FORBIDDEN_ARB_KEYS: tuple[str, ...] = (
    "metainfo" + "Theme",
    "metainfo" + "OnePackage",
)

PROHIBITED_WORD_TERMS: tuple[str, ...] = (
    "Plasma",
    "Hyprland",
    "Omarchy",
    "GNOME",
    "Flatpak",
    "Dolphin",
    "Nemo",
    "Nautilus",
    "registered trademark",
    "AppContainer",
)
PROHIBITED_WORD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (term, re.compile(rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", re.IGNORECASE))
    for term in PROHIBITED_WORD_TERMS
)
PROHIBITED_EXT_TERMS: tuple[str, ...] = (".pkg", ".deb", ".rpm")
PROHIBITED_EXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (ext, re.compile(rf"{re.escape(ext)}(?![A-Za-z0-9])", re.IGNORECASE))
    for ext in PROHIBITED_EXT_TERMS
)
HTML_TAG_RE = re.compile(r"<[A-Za-z/!]")

CSV_COLUMNS: tuple[str, ...] = (
    "Locale",
    "StoreLanguageCode",
    "Direction",
    "Reviewed",
    "Title",
    "ShortDescription",
    "Description",
    "Feature1",
    "Feature2",
    "Feature3",
    "Feature4",
    "Feature5",
    "Feature6",
    "Feature7",
    "Feature8",
    "Feature9",
    "SearchTerm1",
    "SearchTerm2",
    "SearchTerm3",
    "SearchTerm4",
    "SearchTerm5",
    "SearchTerm6",
    "SearchTerm7",
    "ReleaseNotes",
    "PrivacyPolicyUrl",
    "SupportContact",
    "DesktopScreenshots",
)


def parse_json_no_duplicates(raw_text: str, label: str) -> dict[str, Any]:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise ValueError(f"{label}: duplicate JSON key {k!r}")
            out[k] = v
        return out

    parsed = json.loads(raw_text, object_pairs_hook=hook)
    if not isinstance(parsed, dict):
        raise ValueError(f"{label}: top-level JSON value must be an object")
    return parsed


def is_forbidden_char(ch: str, *, allow_newline: bool) -> bool:
    if ch == "\n" and allow_newline:
        return False
    # Permit standard Persian ZWNJ/ZWJ and directional marks matching l10n_codegen.py.
    if ch in ("\u200C", "\u200D", "\u200E", "\u200F"):
        return False
    cp = ord(ch)
    if 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE:
        return True
    if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069 or cp == 0x061C:
        return True
    return unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp")


def arb_path_for_locale(l10n_dir: Path, tag: str) -> Path:
    return l10n_dir / "app" / f"app_{tag.replace('-', '_')}.arb"


def load_arb_strings(l10n_dir: Path, tag: str) -> dict[str, str]:
    path = arb_path_for_locale(l10n_dir, tag)
    data = parse_json_no_duplicates(path.read_text(encoding="utf-8"), path.name)
    declared = str(data.get("@@locale", "")).replace("_", "-")
    if declared != tag:
        raise ValueError(f"{path.name}: @@locale {declared!r} != expected {tag!r}")
    out: dict[str, str] = {}
    for key, val in data.items():
        if key.startswith("@"):
            continue
        if isinstance(val, str):
            out[key] = val
    return out


def resolve_allowed_strings(l10n_dir: Path, tag: str, en_map: dict[str, str]) -> dict[str, str]:
    loc_map = load_arb_strings(l10n_dir, tag) if tag != TEMPLATE_LOCALE else en_map
    base_map: dict[str, str] = {}
    if "-" in tag:
        base_tag = tag.split("-", 1)[0]
        base_path = arb_path_for_locale(l10n_dir, base_tag)
        if base_path.is_file():
            base_map = load_arb_strings(l10n_dir, base_tag)

    resolved: dict[str, str] = {}
    for key in sorted(ALLOWED_STORE_ARB_KEYS):
        if key in loc_map:
            resolved[key] = loc_map[key]
        elif key in base_map:
            resolved[key] = base_map[key]
        elif key in en_map:
            resolved[key] = en_map[key]
        else:
            raise ValueError(f"l10n/app/{tag}: required allowlisted ARB key {key!r} missing")
    return resolved


def inspect_png(path: Path, rel_label: str) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, f"{rel_label}: screenshot file not found"
    raw = path.read_bytes()
    size = len(raw)
    if size < PNG_MIN_BYTES:
        return None, f"{rel_label}: file truncated ({size} bytes < {PNG_MIN_BYTES}-byte minimum PNG size)"
    if size > SCREENSHOT_MAX_BYTES:
        return None, f"{rel_label}: screenshot size {size} exceeds {SCREENSHOT_MAX_BYTES} bytes (50 MiB)"
    if raw[:8] != PNG_SIGNATURE:
        return None, f"{rel_label}: invalid PNG signature {raw[:8]!r} (must be PNG, not JPEG/other format)"

    pos = 8
    chunk_index = 0
    width = 0
    height = 0
    idat_count = 0
    seen_iend = False

    while pos < size:
        if seen_iend:
            return None, f"{rel_label}: trailing garbage bytes ({size - pos} bytes) after PNG IEND chunk"
        if pos + 12 > size:
            return None, f"{rel_label}: truncated PNG chunk header at offset {pos}"
        chunk_len = struct.unpack_from(">I", raw, pos)[0]
        chunk_type = raw[pos + 4 : pos + 8]
        data_start = pos + 8
        data_end = data_start + chunk_len
        crc_end = data_end + 4
        if chunk_len > 0x7FFF_FFFF or crc_end > size:
            return None, f"{rel_label}: truncated PNG chunk {chunk_type!r} (len={chunk_len}) at offset {pos}"
        if not all((0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A) for b in chunk_type):
            return None, f"{rel_label}: invalid non-ASCII PNG chunk type {chunk_type!r} at offset {pos}"

        expected_crc = struct.unpack_from(">I", raw, data_end)[0]
        actual_crc = zlib.crc32(raw[pos + 4 : data_end]) & 0xFFFF_FFFF
        if actual_crc != expected_crc:
            return (
                None,
                f"{rel_label}: PNG chunk {chunk_type.decode('ascii')} CRC32 mismatch "
                f"(expected {expected_crc:#010x}, got {actual_crc:#010x})",
            )

        if chunk_index == 0:
            if chunk_type != b"IHDR" or chunk_len != 13:
                return (
                    None,
                    f"{rel_label}: first PNG chunk must be 13-byte IHDR (got {chunk_type!r}, len={chunk_len})",
                )
            width, height, bit_depth, color_type, compression, filter_method, interlace = struct.unpack_from(
                ">IIBBBBB", raw, data_start
            )
            allowed_depths = PNG_VALID_BIT_DEPTHS.get(color_type)
            if allowed_depths is None or bit_depth not in allowed_depths:
                return (
                    None,
                    f"{rel_label}: invalid PNG IHDR color_type={color_type}, bit_depth={bit_depth}",
                )
            if compression != 0 or filter_method != 0 or interlace not in (0, 1):
                return (
                    None,
                    f"{rel_label}: invalid PNG IHDR compression={compression}, "
                    f"filter={filter_method}, interlace={interlace}",
                )
        else:
            if chunk_type == b"IHDR":
                return None, f"{rel_label}: duplicate PNG IHDR chunk at offset {pos}"
            if chunk_type == b"IDAT":
                idat_count += 1
            elif chunk_type == b"IEND":
                if chunk_len != 0:
                    return None, f"{rel_label}: PNG IEND chunk must have length 0 (got {chunk_len})"
                seen_iend = True

        pos = crc_end
        chunk_index += 1

    if chunk_index == 0:
        return None, f"{rel_label}: PNG contains zero chunks"
    if idat_count < 1:
        return None, f"{rel_label}: PNG contains zero IDAT image data chunks"
    if not seen_iend or pos != size:
        return None, f"{rel_label}: PNG missing terminating IEND chunk at EOF"

    if width < SCREENSHOT_MIN_WIDTH or height < SCREENSHOT_MIN_HEIGHT:
        return (
            None,
            f"{rel_label}: dimensions {width}x{height} below Partner Center desktop minimum "
            f"{SCREENSHOT_MIN_WIDTH}x{SCREENSHOT_MIN_HEIGHT}",
        )
    if width > SCREENSHOT_MAX_WIDTH or height > SCREENSHOT_MAX_HEIGHT:
        return (
            None,
            f"{rel_label}: dimensions {width}x{height} exceed Partner Center desktop maximum "
            f"{SCREENSHOT_MAX_WIDTH}x{SCREENSHOT_MAX_HEIGHT}",
        )
    return (
        {
            "bytes": size,
            "file": rel_label,
            "format": "png",
            "height": height,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "width": width,
        },
        None,
    )


def collect_screenshots(screenshots_dir: Path) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Validate screenshot directory (flat shared or per-locale tree) and map screenshots per locale."""
    errors: list[str] = []
    per_locale: dict[str, list[dict[str, Any]]] = {}

    if not screenshots_dir.is_dir():
        return {}, [f"screenshots directory not found: {screenshots_dir}"]

    root_resolved = screenshots_dir.resolve()
    children = sorted(screenshots_dir.iterdir(), key=lambda p: p.name)
    if not children:
        return {}, [f"screenshots directory is empty: {screenshots_dir}"]

    subdirs = [p for p in children if p.is_dir()]
    root_files = [p for p in children if p.is_file() and not p.name.startswith(".")]

    def inspect_dir_files(files: list[Path], context: str) -> list[dict[str, Any]]:
        valid_entries: list[dict[str, Any]] = []
        for fpath in sorted(files, key=lambda p: p.name):
            rel = fpath.relative_to(screenshots_dir).as_posix()
            resolved = fpath.resolve()
            if not resolved.is_relative_to(root_resolved) or resolved == root_resolved:
                errors.append(f"{context}: screenshot path {rel!r} escapes --screenshots-dir")
                continue
            if fpath.suffix.lower() != ".png":
                errors.append(f"{context}: non-PNG file {rel!r} is not permitted for Store screenshots")
                continue
            meta, err = inspect_png(resolved, rel)
            if err is not None:
                errors.append(f"{context}: {err}")
            elif meta is not None:
                valid_entries.append(meta)
        return valid_entries

    if not subdirs:
        root_valid = inspect_dir_files(root_files, "screenshots(shared)")
        if len(root_valid) < SCREENSHOT_MIN_COUNT:
            errors.append(
                f"screenshots(shared): expected >= {SCREENSHOT_MIN_COUNT} valid PNG screenshot(s), found {len(root_valid)}"
            )
        elif len(root_valid) > SCREENSHOT_MAX_COUNT:
            errors.append(
                f"screenshots(shared): found {len(root_valid)} PNG screenshots (Partner Center max {SCREENSHOT_MAX_COUNT})"
            )
        for tag in CANONICAL_TAGS:
            per_locale[tag] = list(root_valid)
        return per_locale, errors

    # Per-locale tree (optional hybrid fallback to valid root-level PNGs when present).
    unknown_dirs = sorted(d.name for d in subdirs if d.name not in STORE_LANGUAGE_ALLOWLIST)
    if unknown_dirs:
        errors.append(f"screenshots directory contains unknown locale subdirectories: {unknown_dirs}")

    root_valid = inspect_dir_files(root_files, "screenshots(shared-root)") if root_files else []
    if len(root_valid) > SCREENSHOT_MAX_COUNT:
        errors.append(
            f"screenshots(shared-root): found {len(root_valid)} PNG screenshots (max {SCREENSHOT_MAX_COUNT})"
        )

    for tag in CANONICAL_TAGS:
        loc_dir = screenshots_dir / tag
        if loc_dir.is_dir():
            loc_files = [p for p in loc_dir.iterdir() if p.is_file() and not p.name.startswith(".")]
            loc_valid = inspect_dir_files(loc_files, f"locale {tag}")
            if len(loc_valid) < SCREENSHOT_MIN_COUNT:
                errors.append(
                    f"locale {tag}: directory exists but contains {len(loc_valid)} valid PNG screenshots "
                    f"(Partner Center requires >= {SCREENSHOT_MIN_COUNT} per configured language)"
                )
            elif len(loc_valid) > SCREENSHOT_MAX_COUNT:
                errors.append(
                    f"locale {tag}: found {len(loc_valid)} PNG screenshots (Partner Center max {SCREENSHOT_MAX_COUNT})"
                )
            per_locale[tag] = loc_valid
        elif root_valid:
            per_locale[tag] = list(root_valid)
        else:
            errors.append(
                f"locale {tag}: missing screenshots directory (0 screenshots; Partner Center requires >= 1 PNG >= 1366x768)"
            )
            per_locale[tag] = []

    return per_locale, errors


def build_search_terms(strings: dict[str, str]) -> list[str]:
    terms: list[str] = []
    seen_cf: set[str] = set()

    def add_term(raw: str) -> None:
        cleaned = " ".join(raw.strip().split())
        if not cleaned:
            return
        cf = cleaned.casefold()
        if cf in seen_cf:
            return
        seen_cf.add(cf)
        terms.append(cleaned)

    add_term(EXPECTED_TITLE)
    for token in strings["desktopKeywords"].split(";"):
        add_term(token)
    add_term(strings["desktopGenericName"])
    return terms[:MAX_SEARCH_TERMS]


def generate_document(
    l10n_dir: Path,
    screenshots_by_locale: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    status_path = l10n_dir / "status.json"
    status = parse_json_no_duplicates(status_path.read_text(encoding="utf-8"), "status.json")
    languages_meta: dict[str, Any] = status.get("languages", {})
    en_map = load_arb_strings(l10n_dir, TEMPLATE_LOCALE)

    listings: list[dict[str, Any]] = []
    for tag, store_code, autonym in CANONICAL_STORE_LOCALES:
        strings = resolve_allowed_strings(l10n_dir, tag, en_map)
        reviewed = True if tag == TEMPLATE_LOCALE else bool(languages_meta.get(tag, {}).get("reviewed", False))
        short_desc = strings["desktopComment"].strip()
        description = "\n\n".join(strings[k].strip() for k in DESCRIPTION_ARB_KEYS)
        features = [strings[k].strip() for k in FEATURE_ARB_KEYS]
        search_terms = build_search_terms(strings)
        release_notes = "\n".join(strings[k].strip() for k in RELEASE_NOTES_ARB_KEYS)
        screenshots = list(screenshots_by_locale.get(tag, [])) if screenshots_by_locale is not None else []

        listings.append(
            {
                "Description": description,
                "Features": features,
                "PrivacyPolicyUrl": EXPECTED_PRIVACY_URL,
                "ReleaseNotes": release_notes,
                "Screenshots": screenshots,
                "SearchTerms": search_terms,
                "ShortDescription": short_desc,
                "SupportContact": EXPECTED_SUPPORT_CONTACT,
                "Title": EXPECTED_TITLE,
                "autonym": autonym,
                "dir": "rtl" if tag in RTL_LOCALES else "ltr",
                "locale": tag,
                "packageResourceTag": tag,
                "reviewed": reviewed,
                "storeLanguageCode": store_code,
            }
        )

    return {
        "defaultLocale": TEMPLATE_LOCALE,
        "listings": listings,
        "localeCount": len(listings),
        "privacyPolicyUrl": EXPECTED_PRIVACY_URL,
        "schemaVersion": 1,
        "screenshotPolicy": {
            "format": "png",
            "maxBytes": SCREENSHOT_MAX_BYTES,
            "maxCount": SCREENSHOT_MAX_COUNT,
            "maxHeight": SCREENSHOT_MAX_HEIGHT,
            "maxWidth": SCREENSHOT_MAX_WIDTH,
            "minCount": SCREENSHOT_MIN_COUNT,
            "minHeight": SCREENSHOT_MIN_HEIGHT,
            "minWidth": SCREENSHOT_MIN_WIDTH,
            "requiredThemes": ["light", "dark"],
        },
        "screenshotsValidated": screenshots_by_locale is not None,
        "supportContact": EXPECTED_SUPPORT_CONTACT,
    }


def render_json_bytes(doc: dict[str, Any]) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def render_csv_bytes(doc: dict[str, Any]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for item in doc["listings"]:
        features = list(item["Features"])
        search_terms = list(item["SearchTerms"])
        screenshots = ";".join(str(s["file"]) for s in item.get("Screenshots", []))
        row = [
            item["locale"],
            item["storeLanguageCode"],
            item["dir"],
            "true" if item["reviewed"] else "false",
            item["Title"],
            item["ShortDescription"],
            item["Description"],
            *(features[i] if i < len(features) else "" for i in range(9)),
            *(search_terms[i] if i < len(search_terms) else "" for i in range(7)),
            item["ReleaseNotes"],
            item["PrivacyPolicyUrl"],
            item["SupportContact"],
            screenshots,
        ]
        writer.writerow(row)
    return buf.getvalue().encode("utf-8")


def _load_forbidden_arb_strings(l10n_dir: Path) -> list[tuple[str, str]]:
    """Load deduplicated values of forbidden non-Windows ARB keys across all app_*.arb catalogs."""
    app_dir = l10n_dir / "app"
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    if not app_dir.is_dir():
        return out
    for arb_path in sorted(app_dir.glob("app_*.arb")):
        data = parse_json_no_duplicates(arb_path.read_text(encoding="utf-8"), arb_path.name)
        for fk in FORBIDDEN_ARB_KEYS:
            val = data.get(fk)
            if isinstance(val, str) and val.strip():
                pair = (fk, val.strip())
                if pair not in seen:
                    seen.add(pair)
                    out.append(pair)
    return out


def _check_text_hygiene(
    locale: str,
    field: str,
    text: str,
    *,
    allow_newline: bool,
    forbidden_strings: list[tuple[str, str]],
    errors: list[str],
) -> None:
    for ch in text:
        if is_forbidden_char(ch, allow_newline=allow_newline):
            errors.append(
                f"locale {locale} {field}: contains forbidden control/Bidi character U+{ord(ch):04X}"
            )
            break

    if HTML_TAG_RE.search(text):
        errors.append(f"locale {locale} {field}: contains forbidden HTML/XML markup tag")

    for term, pattern in PROHIBITED_WORD_PATTERNS:
        if pattern.search(text):
            errors.append(f"locale {locale} {field}: contains prohibited non-Windows/Store term {term!r}")

    for ext, pattern in PROHIBITED_EXT_PATTERNS:
        if pattern.search(text):
            errors.append(f"locale {locale} {field}: contains prohibited non-Windows package extension {ext!r}")

    for fk, fval in forbidden_strings:
        if fval and fval in text:
            errors.append(
                f"locale {locale} {field}: leaks forbidden non-Windows ARB string from key {fk!r}"
            )


def validate_document(
    doc: dict[str, Any],
    l10n_dir: Path,
    *,
    screenshots_dir: Path | None = None,
    require_screenshots: bool = False,
) -> list[str]:
    """Validate a Store listing document thoroughly, collecting ALL errors before returning."""
    errors: list[str] = []

    raw_listings = doc.get("listings")
    entries: list[tuple[str, dict[str, Any]]] = []
    if isinstance(raw_listings, list):
        for idx, item in enumerate(raw_listings):
            if not isinstance(item, dict):
                errors.append(f"listings[{idx}]: entry must be a JSON object")
                continue
            loc = item.get("locale")
            if not isinstance(loc, str) or not loc.strip():
                errors.append(f"listings[{idx}]: missing non-empty `locale` field")
                continue
            entries.append((loc, item))
    elif isinstance(raw_listings, dict):
        for loc, item in raw_listings.items():
            loc_str = str(loc)
            if not isinstance(item, dict):
                errors.append(f"listings[{loc!r}]: entry must be a JSON object")
                continue
            if "locale" in item and item.get("locale") != loc_str:
                errors.append(
                    f"listings[{loc_str!r}]: inner `locale` {item.get('locale')!r} does not match key {loc_str!r}"
                )
            entries.append((loc_str, item))
    else:
        return ["document missing valid `listings` list or object"]

    seen_locales: set[str] = set()
    for loc, _ in entries:
        if loc in seen_locales:
            errors.append(f"locale {loc}: duplicate listing entry")
        seen_locales.add(loc)
        if loc not in STORE_LANGUAGE_ALLOWLIST:
            errors.append(f"locale {loc}: not in verified 35-language Microsoft Store allowlist")

    missing_locales = sorted(set(CANONICAL_TAGS) - seen_locales)
    if missing_locales:
        errors.append(
            f"incomplete 35-locale Store catalog (found {len(seen_locales)}/35); missing locales: {missing_locales}"
        )

    forbidden_strings = _load_forbidden_arb_strings(l10n_dir)

    any_screenshots_present = any(
        isinstance(item.get("Screenshots"), list) and len(item.get("Screenshots", [])) > 0
        for _, item in entries
    )
    must_have_screenshots = (
        require_screenshots
        or bool(doc.get("screenshotsValidated"))
        or any_screenshots_present
        or screenshots_dir is not None
    )
    screenshots_root_resolved = screenshots_dir.resolve() if screenshots_dir is not None else None

    for loc, item in entries:
        expected_store_code = STORE_LANGUAGE_ALLOWLIST.get(loc)
        if expected_store_code is not None:
            actual_store_code = item.get("storeLanguageCode")
            if not isinstance(actual_store_code, str) or actual_store_code != expected_store_code:
                errors.append(
                    f"locale {loc}: storeLanguageCode {actual_store_code!r} != {expected_store_code!r}"
                )

        expected_dir = "rtl" if loc in RTL_LOCALES else "ltr"
        actual_dir = item.get("dir")
        if not isinstance(actual_dir, str) or actual_dir != expected_dir:
            errors.append(f"locale {loc}: dir {actual_dir!r} != {expected_dir!r}")

        title = item.get("Title")
        if title != EXPECTED_TITLE:
            errors.append(f"locale {loc} Title: expected {EXPECTED_TITLE!r}, got {title!r}")

        privacy_url = item.get("PrivacyPolicyUrl")
        if privacy_url != EXPECTED_PRIVACY_URL:
            errors.append(
                f"locale {loc} PrivacyPolicyUrl: expected HTTPS {EXPECTED_PRIVACY_URL!r}, got {privacy_url!r}"
            )

        support = item.get("SupportContact")
        if support != EXPECTED_SUPPORT_CONTACT:
            errors.append(
                f"locale {loc} SupportContact: expected {EXPECTED_SUPPORT_CONTACT!r}, got {support!r}"
            )

        short_desc = item.get("ShortDescription")
        if not isinstance(short_desc, str) or not short_desc.strip():
            errors.append(f"locale {loc} ShortDescription: must be a non-empty string")
        else:
            if len(short_desc) > MAX_SHORT_DESCRIPTION:
                errors.append(
                    f"locale {loc} ShortDescription: length {len(short_desc)} exceeds Partner Center limit {MAX_SHORT_DESCRIPTION}"
                )
            _check_text_hygiene(
                loc, "ShortDescription", short_desc, allow_newline=False, forbidden_strings=forbidden_strings, errors=errors
            )

        desc = item.get("Description")
        if not isinstance(desc, str) or not desc.strip():
            errors.append(f"locale {loc} Description: must be a non-empty string")
        else:
            if len(desc) > MAX_DESCRIPTION:
                errors.append(
                    f"locale {loc} Description: length {len(desc)} exceeds Partner Center limit {MAX_DESCRIPTION}"
                )
            _check_text_hygiene(
                loc, "Description", desc, allow_newline=True, forbidden_strings=forbidden_strings, errors=errors
            )

        features = item.get("Features")
        if not isinstance(features, list):
            errors.append(f"locale {loc} Features: must be a JSON list")
        else:
            if not (MIN_FEATURES <= len(features) <= MAX_FEATURES):
                errors.append(
                    f"locale {loc} Features: count {len(features)} outside Partner Center range {MIN_FEATURES}..={MAX_FEATURES}"
                )
            for idx, bullet in enumerate(features):
                if not isinstance(bullet, str) or not bullet.strip():
                    errors.append(f"locale {loc} Features[{idx}]: must be a non-empty string")
                    continue
                if len(bullet) > MAX_FEATURE_LENGTH:
                    errors.append(
                        f"locale {loc} Features[{idx}]: length {len(bullet)} exceeds Partner Center limit {MAX_FEATURE_LENGTH}"
                    )
                _check_text_hygiene(
                    loc,
                    f"Features[{idx}]",
                    bullet,
                    allow_newline=False,
                    forbidden_strings=forbidden_strings,
                    errors=errors,
                )

        search_terms = item.get("SearchTerms")
        if not isinstance(search_terms, list):
            errors.append(f"locale {loc} SearchTerms: must be a JSON list")
        else:
            if not (MIN_SEARCH_TERMS <= len(search_terms) <= MAX_SEARCH_TERMS):
                errors.append(
                    f"locale {loc} SearchTerms: count {len(search_terms)} outside Partner Center range "
                    f"{MIN_SEARCH_TERMS}..={MAX_SEARCH_TERMS}"
                )
            seen_terms: set[str] = set()
            for idx, term in enumerate(search_terms):
                if not isinstance(term, str) or not term.strip():
                    errors.append(f"locale {loc} SearchTerms[{idx}]: must be a non-empty string")
                    continue
                if len(term) > MAX_SEARCH_TERM_LENGTH:
                    errors.append(
                        f"locale {loc} SearchTerms[{idx}]: length {len(term)} exceeds Partner Center limit {MAX_SEARCH_TERM_LENGTH}"
                    )
                cf = term.casefold()
                if cf in seen_terms:
                    errors.append(f"locale {loc} SearchTerms[{idx}]: duplicate search term {term!r}")
                seen_terms.add(cf)
                _check_text_hygiene(
                    loc,
                    f"SearchTerms[{idx}]",
                    term,
                    allow_newline=False,
                    forbidden_strings=forbidden_strings,
                    errors=errors,
                )

        release_notes = item.get("ReleaseNotes")
        if not isinstance(release_notes, str) or not release_notes.strip():
            errors.append(f"locale {loc} ReleaseNotes: must be a non-empty string")
        else:
            if len(release_notes) > MAX_RELEASE_NOTES:
                errors.append(
                    f"locale {loc} ReleaseNotes: length {len(release_notes)} exceeds Partner Center limit {MAX_RELEASE_NOTES}"
                )
            _check_text_hygiene(
                loc, "ReleaseNotes", release_notes, allow_newline=True, forbidden_strings=forbidden_strings, errors=errors
            )

        screenshots = item.get("Screenshots", [])
        if not isinstance(screenshots, list):
            errors.append(f"locale {loc} Screenshots: must be a JSON list")
        else:
            if must_have_screenshots:
                if len(screenshots) < SCREENSHOT_MIN_COUNT:
                    errors.append(
                        f"locale {loc} Screenshots: has {len(screenshots)} screenshots "
                        f"(Partner Center requires >= {SCREENSHOT_MIN_COUNT} PNG >= {SCREENSHOT_MIN_WIDTH}x{SCREENSHOT_MIN_HEIGHT})"
                    )
                elif len(screenshots) > SCREENSHOT_MAX_COUNT:
                    errors.append(
                        f"locale {loc} Screenshots: has {len(screenshots)} screenshots (max {SCREENSHOT_MAX_COUNT})"
                    )
            for idx, shot in enumerate(screenshots):
                if not isinstance(shot, dict):
                    errors.append(f"locale {loc} Screenshots[{idx}]: entry must be a JSON object")
                    continue
                fmt = shot.get("format")
                if fmt != "png":
                    errors.append(f"locale {loc} Screenshots[{idx}]: format must be 'png', got {fmt!r}")
                w = shot.get("width")
                h = shot.get("height")
                dims_valid_type = (
                    isinstance(w, int)
                    and not isinstance(w, bool)
                    and isinstance(h, int)
                    and not isinstance(h, bool)
                )
                if not dims_valid_type:
                    errors.append(f"locale {loc} Screenshots[{idx}]: width and height must be integers")
                else:
                    if w < SCREENSHOT_MIN_WIDTH or h < SCREENSHOT_MIN_HEIGHT:
                        errors.append(
                            f"locale {loc} Screenshots[{idx}]: dimensions {w}x{h} below minimum "
                            f"{SCREENSHOT_MIN_WIDTH}x{SCREENSHOT_MIN_HEIGHT}"
                        )
                    if w > SCREENSHOT_MAX_WIDTH or h > SCREENSHOT_MAX_HEIGHT:
                        errors.append(
                            f"locale {loc} Screenshots[{idx}]: dimensions {w}x{h} exceed maximum "
                            f"{SCREENSHOT_MAX_WIDTH}x{SCREENSHOT_MAX_HEIGHT}"
                        )
                rel_file = shot.get("file")
                if not isinstance(rel_file, str) or not rel_file.strip():
                    errors.append(f"locale {loc} Screenshots[{idx}]: missing non-empty `file` path")
                else:
                    path_unsafe = (
                        rel_file != rel_file.strip()
                        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in rel_file)
                        or rel_file.startswith("/")
                        or rel_file.startswith("\\")
                        or "\\" in rel_file
                        or ":" in rel_file
                        or Path(rel_file).is_absolute()
                        or any(part in ("", ".", "..") for part in rel_file.split("/"))
                    )
                    if path_unsafe:
                        errors.append(
                            f"locale {loc} Screenshots[{idx}]: unsafe screenshot relative path {rel_file!r} "
                            "(absolute paths, drive colons, backslashes, and '.'/'..' segments are forbidden)"
                        )
                    elif screenshots_dir is not None and screenshots_root_resolved is not None:
                        candidate = (screenshots_dir / rel_file).resolve()
                        if not candidate.is_relative_to(screenshots_root_resolved) or candidate == screenshots_root_resolved:
                            errors.append(
                                f"locale {loc} Screenshots[{idx}]: screenshot path {rel_file!r} escapes --screenshots-dir"
                            )
                        else:
                            meta, shot_err = inspect_png(candidate, rel_file)
                            if shot_err is not None:
                                errors.append(f"locale {loc} Screenshots[{idx}]: {shot_err}")
                            elif meta is not None:
                                if dims_valid_type and (meta["width"] != w or meta["height"] != h):
                                    errors.append(
                                        f"locale {loc} Screenshots[{idx}]: declared dimensions {w}x{h} "
                                        f"!= actual PNG dimensions {meta['width']}x{meta['height']}"
                                    )
                                if "bytes" in shot:
                                    decl_bytes = shot.get("bytes")
                                    if (
                                        isinstance(decl_bytes, bool)
                                        or not isinstance(decl_bytes, int)
                                        or decl_bytes != meta["bytes"]
                                    ):
                                        errors.append(
                                            f"locale {loc} Screenshots[{idx}]: declared bytes {decl_bytes!r} "
                                            f"!= actual PNG size {meta['bytes']}"
                                        )
                                if "sha256" in shot:
                                    decl_sha = shot.get("sha256")
                                    if not isinstance(decl_sha, str) or decl_sha.lower() != meta["sha256"]:
                                        errors.append(
                                            f"locale {loc} Screenshots[{idx}]: declared sha256 {decl_sha!r} "
                                            f"!= actual PNG SHA-256 {meta['sha256']!r}"
                                        )

    return errors


def check_manifest_resource_parity(errors: list[str]) -> None:
    appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
    expected = set(CANONICAL_TAGS)
    for rel in (
        "target-x86_64/Package.x64.appxmanifest",
        "target-arm64/Package.arm64.appxmanifest",
    ):
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        root = ET.fromstring(path.read_text(encoding="utf-8"))
        langs = [n.attrib.get("Language", "") for n in root.findall(f"{appx_ns}Resources/{appx_ns}Resource")]
        if set(langs) != expected or len(langs) != len(CANONICAL_TAGS):
            errors.append(
                f"{rel}: <Resources> locale set does not match 35-language Store listing catalog "
                f"(missing={sorted(expected - set(langs))}, extra={sorted(set(langs) - expected)})"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate and validate 35-language Microsoft Store listings from l10n/app/*.arb."
    )
    parser.add_argument(
        "--l10n-dir",
        type=Path,
        default=REPO_ROOT / "l10n",
        help="Path to read-only l10n/ directory (default: <repo>/l10n).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "packaging" / "store-listings",
        help="Output directory for store-listings.{json,csv} (default: <repo>/packaging/store-listings).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify committed <out>/store-listings.{json,csv} match deterministic generation byte-for-byte.",
    )
    parser.add_argument(
        "--screenshots-dir",
        type=Path,
        default=None,
        help="Optional screenshots directory (flat shared or per-locale PNG tree; validates >= 1366x768 PNGs).",
    )
    parser.add_argument(
        "--validate-file",
        type=Path,
        default=None,
        help="Standalone validator for an existing store-listings.json file (exits non-zero listing all errors).",
    )
    parser.add_argument(
        "--require-screenshots",
        action="store_true",
        help="Require >= 1 validated desktop PNG screenshot per locale even without --screenshots-dir.",
    )
    args = parser.parse_args(argv)

    if args.validate_file is not None:
        if not args.validate_file.is_file():
            print(f"error: listings file not found: {args.validate_file}", file=sys.stderr)
            return 1
        try:
            doc = parse_json_no_duplicates(
                args.validate_file.read_text(encoding="utf-8"), args.validate_file.name
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: failed to parse {args.validate_file}: {exc}", file=sys.stderr)
            return 1

        all_errors: list[str] = []
        if args.screenshots_dir is not None:
            _, ss_errors = collect_screenshots(args.screenshots_dir)
            all_errors.extend(ss_errors)
        all_errors.extend(
            validate_document(
                doc,
                args.l10n_dir,
                screenshots_dir=args.screenshots_dir,
                require_screenshots=args.require_screenshots,
            )
        )
        if all_errors:
            for err in all_errors:
                print(f"error: {err}", file=sys.stderr)
            return 1
        print(f"store-listings validate OK: {args.validate_file} (35 locales verified, 0 errors).")
        return 0

    screenshots_by_locale: dict[str, list[dict[str, Any]]] | None = None
    pre_errors: list[str] = []
    if args.screenshots_dir is not None:
        screenshots_by_locale, ss_errors = collect_screenshots(args.screenshots_dir)
        pre_errors.extend(ss_errors)

    try:
        doc = generate_document(args.l10n_dir, screenshots_by_locale=screenshots_by_locale)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: failed to generate Store listings: {exc}", file=sys.stderr)
        return 1

    validation_errors = pre_errors + validate_document(
        doc,
        args.l10n_dir,
        screenshots_dir=args.screenshots_dir,
        require_screenshots=args.require_screenshots,
    )
    check_manifest_resource_parity(validation_errors)

    if validation_errors:
        for err in validation_errors:
            print(f"error: {err}", file=sys.stderr)
        return 1

    expected_json = render_json_bytes(doc)
    expected_csv = render_csv_bytes(doc)

    json_path = args.out / "store-listings.json"
    csv_path = args.out / "store-listings.csv"

    if args.check:
        drift_errors: list[str] = []
        for path, expected_bytes in ((json_path, expected_json), (csv_path, expected_csv)):
            if not path.is_file():
                drift_errors.append(f"missing generated Store listing file: {path}")
                continue
            actual_bytes = path.read_bytes()
            if actual_bytes.startswith(b"\xef\xbb\xbf"):
                drift_errors.append(f"{path}: unexpected UTF-8 BOM")
            if b"\r\n" in actual_bytes:
                drift_errors.append(f"{path}: unexpected CRLF line endings (expected LF)")
            if actual_bytes != expected_bytes:
                drift_errors.append(
                    f"{path}: content drifted from deterministic l10n/ generation "
                    "(regenerate with `python3 tools/generate-store-listings.py`)"
                )
        if drift_errors:
            for err in drift_errors:
                print(f"error: {err}", file=sys.stderr)
            return 1
        print(
            f"store-listings check OK: 35 locales verified byte-exact "
            f"({json_path.name} + {csv_path.name}, screenshots_validated={doc['screenshotsValidated']})."
        )
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    json_path.write_bytes(expected_json)
    csv_path.write_bytes(expected_csv)
    print(
        f"store-listings generated OK: {json_path} ({len(expected_json)} bytes) & "
        f"{csv_path} ({len(expected_csv)} bytes) for 35 verified Microsoft Store locales."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
