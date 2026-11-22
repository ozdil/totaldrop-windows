#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Deep structural, PRI, PE32+ hardening, CRT, COM, manifest, bundle, upload, and live C ABI verifier for TotalDrop MSIX packages.

Uses only the Python standard library so it runs cleanly on GitHub Actions
`ubuntu-latest`, `windows-latest`, and `windows-11-arm` runners without extra dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import platform
import re
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

EXPECTED_APP_VERSION = "0.1.0-beta.1"
EXPECTED_CORE_VERSION = "0.2.0-beta.5"
EXPECTED_MSIX_VERSION = "0.1.1.0"
EXPECTED_EXPLORER_CLSID = "8f6e3d72-4b9a-4e1c-9d3a-7c2f5a81e4b0"
EXPECTED_TOAST_CLSID = "7df2cced-0448-4849-a140-41cd106eaa9b"
UNSIGNED_PACKAGE_OID = "2.25.311729368913984317654407730594956997722"

BARE_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
QUAD_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$", re.ASCII)
IDENTITY_NAME_RE = re.compile(r"^[A-Za-z0-9.-]{3,50}$")
RDN_RE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9-]*|(?:OID\.)?\d+(?:\.\d+)+)\s*=\s*\S.*$")

APPX_NS = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
BUNDLE_NS = "{http://schemas.microsoft.com/appx/2013/bundle}"

REQUIRED_FFI_EXPORTS: tuple[str, ...] = (
    # Phase 1 (6 exports)
    "totaldrop_win_string_free",
    "totaldrop_win_version_json",
    "totaldrop_win_validate_uri_json",
    "totaldrop_win_validate_input_json",
    "totaldrop_win_format_percent_json",
    "totaldrop_win_ui_bundle_json",
    # Phase 2 Group A (8 exports)
    "totaldrop_win_extract_clipboard_code_json",
    "totaldrop_win_code_completions_json",
    "totaldrop_win_format_bytes_json",
    "totaldrop_win_format_message_json",
    "totaldrop_win_sanitize_filename_json",
    "totaldrop_win_sanitize_text_json",
    "totaldrop_win_validate_server_url_json",
    "totaldrop_win_validate_paths_json",
    # Phase 2 Group B (10 exports)
    "totaldrop_win_send_files_start",
    "totaldrop_win_send_text_start",
    "totaldrop_win_receive_connect_start",
    "totaldrop_win_receive_accept_files",
    "totaldrop_win_receive_accept_text",
    "totaldrop_win_receive_decline",
    "totaldrop_win_session_poll_events_ndjson",
    "totaldrop_win_session_cancel",
    "totaldrop_win_session_destroy",
    "totaldrop_win_shutdown",
    # Phase 3 Router (7 exports -> 31 cumulative)
    "totaldrop_win_router_create",
    "totaldrop_win_router_ingest_ipc_bytes_json",
    "totaldrop_win_router_update_locale_json",
    "totaldrop_win_router_set_animations_json",
    "totaldrop_win_router_set_activity_json",
    "totaldrop_win_router_drain_ndjson",
    "totaldrop_win_router_destroy",
)

REQUIRED_EXPLORER_EXT_EXPORTS: tuple[str, ...] = (
    "DllGetClassObject",
    "DllCanUnloadNow",
)

REQUIRED_SYMBOL_PDBS: frozenset[str] = frozenset(
    {
        "totaldrop-winui.pdb",
        "totaldrop_windows_ffi.pdb",
        "totaldrop_explorer_ext.pdb",
    }
)

FORBIDDEN_KEY_EXTS: tuple[str, ...] = (
    ".pfx",
    ".p12",
    ".cer",
    ".snk",
    ".key",
    ".pem",
    ".jks",
    ".keystore",
)

FORBIDDEN_CRT_DLLS: tuple[str, ...] = (
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "vcruntime140d.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "concrt140.dll",
    "vcomp140.dll",
    "ucrtbased.dll",
)

FORBIDDEN_CLR_HOST_DLLS: tuple[str, ...] = (
    "hostfxr.dll",
    "coreclr.dll",
    "clrjit.dll",
    "mscoree.dll",
)

RT_ICON = 3
RT_GROUP_ICON = 14
EXPLORER_ICON_RESOURCE_ID = 101


def _build_expected_assets() -> frozenset[str]:
    """Return the exact 46 canonical Kose asset filenames matching tools/render-windows-assets.py."""
    names: list[str] = ["TotalDrop.ico"]
    for prefix in (
        "StoreLogo",
        "Square44x44Logo",
        "Square71x71Logo",
        "Square150x150Logo",
        "Wide310x150Logo",
        "Square310x310Logo",
    ):
        for scale in (100, 125, 150, 200, 400):
            names.append(f"{prefix}.scale-{scale}.png")
    for size in (16, 24, 32, 48, 256):
        names.append(f"Square44x44Logo.targetsize-{size}.png")
        names.append(f"Square44x44Logo.targetsize-{size}_altform-unplated.png")
        names.append(f"Square44x44Logo.targetsize-{size}_altform-lightunplated.png")
    return frozenset(names)


EXPECTED_ASSETS: frozenset[str] = _build_expected_assets()

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_FILE_DLL = 0x2000
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20
IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT = 0x0001
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x0800

_SMOKE_TEST_CHILD_SCRIPT = r"""
import ctypes
import json
import struct
import sys

dll_path, expected_app, expected_core, expected_msix = sys.argv[1:5]
lib = ctypes.CDLL(dll_path)

lib.totaldrop_win_string_free.argtypes = [ctypes.c_void_p]
lib.totaldrop_win_string_free.restype = None

lib.totaldrop_win_version_json.argtypes = []
lib.totaldrop_win_version_json.restype = ctypes.c_void_p

lib.totaldrop_win_validate_uri_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_validate_uri_json.restype = ctypes.c_void_p

lib.totaldrop_win_validate_input_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_validate_input_json.restype = ctypes.c_void_p

lib.totaldrop_win_format_percent_json.argtypes = [
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_char_p,
]
lib.totaldrop_win_format_percent_json.restype = ctypes.c_void_p

lib.totaldrop_win_ui_bundle_json.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_ui_bundle_json.restype = ctypes.c_void_p

lib.totaldrop_win_extract_clipboard_code_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_extract_clipboard_code_json.restype = ctypes.c_void_p

lib.totaldrop_win_code_completions_json.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
lib.totaldrop_win_code_completions_json.restype = ctypes.c_void_p

lib.totaldrop_win_format_bytes_json.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]
lib.totaldrop_win_format_bytes_json.restype = ctypes.c_void_p

lib.totaldrop_win_format_message_json.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_format_message_json.restype = ctypes.c_void_p

lib.totaldrop_win_sanitize_filename_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_sanitize_filename_json.restype = ctypes.c_void_p

lib.totaldrop_win_sanitize_text_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_sanitize_text_json.restype = ctypes.c_void_p

lib.totaldrop_win_validate_server_url_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_validate_server_url_json.restype = ctypes.c_void_p

lib.totaldrop_win_validate_paths_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_validate_paths_json.restype = ctypes.c_void_p

lib.totaldrop_win_send_files_start.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_send_files_start.restype = ctypes.c_uint64

lib.totaldrop_win_send_text_start.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_send_text_start.restype = ctypes.c_uint64

lib.totaldrop_win_receive_connect_start.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_receive_connect_start.restype = ctypes.c_uint64

lib.totaldrop_win_receive_accept_files.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
lib.totaldrop_win_receive_accept_files.restype = ctypes.c_int32

lib.totaldrop_win_receive_accept_text.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_receive_accept_text.restype = ctypes.c_int32

lib.totaldrop_win_receive_decline.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_receive_decline.restype = ctypes.c_int32

lib.totaldrop_win_session_poll_events_ndjson.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_session_poll_events_ndjson.restype = ctypes.c_void_p

lib.totaldrop_win_session_cancel.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_session_cancel.restype = ctypes.c_int32

lib.totaldrop_win_session_destroy.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_session_destroy.restype = ctypes.c_int32

lib.totaldrop_win_shutdown.argtypes = [ctypes.c_uint32]
lib.totaldrop_win_shutdown.restype = ctypes.c_int32

# Phase 3 router C ABI exports
lib.totaldrop_win_router_create.argtypes = [
    ctypes.c_uint32,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_bool,
]
lib.totaldrop_win_router_create.restype = ctypes.c_uint64

lib.totaldrop_win_router_ingest_ipc_bytes_json.argtypes = [
    ctypes.c_uint64,
    ctypes.c_void_p,
    ctypes.c_size_t,
]
lib.totaldrop_win_router_ingest_ipc_bytes_json.restype = ctypes.c_void_p

lib.totaldrop_win_router_update_locale_json.argtypes = [
    ctypes.c_uint64,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_router_update_locale_json.restype = ctypes.c_void_p

lib.totaldrop_win_router_set_animations_json.argtypes = [
    ctypes.c_uint64,
    ctypes.c_bool,
]
lib.totaldrop_win_router_set_animations_json.restype = ctypes.c_void_p

lib.totaldrop_win_router_set_activity_json.argtypes = [
    ctypes.c_uint64,
    ctypes.c_char_p,
]
lib.totaldrop_win_router_set_activity_json.restype = ctypes.c_void_p

lib.totaldrop_win_router_drain_ndjson.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_router_drain_ndjson.restype = ctypes.c_void_p

lib.totaldrop_win_router_destroy.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_router_destroy.restype = ctypes.c_int32


def take_str(ptr):
    if not ptr:
        raise ValueError("FFI returned null pointer during live smoke test")
    try:
        raw = ctypes.cast(ptr, ctypes.c_char_p).value
        if raw is None:
            raise ValueError("FFI returned empty C string")
        return raw.decode("utf-8")
    finally:
        lib.totaldrop_win_string_free(ptr)


def take_json(ptr):
    return json.loads(take_str(ptr))


# Null free must be safe.
lib.totaldrop_win_string_free(None)

ver = take_json(lib.totaldrop_win_version_json())
assert ver == {
    "app_version": expected_app,
    "core_version": expected_core,
    "msix_version": expected_msix,
}, f"unexpected version JSON: {ver}"

uri_ok = take_json(lib.totaldrop_win_validate_uri_json(b"totaldrop://r/7-harbor-rocket"))
assert uri_ok.get("display_english") == "7-harbor-rocket", f"unexpected uri ok: {uri_ok}"

uri_bad = take_json(lib.totaldrop_win_validate_uri_json(b"https://evil.example/r#7-harbor-rocket"))
assert uri_bad.get("ok") is False, f"expected error envelope for evil URI: {uri_bad}"

input_ok = take_json(lib.totaldrop_win_validate_input_json(b"7 harbor rocket"))
assert input_ok.get("canonical") == "7-840-1499", f"unexpected input ok: {input_ok}"

pct = take_json(lib.totaldrop_win_format_percent_json(999_999, 1_000_000, b"tr-TR"))
assert pct == {"whole": 99, "formatted": "%99"}, f"unexpected #483 percent JSON: {pct}"

ar_bundle = take_json(lib.totaldrop_win_ui_bundle_json(b"ar-SA,en-US", b"ar-EG", None))
assert ar_bundle.get("language_tag") == "ar", f"unexpected ar bundle: {ar_bundle}"
assert ar_bundle.get("flow_direction") == "RightToLeft"
assert ar_bundle.get("verification_title") == "Verification words"

clip_ok = take_json(lib.totaldrop_win_extract_clipboard_code_json(b"Code: 7-harbor-rocket"))
assert clip_ok.get("display_english") == "7-harbor-rocket", f"unexpected clipboard ok: {clip_ok}"

comp_ok = take_json(lib.totaldrop_win_code_completions_json(b"harb", 4))
assert comp_ok == ["harbor"], f"unexpected completions: {comp_ok}"

bytes_de = take_json(lib.totaldrop_win_format_bytes_json(1_500_000, b"en-US", b"de-DE"))
assert bytes_de == {"bytes": 1_500_000, "formatted": "1,5 MB"}, f"unexpected bytes JSON: {bytes_de}"

msg_ok = take_json(
    lib.totaldrop_win_format_message_json(
        b"sendDoneBody", b'{"count":3}', b"en-US", b"en-US"
    )
)
assert msg_ok.get("formatted") == "All 3 files arrived intact.", f"unexpected message JSON: {msg_ok}"

fn_ok = take_json(lib.totaldrop_win_sanitize_filename_json("invoice\u202efdp.exe".encode("utf-8")))
assert fn_ok.get("has_hidden_controls") is True and "<U+202E>" in fn_ok.get("sanitized", "")

txt_ok = take_json(lib.totaldrop_win_sanitize_text_json(b"hello\r\nworld"))
assert txt_ok == {"display_text": "hello\nworld", "shortened": False, "has_hidden_controls": False}

srv_ok = take_json(lib.totaldrop_win_validate_server_url_json(b"wss://rendezvous.totaldrop.app"))
assert srv_ok == {"ok": True}, f"unexpected server url ok: {srv_ok}"

srv_bad = take_json(lib.totaldrop_win_validate_server_url_json(b"wss://user@host"))
assert srv_bad.get("ok") is False and srv_bad.get("error", {}).get("l10n_key") == "errorBadServer"

paths_ok = take_json(
    lib.totaldrop_win_validate_paths_json(b'["\\\\\\\\nas01\\\\team\\\\spec.docx"]')
)
assert len(paths_ok) == 1 and paths_ok[0].get("extended_path") == r"\\?\UNC\nas01\team\spec.docx"

assert lib.totaldrop_win_send_files_start(None, None, None, None) == 0
assert lib.totaldrop_win_send_text_start(None, None, None, None) == 0
assert lib.totaldrop_win_receive_connect_start(None, None, None, None) == 0
assert lib.totaldrop_win_receive_accept_files(0, None) == -1
assert lib.totaldrop_win_receive_accept_files(0, b"C:\\Downloads") == -3
assert lib.totaldrop_win_receive_accept_text(0) == -3
assert lib.totaldrop_win_receive_decline(0) == -3
poll_bad = take_json(lib.totaldrop_win_session_poll_events_ndjson(0))
assert poll_bad.get("ok") is False and poll_bad.get("error", {}).get("kind") == "invalid_handle", (
    f"unexpected poll invalid_handle JSON: {poll_bad}"
)
assert lib.totaldrop_win_session_cancel(0) == -3
assert lib.totaldrop_win_session_destroy(0) == -3

# Phase 3 router live C ABI smoke test
router_id = lib.totaldrop_win_router_create(1, b"en-US", b"en-US", None, True)
assert router_id > 0, f"expected non-zero router handle, got {router_id}"

initial_ndjson = take_str(lib.totaldrop_win_router_drain_ndjson(router_id))
assert len(initial_ndjson.splitlines()) == 2

loc_msg = take_json(lib.totaldrop_win_router_update_locale_json(router_id, b"tr-TR", b"tr-TR"))
assert loc_msg.get("kind") == "ui_bundle_ready"
assert loc_msg.get("data", {}).get("language_tag") == "tr"

act_msg = take_json(
    lib.totaldrop_win_router_set_activity_json(
        router_id, b'{"state":"transferring","done_bytes":512,"total_bytes":4096}'
    )
)
assert act_msg.get("kind") == "mark_animation_state"
assert act_msg.get("data", {}).get("animate") is True

anim_off = take_json(lib.totaldrop_win_router_set_animations_json(router_id, False))
assert anim_off.get("data", {}).get("animate") is False

idle_msg = take_json(lib.totaldrop_win_router_set_activity_json(router_id, b'{"state":"idle"}'))
assert idle_msg.get("data", {}).get("animate") is False

payload = b'{"version":1,"payload":{"kind":"share_target","paths":["\\\\\\\\nas01\\\\share\\\\a.txt"],"text":null}}'
frame = struct.pack("<I", len(payload)) + payload
buf = ctypes.create_string_buffer(frame)
decs = take_json(lib.totaldrop_win_router_ingest_ipc_bytes_json(router_id, ctypes.byref(buf), len(frame)))
assert isinstance(decs, list) and len(decs) == 1
assert decs[0].get("decision") == "navigate_send_files"
assert decs[0].get("paths") == [r"\\?\UNC\nas01\share\a.txt"]

# 0-byte EOF flush with null pointer must succeed cleanly.
eof_ok = take_json(lib.totaldrop_win_router_ingest_ipc_bytes_json(router_id, None, 0))
assert eof_ok == []

assert lib.totaldrop_win_router_destroy(router_id) == 0
assert lib.totaldrop_win_router_destroy(router_id) == -3
assert lib.totaldrop_win_shutdown(100) == 0
"""

_COM_SMOKE_TEST_CHILD_SCRIPT = r"""
import ctypes
import sys
import uuid


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_str(cls, text: str) -> "GUID":
        raw = uuid.UUID(text).bytes_le
        return cls.from_buffer_copy(raw)

    def to_str(self) -> str:
        return str(uuid.UUID(bytes_le=bytes(self)))


dll_path, expected_clsid = sys.argv[1:3]
mod = ctypes.WinDLL(dll_path)
ole32 = ctypes.WinDLL("ole32.dll")
shell32 = ctypes.WinDLL("shell32.dll")
user32 = ctypes.WinDLL("user32.dll")

ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
ole32.CoTaskMemFree.restype = None

shell32.ExtractIconExW.argtypes = [
    ctypes.c_wchar_p,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_uint,
]
shell32.ExtractIconExW.restype = ctypes.c_uint

user32.DestroyIcon.argtypes = [ctypes.c_void_p]
user32.DestroyIcon.restype = ctypes.c_int

mod.DllCanUnloadNow.argtypes = []
mod.DllCanUnloadNow.restype = ctypes.c_int32

mod.DllGetClassObject.argtypes = [
    ctypes.POINTER(GUID),
    ctypes.POINTER(GUID),
    ctypes.POINTER(ctypes.c_void_p),
]
mod.DllGetClassObject.restype = ctypes.c_int32

assert mod.DllCanUnloadNow() == 0, "expected S_OK before instantiating COM objects"

clsid = GUID.from_str(expected_clsid)
iid_factory = GUID.from_str("00000001-0000-0000-c000-000000000046")
iid_cmd = GUID.from_str("a08ce4d0-fa25-44ab-b57c-c7b1c323e0b9")

factory_ptr = ctypes.c_void_p()
hr = mod.DllGetClassObject(ctypes.byref(clsid), ctypes.byref(iid_factory), ctypes.byref(factory_ptr))
assert hr == 0 and factory_ptr.value, f"DllGetClassObject failed: hr={hr:#x}"
assert mod.DllCanUnloadNow() == 1, "expected S_FALSE while factory is alive"

factory_vtbl = ctypes.cast(
    ctypes.cast(factory_ptr, ctypes.POINTER(ctypes.c_void_p)).contents.value,
    ctypes.POINTER(ctypes.c_void_p),
)
ReleaseFn = ctypes.WINFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)
CreateInstanceFn = ctypes.WINFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(GUID),
    ctypes.POINTER(ctypes.c_void_p),
)

cmd_ptr = ctypes.c_void_p()
create_inst = CreateInstanceFn(factory_vtbl[3])
hr = create_inst(factory_ptr, None, ctypes.byref(iid_cmd), ctypes.byref(cmd_ptr))
assert hr == 0 and cmd_ptr.value, f"IClassFactory::CreateInstance failed: hr={hr:#x}"

cmd_vtbl = ctypes.cast(
    ctypes.cast(cmd_ptr, ctypes.POINTER(ctypes.c_void_p)).contents.value,
    ctypes.POINTER(ctypes.c_void_p),
)
GetTitleFn = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
GetIconFn = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
GetCanonicalFn = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(GUID))
GetStateFn = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32))
GetFlagsFn = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32))

out_guid = GUID()
assert GetCanonicalFn(cmd_vtbl[6])(cmd_ptr, ctypes.byref(out_guid)) == 0
assert out_guid.to_str().lower() == expected_clsid.lower(), f"canonical CLSID mismatch: {out_guid.to_str()}"

title_ptr = ctypes.c_void_p()
assert GetTitleFn(cmd_vtbl[3])(cmd_ptr, None, ctypes.byref(title_ptr)) == 0
assert title_ptr.value
title = ctypes.wstring_at(title_ptr.value)
ole32.CoTaskMemFree(title_ptr)
assert title.strip(), "GetTitle returned empty string"

icon_ptr = ctypes.c_void_p()
assert GetIconFn(cmd_vtbl[4])(cmd_ptr, None, ctypes.byref(icon_ptr)) == 0
assert icon_ptr.value
icon_spec = ctypes.wstring_at(icon_ptr.value)
ole32.CoTaskMemFree(icon_ptr)
assert icon_spec.endswith(",-101"), f"unexpected GetIcon spec: {icon_spec}"

large_ico = ctypes.c_void_p()
small_ico = ctypes.c_void_p()
extracted = shell32.ExtractIconExW(dll_path, -101, ctypes.byref(large_ico), ctypes.byref(small_ico), 1)
assert extracted >= 1, f"ExtractIconExW(dll, -101) failed: {extracted}"
if large_ico.value:
    user32.DestroyIcon(large_ico)
if small_ico.value:
    user32.DestroyIcon(small_ico)

state = ctypes.c_int32(-1)
assert GetStateFn(cmd_vtbl[7])(cmd_ptr, None, 0, ctypes.byref(state)) == 0
assert state.value == 2, f"expected ECS_HIDDEN (2) for null array, got {state.value}"

flags = ctypes.c_int32(-1)
assert GetFlagsFn(cmd_vtbl[9])(cmd_ptr, ctypes.byref(flags)) == 0
assert flags.value == 0, f"expected ECF_DEFAULT (0), got {flags.value}"

ReleaseFn(cmd_vtbl[2])(cmd_ptr)
ReleaseFn(factory_vtbl[2])(factory_ptr)
assert mod.DllCanUnloadNow() == 0, "expected S_OK after releasing all COM instances"
"""


def _python_host_arch() -> str | None:
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        return "x64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    return None


def _validate_msix_version_quad(version: str, label: str, *, store_mode: bool) -> None:
    if not isinstance(version, str) or not QUAD_RE.fullmatch(version):
        raise ValueError(
            f"{label}: invalid MSIX version {version!r} (expected Major.Minor.Build.Revision)"
        )
    parts = version.split(".")
    nums: list[int] = []
    for part in parts:
        if len(part) > 1 and part.startswith("0"):
            raise ValueError(f"{label}: leading zero not permitted in version component {part!r}")
        val = int(part)
        if val < 0 or val > 65535:
            raise ValueError(
                f"{label}: version component {val} outside 0..=65535 uint16 quad bounds"
            )
        nums.append(val)
    if store_mode:
        if nums[0] < 1:
            raise ValueError(
                f"{label}: Store MSIX version {version!r} violates Microsoft Store Major >= 1 requirement"
            )
        if nums[3] != 0:
            raise ValueError(
                f"{label}: Store MSIX version {version!r} violates Microsoft Store Revision == 0 requirement"
            )


def _validate_x500_publisher(publisher: str, label: str) -> None:
    if not isinstance(publisher, str) or not publisher.strip():
        raise ValueError(f"{label}: Publisher must be a non-empty X.500 CN=... distinguished name")
    if len(publisher) > 8192:
        raise ValueError(f"{label}: Publisher exceeds 8192 characters")
    for ch in publisher:
        cp = ord(ch)
        if (
            cp < 0x20
            or cp == 0x7F
            or 0x202A <= cp <= 0x202E
            or 0x2066 <= cp <= 0x2069
            or cp == 0x061C
        ):
            raise ValueError(f"{label}: Publisher contains forbidden control/Bidi char U+{cp:04X}")
    if UNSIGNED_PACKAGE_OID in publisher.lower():
        raise ValueError(
            f"{label}: Publisher contains forbidden unsigned-package OID {UNSIGNED_PACKAGE_OID}"
        )

    rdns: list[str] = []
    buf: list[str] = []
    in_quotes = False
    escaped = False
    for ch in publisher:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\":
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
            continue
        if ch == "," and not in_quotes:
            rdns.append("".join(buf).strip())
            buf.clear()
            continue
        buf.append(ch)
    if in_quotes or escaped:
        raise ValueError(f"{label}: malformed X.500 Publisher {publisher!r} (unterminated quote/escape)")
    rdns.append("".join(buf).strip())

    has_cn = False
    for rdn in rdns:
        if not rdn or not RDN_RE.fullmatch(rdn):
            raise ValueError(
                f"{label}: malformed X.500 Publisher RDN {rdn!r} in {publisher!r} (expected e.g. 'CN=...')"
            )
        key, val = rdn.split("=", 1)
        if key.strip().upper() == "CN" and val.strip():
            has_cn = True
    if not has_cn:
        raise ValueError(f"{label}: X.500 Publisher {publisher!r} must include a non-empty 'CN=' attribute")


def _validate_identity_store_policy(
    name: str,
    publisher: str,
    version: str,
    label: str,
    *,
    expected_version: str | None,
    store_mode: bool,
    allow_test_identity: bool,
) -> None:
    if not IDENTITY_NAME_RE.fullmatch(name):
        raise ValueError(f"{label}: invalid Identity/@Name {name!r}")
    _validate_x500_publisher(publisher, f"{label} Identity/@Publisher")
    _validate_msix_version_quad(version, f"{label} Identity/@Version", store_mode=store_mode)
    if expected_version is not None and version != expected_version:
        raise ValueError(
            f"{label}: Identity/@Version mismatch: {version!r} != {expected_version!r}"
        )
    if store_mode and not allow_test_identity:
        if publisher == "CN=TotalDrop" or name == "TotalDrop.TotalDrop":
            raise ValueError(
                f"{label}: Store-mode build refuses placeholder test identity "
                f"(Name={name!r}, Publisher={publisher!r}); supply Partner Center identity or pass --allow-test-identity"
            )


def _check_opc_zip_entries(
    zf: zipfile.ZipFile,
    label: str,
    *,
    flat_root_only: bool = False,
    case_sensitive_unique_paths: tuple[str, ...] = (),
) -> list[str]:
    bad_member = zf.testzip()
    if bad_member is not None:
        raise ValueError(f"{label}: corrupted ZIP member {bad_member!r}")

    raw_names = zf.namelist()
    seen_exact: set[str] = set()
    lower_counts: dict[str, int] = {}
    for name in raw_names:
        if name in seen_exact:
            raise ValueError(f"{label}: duplicate ZIP entry {name!r}")
        seen_exact.add(name)
        lower_name = name.lower()
        lower_counts[lower_name] = lower_counts.get(lower_name, 0) + 1

        if not name or name.startswith("/") or "\\" in name:
            raise ValueError(f"{label}: unsafe OPC/ZIP entry path {name!r}")
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in name):
            raise ValueError(f"{label}: non-ASCII or control char in ZIP entry name {name!r}")
        parts = name.split("/")
        if ".." in parts:
            raise ValueError(f"{label}: path traversal component in ZIP entry {name!r}")
        if flat_root_only and ("/" in name):
            raise ValueError(f"{label}: nested directory entry {name!r} not permitted (flat root files only)")

    for critical_path in case_sensitive_unique_paths:
        if lower_counts.get(critical_path.lower(), 0) > 1:
            raise ValueError(
                f"{label}: case-insensitive duplicate critical manifest entry {critical_path!r}"
            )
    return raw_names


def _canonicalize_manifest_for_parity(elem: ET.Element) -> tuple[object, ...]:
    """Return a canonical tree representation ignoring comments/whitespace and ONLY Identity/@ProcessorArchitecture."""
    attrs: list[tuple[str, str]] = []
    for k, v in sorted(elem.attrib.items()):
        if elem.tag == f"{APPX_NS}Identity" and k == "ProcessorArchitecture":
            continue
        attrs.append((k, v))
    text = (elem.text or "").strip()
    children = tuple(_canonicalize_manifest_for_parity(child) for child in elem)
    return (elem.tag, tuple(attrs), text, children)


def _parse_resource_directory(
    data: bytes, rsrc_off: int, rsrc_size: int
) -> tuple[set[int], set[tuple[int, int]]]:
    """Parse 2 levels of PE DataDirectory[2] Resource Directory (Type ID -> Name ID)."""
    resource_types: set[int] = set()
    resource_ids: set[tuple[int, int]] = set()
    if rsrc_size < 16 or rsrc_off + 16 > len(data):
        return resource_types, resource_ids

    def read_dir_entries(dir_off: int) -> list[tuple[int, int]]:
        if dir_off + 16 > len(data):
            return []
        _, _, _, _, n_named, n_id = struct.unpack_from("<IIHHHH", data, dir_off)
        total = n_named + n_id
        entries: list[tuple[int, int]] = []
        pos = dir_off + 16
        for _ in range(total):
            if pos + 8 > len(data):
                break
            name_or_id, offset_to_data = struct.unpack_from("<II", data, pos)
            entries.append((name_or_id, offset_to_data))
            pos += 8
        return entries

    for type_raw, type_sub in read_dir_entries(rsrc_off):
        if (type_raw & 0x8000_0000) != 0:
            continue
        type_id = type_raw & 0xFFFF
        resource_types.add(type_id)
        if (type_sub & 0x8000_0000) == 0:
            continue
        lvl2_off = rsrc_off + (type_sub & 0x7FFF_FFFF)
        for name_raw, _ in read_dir_entries(lvl2_off):
            if (name_raw & 0x8000_0000) != 0:
                continue
            resource_ids.add((type_id, name_raw & 0xFFFF))

    return resource_types, resource_ids


def parse_pe64_bytes(data: bytes, label: str) -> dict[str, object]:
    """Parse PE32+ headers, security flags, Debug Dir CET_COMPAT, Load Config, imports, exports, and resources."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{label}: missing MZ header")

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError(f"{label}: missing PE signature")

        coff_off = e_lfanew + 4
        machine, num_sections, _, _, _, opt_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, coff_off
        )
        opt_off = coff_off + 20
        if opt_off + 2 > len(data):
            raise ValueError(f"{label}: truncated PE optional header")
        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            raise ValueError(f"{label}: expected PE32+ (0x20B), got {magic:#x}")
        if opt_size < 112 or opt_off + opt_size > len(data):
            raise ValueError(f"{label}: truncated PE32+ optional header")

        dll_chars = struct.unpack_from("<H", data, opt_off + 70)[0]
        num_rvas = struct.unpack_from("<I", data, opt_off + 108)[0]
        data_dirs_off = opt_off + 112

        def data_dir(index: int) -> tuple[int, int]:
            off = data_dirs_off + index * 8
            if index >= num_rvas or off + 8 > opt_off + opt_size or off + 8 > len(data):
                return (0, 0)
            return struct.unpack_from("<II", data, off)

        sections: list[tuple[int, int, int, int]] = []
        sec_off = opt_off + opt_size
        if sec_off + num_sections * 40 > len(data):
            raise ValueError(f"{label}: truncated PE32+ section table")
        for i in range(num_sections):
            entry_off = sec_off + i * 40
            _, v_size, v_addr, raw_size, raw_ptr, _, _, _, _, _ = struct.unpack_from(
                "<8sIIIIIIHHI", data, entry_off
            )
            sections.append((v_addr, max(v_size, raw_size), raw_ptr, raw_size))

        def rva_to_off(rva: int) -> int | None:
            if rva == 0:
                return None
            for v_addr, span, raw_ptr, raw_size in sections:
                if v_addr <= rva < v_addr + span:
                    delta = rva - v_addr
                    if delta < raw_size and raw_ptr + delta < len(data):
                        return raw_ptr + delta
            return None

        def read_cstr(off: int | None) -> str:
            if off is None or off >= len(data):
                return ""
            end = data.find(b"\x00", off)
            if end == -1:
                return ""
            return data[off:end].decode("ascii", errors="replace")

        # Extended DllCharacteristics (CET_COMPAT) in Debug Directory Type == 20.
        ex_dll_chars = 0
        dbg_rva, dbg_size = data_dir(6)
        dbg_off = rva_to_off(dbg_rva)
        if dbg_off is not None and dbg_size >= 28:
            for i in range(dbg_size // 28):
                eoff = dbg_off + i * 28
                if eoff + 28 > len(data):
                    break
                _, _, _, _, dtype, size_of_data, addr_raw, ptr_raw = struct.unpack_from(
                    "<IIHHIIII", data, eoff
                )
                if dtype == IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS and size_of_data >= 4:
                    val_off = ptr_raw if ptr_raw != 0 else rva_to_off(addr_raw)
                    if val_off is not None and val_off + 4 <= len(data):
                        ex_dll_chars |= struct.unpack_from("<I", data, val_off)[0]

        # Load Config DependentLoadFlags (offset 0x4E in IMAGE_LOAD_CONFIG_DIRECTORY64;
        # minimum struct size 0x50 = 80 bytes per Microsoft PE32+ specification).
        # Note: MSVC link.exe historically sets DataDirectory[10].Size = 0x40 while
        # the struct's own Size header field holds the full >= 0x50 length, whereas
        # DataDirectory[10].Size == 0 disables Load Config in the Windows PE loader.
        dependent_load_flags: int | None = None
        lc_rva, lc_dir_size = data_dir(10)
        lc_off = rva_to_off(lc_rva)
        if lc_dir_size > 0 and lc_off is not None and lc_off + 4 <= len(data):
            lc_struct_size = struct.unpack_from("<I", data, lc_off)[0]
            if lc_struct_size >= 0x50 and lc_off + 0x50 <= len(data):
                dependent_load_flags = struct.unpack_from("<H", data, lc_off + 0x4E)[0]

        # Standard Import Directory (DataDirectory[1]).
        imports: list[str] = []
        imp_rva, _ = data_dir(1)
        imp_off = rva_to_off(imp_rva)
        if imp_off is not None:
            pos = imp_off
            while pos + 20 <= len(data):
                oft, ts, fwd, name_rva, ft = struct.unpack_from("<IIIII", data, pos)
                if (oft, ts, fwd, name_rva, ft) == (0, 0, 0, 0, 0):
                    break
                dll_name = read_cstr(rva_to_off(name_rva)).lower()
                if dll_name:
                    imports.append(dll_name)
                pos += 20

        # Delay-Import Directory (DataDirectory[13]).
        delay_imports: list[str] = []
        dimp_rva, _ = data_dir(13)
        dimp_off = rva_to_off(dimp_rva)
        if dimp_off is not None:
            pos = dimp_off
            while pos + 32 <= len(data):
                attrs, dll_name_rva, _, _, _, _, _, _ = struct.unpack_from("<IIIIIIII", data, pos)
                if attrs == 0 and dll_name_rva == 0:
                    break
                dll_name = read_cstr(rva_to_off(dll_name_rva)).lower()
                if dll_name:
                    delay_imports.append(dll_name)
                pos += 32

        # Export Directory (DataDirectory[0]).
        exports: list[str] = []
        exp_rva, _ = data_dir(0)
        exp_off = rva_to_off(exp_rva)
        if exp_off is not None and exp_off + 40 <= len(data):
            num_names = struct.unpack_from("<I", data, exp_off + 24)[0]
            names_rva = struct.unpack_from("<I", data, exp_off + 32)[0]
            names_off = rva_to_off(names_rva)
            if names_off is not None:
                for i in range(num_names):
                    if names_off + i * 4 + 4 > len(data):
                        break
                    sym_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
                    sym = read_cstr(rva_to_off(sym_rva))
                    if sym:
                        exports.append(sym)

        # Resource Directory (DataDirectory[2]).
        rsrc_rva, rsrc_size = data_dir(2)
        rsrc_off = rva_to_off(rsrc_rva)
        resource_types: set[int] = set()
        resource_ids: set[tuple[int, int]] = set()
        if rsrc_off is not None and rsrc_size >= 16:
            resource_types, resource_ids = _parse_resource_directory(data, rsrc_off, rsrc_size)

        clr_rva, clr_size = data_dir(14)
    except struct.error as exc:
        raise ValueError(f"{label}: truncated or malformed PE32+ binary: {exc}") from exc

    return {
        "machine": machine,
        "characteristics": characteristics,
        "dll_chars": dll_chars,
        "ex_dll_chars": ex_dll_chars,
        "dependent_load_flags": dependent_load_flags,
        "imports": imports,
        "delay_imports": delay_imports,
        "exports": exports,
        "resource_types": resource_types,
        "resource_ids": resource_ids,
        "clr_header": (clr_rva, clr_size),
    }


def parse_pe64(path: Path) -> dict[str, object]:
    return parse_pe64_bytes(path.read_bytes(), path.name)


def verify_manifest_extensions(manifest_root: ET.Element) -> None:
    """Validate Explorer COM, FileExplorerContextMenus, Toast Activation, runFullTrust, and scoped FirewallRules."""
    appx_ns = APPX_NS
    uap_ns = "{http://schemas.microsoft.com/appx/manifest/uap/windows10}"
    com_ns = "{http://schemas.microsoft.com/appx/manifest/com/windows10}"
    desktop_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10}"
    desktop2_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10/2}"
    desktop4_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10/4}"
    desktop5_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10/5}"
    rescap_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities}"

    if manifest_root.tag != f"{appx_ns}Package":
        raise ValueError(f"AppxManifest.xml root must be <Package>, got {manifest_root.tag!r}")

    doc_applications = manifest_root.findall(f".//{appx_ns}Applications")
    direct_applications = manifest_root.findall(f"{appx_ns}Applications")
    if len(doc_applications) != 1 or len(direct_applications) != 1:
        raise ValueError(
            "AppxManifest.xml must contain exactly 1 top-level <Applications> element "
            f"(doc={len(doc_applications)}, direct={len(direct_applications)})"
        )

    doc_apps = manifest_root.findall(f".//{appx_ns}Application")
    direct_apps = manifest_root.findall(f"{appx_ns}Applications/{appx_ns}Application")
    if len(doc_apps) != 1 or len(direct_apps) != 1:
        raise ValueError(
            "AppxManifest.xml must contain exactly 1 <Application> under <Applications> "
            f"(doc={len(doc_apps)}, direct={len(direct_apps)})"
        )
    app = direct_apps[0]
    if app.attrib.get("Executable") != "totaldrop-winui.exe":
        raise ValueError(
            f"AppxManifest.xml <Application> Executable mismatch: {app.attrib.get('Executable')!r}"
        )

    app_exts = app.findall(f"{appx_ns}Extensions")
    if len(app_exts) != 1:
        raise ValueError(
            f"AppxManifest.xml <Application> must contain exactly 1 <Extensions>, found {len(app_exts)}"
        )
    pkg_exts = manifest_root.findall(f"{appx_ns}Extensions")
    if len(pkg_exts) != 1:
        raise ValueError(
            f"AppxManifest.xml <Package> must contain exactly 1 <Extensions>, found {len(pkg_exts)}"
        )
    doc_exts = manifest_root.findall(f".//{appx_ns}Extensions")
    if len(doc_exts) != 2:
        raise ValueError(
            f"AppxManifest.xml must contain exactly 2 <Extensions> containers total, found {len(doc_exts)}"
        )
    app_ext = app_exts[0]
    pkg_ext = pkg_exts[0]

    allowed_app_ext_tags = {
        f"{uap_ns}Extension",
        f"{com_ns}Extension",
        f"{desktop4_ns}Extension",
        f"{desktop_ns}Extension",
    }
    unexpected_app_exts = [child.tag for child in app_ext if child.tag not in allowed_app_ext_tags]
    if unexpected_app_exts:
        raise ValueError(
            "AppxManifest.xml Applications/Application/Extensions contains unexpected extension(s): "
            f"{unexpected_app_exts!r}"
        )

    # 2. com:Extension (windows.comServer): exact 1 SurrogateServer (1 Class) + 1 ExeServer (1 Class).
    doc_com_exts = manifest_root.findall(f".//{com_ns}Extension")
    app_com_exts = app_ext.findall(f"{com_ns}Extension")
    if len(doc_com_exts) != 1 or len(app_com_exts) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <com:Extension> directly under "
            f"Applications/Application/Extensions (doc={len(doc_com_exts)}, app={len(app_com_exts)})"
        )
    com_ext = app_com_exts[0]
    if com_ext.attrib.get("Category") != "windows.comServer":
        raise ValueError(
            f"<com:Extension> Category must be 'windows.comServer', got {com_ext.attrib.get('Category')!r}"
        )

    doc_com_servers = manifest_root.findall(f".//{com_ns}ComServer")
    child_com_servers = com_ext.findall(f"{com_ns}ComServer")
    if len(doc_com_servers) != 1 or len(child_com_servers) != 1 or len(list(com_ext)) != 1:
        raise ValueError(
            "AppxManifest.xml <com:Extension> must contain exactly 1 <com:ComServer> as its sole child "
            f"(doc={len(doc_com_servers)}, direct={len(child_com_servers)}, children={len(list(com_ext))})"
        )
    com_server = child_com_servers[0]
    com_children = list(com_server)
    if len(com_children) != 2:
        raise ValueError(
            "AppxManifest.xml <com:ComServer> must contain exactly 2 children "
            f"(1 ExeServer + 1 SurrogateServer), found {len(com_children)}"
        )
    if [child.tag for child in com_children] != [
        f"{com_ns}ExeServer",
        f"{com_ns}SurrogateServer",
    ]:
        raise ValueError(
            "AppxManifest.xml <com:ComServer> must declare <com:ExeServer> before "
            "<com:SurrogateServer> per ComManifestSchema.xsd CT_ComServer sequence"
        )

    doc_surrogates = manifest_root.findall(f".//{com_ns}SurrogateServer")
    child_surrogates = com_server.findall(f"{com_ns}SurrogateServer")
    if len(doc_surrogates) != 1 or len(child_surrogates) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <com:SurrogateServer> directly under <com:ComServer> "
            f"(doc={len(doc_surrogates)}, direct={len(child_surrogates)})"
        )
    surrogate = child_surrogates[0]
    surrogate_classes = surrogate.findall(f"{com_ns}Class")
    if len(list(surrogate)) != 1 or len(surrogate_classes) != 1:
        raise ValueError(
            "AppxManifest.xml <com:SurrogateServer> must contain exactly 1 <com:Class> as its sole child "
            f"(children={len(list(surrogate))}, classes={len(surrogate_classes)})"
        )
    explorer_cls = surrogate_classes[0]
    if len(list(explorer_cls)) != 0:
        raise ValueError("Explorer <com:Class> must not contain child elements")
    explorer_id = explorer_cls.attrib.get("Id", "")
    if not BARE_GUID_RE.fullmatch(explorer_id):
        raise ValueError(f"Explorer COM Class Id must be a bare GUID without braces, got {explorer_id!r}")
    if explorer_id.lower() != EXPECTED_EXPLORER_CLSID:
        raise ValueError(
            f"Explorer COM Class Id mismatch: {explorer_id!r} != {EXPECTED_EXPLORER_CLSID!r}"
        )
    if explorer_cls.attrib.get("Path") != "totaldrop_explorer_ext.dll":
        raise ValueError(f"Explorer COM Path mismatch: {explorer_cls.attrib.get('Path')!r}")
    if explorer_cls.attrib.get("ThreadingModel") != "STA":
        raise ValueError(
            f"Explorer COM ThreadingModel must be 'STA', got {explorer_cls.attrib.get('ThreadingModel')!r}"
        )

    doc_exe_servers = manifest_root.findall(f".//{com_ns}ExeServer")
    child_exe_servers = com_server.findall(f"{com_ns}ExeServer")
    if len(doc_exe_servers) != 1 or len(child_exe_servers) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <com:ExeServer> directly under <com:ComServer> "
            f"(doc={len(doc_exe_servers)}, direct={len(child_exe_servers)})"
        )
    exe_server = child_exe_servers[0]
    if exe_server.attrib.get("Executable") != "totaldrop-winui.exe":
        raise ValueError(f"Toast ExeServer Executable mismatch: {exe_server.attrib.get('Executable')!r}")
    if exe_server.attrib.get("Arguments") != "----AppNotificationActivated:":
        raise ValueError(f"Toast ExeServer Arguments mismatch: {exe_server.attrib.get('Arguments')!r}")
    exe_classes = exe_server.findall(f"{com_ns}Class")
    if len(list(exe_server)) != 1 or len(exe_classes) != 1:
        raise ValueError(
            "AppxManifest.xml <com:ExeServer> must contain exactly 1 <com:Class> as its sole child "
            f"(children={len(list(exe_server))}, classes={len(exe_classes)})"
        )
    toast_cls = exe_classes[0]
    if len(list(toast_cls)) != 0:
        raise ValueError("Toast ExeServer <com:Class> must not contain child elements")
    toast_cls_id = toast_cls.attrib.get("Id", "")
    if not BARE_GUID_RE.fullmatch(toast_cls_id):
        raise ValueError(f"Toast ExeServer Class Id must be a bare GUID without braces, got {toast_cls_id!r}")
    if toast_cls_id.lower() != EXPECTED_TOAST_CLSID:
        raise ValueError(
            f"Toast ExeServer Class Id mismatch: {toast_cls_id!r} != {EXPECTED_TOAST_CLSID!r}"
        )

    doc_com_classes = manifest_root.findall(f".//{com_ns}Class")
    if len(doc_com_classes) != 2:
        raise ValueError(
            f"AppxManifest.xml must declare exactly 2 <com:Class> elements total, found {len(doc_com_classes)}"
        )
    doc_com_all = [el for el in manifest_root.iter() if el.tag.startswith(com_ns)]
    if len(doc_com_all) != 6:
        raise ValueError(
            f"AppxManifest.xml contains unexpected com:* elements (expected 6 total, found {len(doc_com_all)})"
        )

    # 3. desktop4:Extension (windows.fileExplorerContextMenus): exact 2 ItemTypes (* and Directory), 1 Verb each.
    doc_d4_exts = manifest_root.findall(f".//{desktop4_ns}Extension")
    app_d4_exts = app_ext.findall(f"{desktop4_ns}Extension")
    if len(doc_d4_exts) != 1 or len(app_d4_exts) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <desktop4:Extension> directly under "
            f"Applications/Application/Extensions (doc={len(doc_d4_exts)}, app={len(app_d4_exts)})"
        )
    d4_ext = app_d4_exts[0]
    if d4_ext.attrib.get("Category") != "windows.fileExplorerContextMenus":
        raise ValueError(
            "<desktop4:Extension> Category must be 'windows.fileExplorerContextMenus', "
            f"got {d4_ext.attrib.get('Category')!r}"
        )
    doc_ctx_menus = manifest_root.findall(f".//{desktop4_ns}FileExplorerContextMenus")
    child_ctx_menus = d4_ext.findall(f"{desktop4_ns}FileExplorerContextMenus")
    if len(doc_ctx_menus) != 1 or len(child_ctx_menus) != 1 or len(list(d4_ext)) != 1:
        raise ValueError(
            "AppxManifest.xml <desktop4:Extension> must contain exactly 1 <desktop4:FileExplorerContextMenus> "
            f"as its sole child (doc={len(doc_ctx_menus)}, direct={len(child_ctx_menus)}, children={len(list(d4_ext))})"
        )
    ctx_menus = child_ctx_menus[0]
    doc_item_types = manifest_root.findall(f".//{desktop5_ns}ItemType")
    child_item_types = ctx_menus.findall(f"{desktop5_ns}ItemType")
    if len(list(ctx_menus)) != 2 or len(doc_item_types) != 2 or len(child_item_types) != 2:
        raise ValueError(
            "AppxManifest.xml <desktop4:FileExplorerContextMenus> must contain exactly 2 <desktop5:ItemType> "
            f"children total (children={len(list(ctx_menus))}, doc={len(doc_item_types)}, direct={len(child_item_types)})"
        )
    seen_types: list[str | None] = [it.attrib.get("Type") for it in child_item_types]
    if set(seen_types) != {"*", "Directory"}:
        raise ValueError(
            f"<desktop5:ItemType> Type set must be exactly {{'*', 'Directory'}}, got {seen_types!r}"
        )
    verb_ids: set[str] = set()
    for item_type in child_item_types:
        verbs = item_type.findall(f"{desktop5_ns}Verb")
        if len(list(item_type)) != 1 or len(verbs) != 1:
            raise ValueError(
                f"<desktop5:ItemType Type={item_type.attrib.get('Type')!r}> must contain exactly 1 "
                f"<desktop5:Verb> as its sole child (children={len(list(item_type))}, verbs={len(verbs)})"
            )
        verb = verbs[0]
        if len(list(verb)) != 0:
            raise ValueError("<desktop5:Verb> must not contain child elements")
        verb_id = verb.attrib.get("Id", "")
        if not verb_id.strip():
            raise ValueError(
                f"<desktop5:Verb> under Type={item_type.attrib.get('Type')!r} must have a non-empty Id"
            )
        if verb_id in verb_ids:
            raise ValueError(f"Duplicate <desktop5:Verb> Id {verb_id!r}")
        verb_ids.add(verb_id)
        verb_clsid = verb.attrib.get("Clsid", "")
        if not BARE_GUID_RE.fullmatch(verb_clsid):
            raise ValueError(
                f"<desktop5:Verb> Clsid must be a bare GUID without braces, got {verb_clsid!r}"
            )
        if verb_clsid.lower() != EXPECTED_EXPLORER_CLSID:
            raise ValueError(
                f"<desktop5:Verb> Clsid mismatch: {verb_clsid!r} != {EXPECTED_EXPLORER_CLSID!r}"
            )

    doc_verbs = manifest_root.findall(f".//{desktop5_ns}Verb")
    if len(doc_verbs) != 2:
        raise ValueError(
            f"AppxManifest.xml must declare exactly 2 <desktop5:Verb> elements total, found {len(doc_verbs)}"
        )
    doc_d4_all = [el for el in manifest_root.iter() if el.tag.startswith(desktop4_ns)]
    if len(doc_d4_all) != 2:
        raise ValueError(
            f"AppxManifest.xml contains unexpected desktop4:* elements (expected 2 total, found {len(doc_d4_all)})"
        )
    doc_d5_all = [el for el in manifest_root.iter() if el.tag.startswith(desktop5_ns)]
    if len(doc_d5_all) != 4:
        raise ValueError(
            f"AppxManifest.xml contains unexpected desktop5:* elements (expected 4 total, found {len(doc_d5_all)})"
        )

    # 4. desktop:Extension (windows.toastNotificationActivation) matching com:ExeServer Class Id.
    doc_d_exts = manifest_root.findall(f".//{desktop_ns}Extension")
    app_d_exts = app_ext.findall(f"{desktop_ns}Extension")
    if len(doc_d_exts) != 1 or len(app_d_exts) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <desktop:Extension> directly under "
            f"Applications/Application/Extensions (doc={len(doc_d_exts)}, app={len(app_d_exts)})"
        )
    d_ext = app_d_exts[0]
    if d_ext.attrib.get("Category") != "windows.toastNotificationActivation":
        raise ValueError(
            "<desktop:Extension> Category must be 'windows.toastNotificationActivation', "
            f"got {d_ext.attrib.get('Category')!r}"
        )
    doc_toasts = manifest_root.findall(f".//{desktop_ns}ToastNotificationActivation")
    child_toasts = d_ext.findall(f"{desktop_ns}ToastNotificationActivation")
    if len(doc_toasts) != 1 or len(child_toasts) != 1 or len(list(d_ext)) != 1:
        raise ValueError(
            "AppxManifest.xml <desktop:Extension> must contain exactly 1 <desktop:ToastNotificationActivation> "
            f"as its sole child (doc={len(doc_toasts)}, direct={len(child_toasts)}, children={len(list(d_ext))})"
        )
    toast_elem = child_toasts[0]
    if len(list(toast_elem)) != 0:
        raise ValueError("<desktop:ToastNotificationActivation> must not contain child elements")
    toast_guid = toast_elem.attrib.get("ToastActivatorCLSID", "")
    if not BARE_GUID_RE.fullmatch(toast_guid):
        raise ValueError(f"ToastActivatorCLSID must be a bare GUID without braces, got {toast_guid!r}")
    if toast_guid.lower() != EXPECTED_TOAST_CLSID:
        raise ValueError(f"ToastActivatorCLSID mismatch: {toast_guid!r} != {EXPECTED_TOAST_CLSID!r}")
    if toast_guid.lower() == EXPECTED_EXPLORER_CLSID:
        raise ValueError("ToastActivatorCLSID must be distinct from Explorer COM CLSID")
    if toast_guid.lower() != toast_cls_id.lower():
        raise ValueError(
            f"ToastActivatorCLSID ({toast_guid!r}) must match ExeServer/Class/@Id ({toast_cls_id!r})"
        )
    doc_d_all = [el for el in manifest_root.iter() if el.tag.startswith(desktop_ns)]
    if len(doc_d_all) != 2:
        raise ValueError(
            f"AppxManifest.xml contains unexpected desktop:* elements (expected 2 total, found {len(doc_d_all)})"
        )

    # 5. Package-level desktop2:Extension (windows.firewallRules): exact 1 FirewallRules + 1 scoped Rule.
    doc_d2_exts = manifest_root.findall(f".//{desktop2_ns}Extension")
    pkg_d2_exts = pkg_ext.findall(f"{desktop2_ns}Extension")
    if len(doc_d2_exts) != 1 or len(pkg_d2_exts) != 1 or len(list(pkg_ext)) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <desktop2:Extension> as the sole child of "
            f"Package/Extensions (doc={len(doc_d2_exts)}, pkg={len(pkg_d2_exts)}, pkg_children={len(list(pkg_ext))})"
        )
    d2_ext = pkg_d2_exts[0]
    if d2_ext.attrib.get("Category") != "windows.firewallRules":
        raise ValueError(
            "<desktop2:Extension> Category must be 'windows.firewallRules', "
            f"got {d2_ext.attrib.get('Category')!r}"
        )
    doc_fw_rules = manifest_root.findall(f".//{desktop2_ns}FirewallRules")
    child_fw_rules = d2_ext.findall(f"{desktop2_ns}FirewallRules")
    if len(doc_fw_rules) != 1 or len(child_fw_rules) != 1 or len(list(d2_ext)) != 1:
        raise ValueError(
            "AppxManifest.xml <desktop2:Extension> must contain exactly 1 <desktop2:FirewallRules> "
            f"as its sole child (doc={len(doc_fw_rules)}, direct={len(child_fw_rules)}, children={len(list(d2_ext))})"
        )
    fw_rules = child_fw_rules[0]
    if fw_rules.attrib.get("Executable") != "totaldrop-winui.exe":
        raise ValueError(f"FirewallRules Executable mismatch: {fw_rules.attrib.get('Executable')!r}")
    doc_rules = manifest_root.findall(f".//{desktop2_ns}Rule")
    child_rules = fw_rules.findall(f"{desktop2_ns}Rule")
    if len(doc_rules) != 1 or len(child_rules) != 1 or len(list(fw_rules)) != 1:
        raise ValueError(
            "AppxManifest.xml <desktop2:FirewallRules> must contain exactly 1 <desktop2:Rule> "
            f"as its sole child (doc={len(doc_rules)}, direct={len(child_rules)}, children={len(list(fw_rules))})"
        )
    rule = child_rules[0]
    if len(list(rule)) != 0:
        raise ValueError("<desktop2:Rule> must not contain child elements")
    if (
        rule.attrib.get("Direction") != "in"
        or rule.attrib.get("IPProtocol") != "UDP"
        or rule.attrib.get("Profile") != "private"
    ):
        raise ValueError(
            "FirewallRule must be strictly Direction='in', IPProtocol='UDP', Profile='private'; "
            f"got {rule.attrib!r}"
        )
    doc_d2_all = [el for el in manifest_root.iter() if el.tag.startswith(desktop2_ns)]
    if len(doc_d2_all) != 3:
        raise ValueError(
            f"AppxManifest.xml contains unexpected desktop2:* elements (expected 3 total, found {len(doc_d2_all)})"
        )

    # 6. Restricted capability runFullTrust (sole rescap:Capability under Package/Capabilities).
    doc_caps = manifest_root.findall(f".//{appx_ns}Capabilities")
    direct_caps = manifest_root.findall(f"{appx_ns}Capabilities")
    if len(doc_caps) != 1 or len(direct_caps) != 1:
        raise ValueError(
            "AppxManifest.xml must contain exactly 1 top-level <Capabilities> element "
            f"(doc={len(doc_caps)}, direct={len(direct_caps)})"
        )
    caps = direct_caps[0]
    doc_rescaps = manifest_root.findall(f".//{rescap_ns}Capability")
    direct_rescaps = caps.findall(f"{rescap_ns}Capability")
    if (
        len(doc_rescaps) != 1
        or len(direct_rescaps) != 1
        or direct_rescaps[0].attrib.get("Name") != "runFullTrust"
    ):
        raise ValueError(
            'AppxManifest.xml must declare exactly 1 <rescap:Capability Name="runFullTrust" /> '
            "under Package/Capabilities"
        )


def verify_pri_dump(pri_dump_path: Path) -> None:
    raw = pri_dump_path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    upper_text = text.upper()
    required_tokens = (
        "StoreLogo.png",
        "Square44x44Logo.png",
        "Square150x150Logo.png",
        "Wide310x150Logo.png",
        "Square71x71Logo.png",
        "Square310x310Logo.png",
        "App.xbf",
        "MainWindow.xbf",
        "SendPage.xbf",
        "ReceivePage.xbf",
        "SettingsPage.xbf",
    )
    missing = [tok for tok in required_tokens if tok not in text]
    for qualifier in ("UNPLATED", "LIGHTUNPLATED"):
        if not re.search(rf"(?<![A-Z0-9]){qualifier}(?![A-Z0-9])", upper_text):
            missing.append(qualifier)
    if missing:
        raise ValueError(f"resources.pri dump missing expected entries: {missing}")

    for lang_marker in ('"EN"', '"TR"', '"AR"', '"JA"', '"ZH-HANS"', '"ZH-HANT"'):
        if lang_marker not in upper_text:
            raise ValueError(f"resources.pri dump missing locale candidate {lang_marker}")


def smoke_test_ffi_dll(dll_path: Path) -> None:
    """Invoke live C ABI exports in a short-lived child subprocess."""
    subprocess.run(
        [
            sys.executable,
            "-c",
            _SMOKE_TEST_CHILD_SCRIPT,
            str(dll_path),
            EXPECTED_APP_VERSION,
            EXPECTED_CORE_VERSION,
            EXPECTED_MSIX_VERSION,
        ],
        check=True,
    )


def smoke_test_explorer_ext_dll(dll_path: Path) -> None:
    """Invoke live Win32 COM exports and ExtractIconExW(-101) in a short-lived child subprocess."""
    subprocess.run(
        [
            sys.executable,
            "-c",
            _COM_SMOKE_TEST_CHILD_SCRIPT,
            str(dll_path),
            EXPECTED_EXPLORER_CLSID,
        ],
        check=True,
    )


def _check_pe_common(label: str, pe: dict[str, object], expected_machine: int, arch: str, expect_dll: bool) -> None:
    if pe["machine"] != expected_machine:
        raise ValueError(f"{label}: expected machine {expected_machine:#x}, got {pe['machine']:#x}")
    chars = int(pe["characteristics"])  # type: ignore[arg-type]
    is_dll = (chars & IMAGE_FILE_DLL) != 0
    if is_dll != expect_dll:
        raise ValueError(f"{label}: IMAGE_FILE_DLL={is_dll}, expected {expect_dll}")
    dc = int(pe["dll_chars"])  # type: ignore[arg-type]
    for flag_name, flag_bit in (
        ("HIGH_ENTROPY_VA", IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
        ("DYNAMIC_BASE", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
        ("NX_COMPAT", IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
    ):
        if (dc & flag_bit) == 0:
            raise ValueError(f"{label}: missing PE hardening flag {flag_name} (DllCharacteristics={dc:#x})")
    if arch == "x64":
        ex_dc = int(pe["ex_dll_chars"])  # type: ignore[arg-type]
        if (ex_dc & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT) == 0:
            raise ValueError(
                f"{label}: missing CET_COMPAT in Debug Directory Type=20 (ex_dll_chars={ex_dc:#x})"
            )


def _check_no_forbidden_crt(label: str, pe: dict[str, object]) -> None:
    all_imports = set(pe["imports"]) | set(pe["delay_imports"])  # type: ignore[arg-type]
    bad_crt = sorted(
        imp for imp in all_imports if any(imp.startswith(f.replace(".dll", "")) for f in FORBIDDEN_CRT_DLLS)
    )
    if bad_crt:
        raise ValueError(f"{label} links dynamic MSVC CRT DLL(s): {bad_crt}")


def verify_msix_archive(
    source: Path | bytes,
    label: str,
    *,
    arch: str,
    expected_version: str | None,
    expect_signed: bool,
    store_mode: bool,
    allow_test_identity: bool,
    pri_dump: Path | None = None,
    run_live_smoke: bool = True,
) -> dict[str, object]:
    """Deep-verify a single-architecture .msix package (from disk Path or in-memory bytes)."""
    if isinstance(source, Path):
        if not source.is_file():
            raise ValueError(f"MSIX not found: {source}")
        raw_bytes = source.read_bytes()
    else:
        raw_bytes = source

    if len(raw_bytes) < 4 or raw_bytes[:4] != b"PK\x03\x04":
        raise ValueError(f"{label}: not a ZIP/OPC archive (magic={raw_bytes[:4]!r})")

    expected_machine = IMAGE_FILE_MACHINE_AMD64 if arch == "x64" else IMAGE_FILE_MACHINE_ARM64

    with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
        raw_names = _check_opc_zip_entries(
            zf,
            label,
            flat_root_only=False,
            case_sensitive_unique_paths=("AppxManifest.xml",),
        )
        names = set(raw_names)
        required = {
            "AppxManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
            "resources.pri",
            "totaldrop-winui.exe",
            "totaldrop_windows_ffi.dll",
            "totaldrop_explorer_ext.dll",
            "App.xbf",
            "MainWindow.xbf",
            "Views/SendPage.xbf",
            "Views/ReceivePage.xbf",
            "Views/SettingsPage.xbf",
        }
        if expect_signed:
            required.add("AppxSignature.p7x")

        missing = sorted(required - names)
        if missing:
            raise ValueError(f"{label}: MSIX missing required entries: {missing}")

        if expect_signed and zf.getinfo("AppxSignature.p7x").file_size <= 0:
            raise ValueError(f"{label}: AppxSignature.p7x is empty")

        asset_entries = {n for n in names if n.startswith("Assets/") and not n.endswith("/")}
        expected_asset_entries = {f"Assets/{name}" for name in EXPECTED_ASSETS}
        if asset_entries != expected_asset_entries:
            missing_assets = sorted(expected_asset_entries - asset_entries)
            extra_assets = sorted(asset_entries - expected_asset_entries)
            raise ValueError(
                f"{label}: MSIX Assets/ mismatch (expected {len(expected_asset_entries)} canonical Kose assets; "
                f"missing={missing_assets[:8]}, unexpected={extra_assets[:8]})"
            )

        forbidden_entries = [
            n
            for n in raw_names
            if n.lower().endswith(".pdb")
            or n.lower().endswith(".resw")
            or n.lower().endswith(FORBIDDEN_KEY_EXTS)
            or (
                Path(n.replace("\\", "/")).name.lower().startswith("resources.")
                and n.lower().endswith(".pri")
                and n.lower() != "resources.pri"
            )
        ]
        if forbidden_entries:
            raise ValueError(f"{label}: forbidden staging/key artifacts packed in MSIX: {forbidden_entries}")

        manifest_raw = zf.read("AppxManifest.xml").decode("utf-8", errors="strict")
        if UNSIGNED_PACKAGE_OID in manifest_raw.lower():
            raise ValueError(
                f"{label}: AppxManifest.xml contains forbidden unsigned-package OID {UNSIGNED_PACKAGE_OID}"
            )
        manifest_root = ET.fromstring(manifest_raw)

        doc_idents = manifest_root.findall(f".//{APPX_NS}Identity")
        direct_idents = manifest_root.findall(f"{APPX_NS}Identity")
        if len(doc_idents) != 1 or len(direct_idents) != 1:
            raise ValueError(
                f"{label}: AppxManifest.xml must declare exactly 1 top-level <Identity> "
                f"(doc={len(doc_idents)}, direct={len(direct_idents)})"
            )
        ident = direct_idents[0]
        actual_arch = ident.attrib.get("ProcessorArchitecture", "")
        if actual_arch != arch:
            raise ValueError(f"{label}: AppxManifest arch mismatch: {actual_arch!r} != {arch!r}")

        ident_name = ident.attrib.get("Name", "")
        ident_pub = ident.attrib.get("Publisher", "")
        ident_ver = ident.attrib.get("Version", "")
        _validate_identity_store_policy(
            ident_name,
            ident_pub,
            ident_ver,
            f"{label} AppxManifest.xml",
            expected_version=expected_version,
            store_mode=store_mode,
            allow_test_identity=allow_test_identity,
        )
        verify_manifest_extensions(manifest_root)

        ffi_bytes = zf.read("totaldrop_windows_ffi.dll")
        ext_bytes = zf.read("totaldrop_explorer_ext.dll")
        exe_bytes = zf.read("totaldrop-winui.exe")

        ffi_pe = parse_pe64_bytes(ffi_bytes, f"{label}:totaldrop_windows_ffi.dll")
        ext_pe = parse_pe64_bytes(ext_bytes, f"{label}:totaldrop_explorer_ext.dll")
        exe_pe = parse_pe64_bytes(exe_bytes, f"{label}:totaldrop-winui.exe")

        _check_pe_common(f"{label}:totaldrop_windows_ffi.dll", ffi_pe, expected_machine, arch, expect_dll=True)
        _check_pe_common(f"{label}:totaldrop_explorer_ext.dll", ext_pe, expected_machine, arch, expect_dll=True)
        _check_pe_common(f"{label}:totaldrop-winui.exe", exe_pe, expected_machine, arch, expect_dll=False)

        for dll_label, dll_pe in (
            (f"{label}:totaldrop_windows_ffi.dll", ffi_pe),
            (f"{label}:totaldrop_explorer_ext.dll", ext_pe),
        ):
            dep_flags = dll_pe["dependent_load_flags"]
            if not isinstance(dep_flags, int) or (dep_flags & LOAD_LIBRARY_SEARCH_SYSTEM32) == 0:
                raise ValueError(f"{dll_label}: missing DependentLoadFlags 0x800 (got {dep_flags!r})")
            _check_no_forbidden_crt(dll_label, dll_pe)

        _check_no_forbidden_crt(f"{label}:totaldrop-winui.exe", exe_pe)

        ffi_exports = set(ffi_pe["exports"])  # type: ignore[arg-type]
        missing_exports = [sym for sym in REQUIRED_FFI_EXPORTS if sym not in ffi_exports]
        if missing_exports:
            raise ValueError(f"{label}: totaldrop_windows_ffi.dll missing C ABI exports: {missing_exports}")

        ext_exports = set(ext_pe["exports"])  # type: ignore[arg-type]
        missing_ext_exports = [sym for sym in REQUIRED_EXPLORER_EXT_EXPORTS if sym not in ext_exports]
        if missing_ext_exports:
            raise ValueError(
                f"{label}: totaldrop_explorer_ext.dll missing COM exports: {missing_ext_exports}"
            )
        ext_rsrc_types = set(ext_pe["resource_types"])  # type: ignore[arg-type]
        ext_rsrc_ids = set(ext_pe["resource_ids"])  # type: ignore[arg-type]
        if (RT_GROUP_ICON, EXPLORER_ICON_RESOURCE_ID) not in ext_rsrc_ids or RT_ICON not in ext_rsrc_types:
            raise ValueError(
                f"{label}: totaldrop_explorer_ext.dll missing embedded Win32 icon resource ID 101 "
                f"(types={sorted(ext_rsrc_types)}, ids={sorted(ext_rsrc_ids)})"
            )

        if exe_pe["clr_header"] != (0, 0):
            raise ValueError(
                f"{label}: totaldrop-winui.exe has non-zero CLR header {exe_pe['clr_header']} (not Native AOT)"
            )
        exe_imports = set(exe_pe["imports"]) | set(exe_pe["delay_imports"])  # type: ignore[arg-type]
        bad_clr = sorted(imp for imp in exe_imports if imp in FORBIDDEN_CLR_HOST_DLLS)
        if bad_clr:
            raise ValueError(f"{label}: totaldrop-winui.exe imports CLR host DLL(s): {bad_clr}")
        exe_rsrc_types = set(exe_pe["resource_types"])  # type: ignore[arg-type]
        if RT_GROUP_ICON not in exe_rsrc_types or RT_ICON not in exe_rsrc_types:
            raise ValueError(
                f"{label}: totaldrop-winui.exe missing embedded application icon resources "
                f"(types={sorted(exe_rsrc_types)})"
            )

        if sys.platform == "win32" and run_live_smoke:
            host_arch = _python_host_arch()
            if host_arch == arch:
                with tempfile.TemporaryDirectory(prefix="totaldrop-msix-smoke-") as tmp:
                    tmp_dir = Path(tmp)
                    ffi_path = tmp_dir / "totaldrop_windows_ffi.dll"
                    ext_path = tmp_dir / "totaldrop_explorer_ext.dll"
                    ffi_path.write_bytes(ffi_bytes)
                    ext_path.write_bytes(ext_bytes)
                    smoke_test_ffi_dll(ffi_path)
                    smoke_test_explorer_ext_dll(ext_path)
            else:
                print(
                    f"note: skipping live ctypes smoke test for {label} (arch={arch}) on host Python arch={host_arch}; "
                    "all static PE32+, export, resource, and manifest checks passed."
                )

    if pri_dump is not None:
        verify_pri_dump(pri_dump)

    return {
        "arch": arch,
        "name": ident_name,
        "publisher": ident_pub,
        "version": ident_ver,
        "manifest_root": manifest_root,
        "size_bytes": len(raw_bytes),
    }


def verify_msixbundle_archive(
    source: Path | bytes,
    label: str,
    *,
    expected_version: str | None,
    expect_signed: bool,
    store_mode: bool,
    allow_test_identity: bool,
    run_live_smoke: bool = True,
) -> dict[str, object]:
    """Deep-verify a unified dual-arch (x64 + arm64) .msixbundle archive."""
    if isinstance(source, Path):
        if not source.is_file():
            raise ValueError(f"MSIX bundle not found: {source}")
        raw_bytes = source.read_bytes()
    else:
        raw_bytes = source

    if len(raw_bytes) < 4 or raw_bytes[:4] != b"PK\x03\x04":
        raise ValueError(f"{label}: not a ZIP/OPC .msixbundle archive (magic={raw_bytes[:4]!r})")

    with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
        raw_names = _check_opc_zip_entries(
            zf,
            label,
            flat_root_only=False,
            case_sensitive_unique_paths=("AppxMetadata/AppxBundleManifest.xml",),
        )
        names = set(raw_names)
        required = {
            "AppxMetadata/AppxBundleManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
        }
        if expect_signed:
            required.add("AppxSignature.p7x")
        missing = sorted(required - names)
        if missing:
            raise ValueError(f"{label}: .msixbundle missing required OPC entries: {missing}")
        if expect_signed and zf.getinfo("AppxSignature.p7x").file_size <= 0:
            raise ValueError(f"{label}: AppxSignature.p7x is empty")

        forbidden_bundle_exts = FORBIDDEN_KEY_EXTS + (".pdb", ".resw")
        bad_entries = [n for n in raw_names if n.lower().endswith(forbidden_bundle_exts)]
        if bad_entries:
            raise ValueError(f"{label}: forbidden key/symbol/staging files inside .msixbundle: {bad_entries}")

        manifest_raw = zf.read("AppxMetadata/AppxBundleManifest.xml").decode("utf-8", errors="strict")
        if UNSIGNED_PACKAGE_OID in manifest_raw.lower():
            raise ValueError(
                f"{label}: AppxBundleManifest.xml contains forbidden unsigned-package OID {UNSIGNED_PACKAGE_OID}"
            )
        bundle_root = ET.fromstring(manifest_raw)
        if bundle_root.tag != f"{BUNDLE_NS}Bundle":
            raise ValueError(
                f"{label}: AppxBundleManifest.xml root must be <Bundle>, got {bundle_root.tag!r}"
            )

        doc_idents = bundle_root.findall(f".//{BUNDLE_NS}Identity")
        direct_idents = bundle_root.findall(f"{BUNDLE_NS}Identity")
        if len(doc_idents) != 1 or len(direct_idents) != 1:
            raise ValueError(
                f"{label}: AppxBundleManifest.xml must declare exactly 1 top-level <Identity> "
                f"(doc={len(doc_idents)}, direct={len(direct_idents)})"
            )
        b_ident = direct_idents[0]
        b_name = b_ident.attrib.get("Name", "")
        b_pub = b_ident.attrib.get("Publisher", "")
        b_ver = b_ident.attrib.get("Version", "")
        _validate_identity_store_policy(
            b_name,
            b_pub,
            b_ver,
            f"{label} AppxBundleManifest.xml",
            expected_version=expected_version,
            store_mode=store_mode,
            allow_test_identity=allow_test_identity,
        )

        doc_pkgs_containers = bundle_root.findall(f".//{BUNDLE_NS}Packages")
        direct_pkgs_containers = bundle_root.findall(f"{BUNDLE_NS}Packages")
        if len(doc_pkgs_containers) != 1 or len(direct_pkgs_containers) != 1:
            raise ValueError(
                f"{label}: AppxBundleManifest.xml must declare exactly 1 top-level <Packages> "
                f"(doc={len(doc_pkgs_containers)}, direct={len(direct_pkgs_containers)})"
            )
        pkgs_container = direct_pkgs_containers[0]
        pkg_children = list(pkgs_container)
        unexpected_children = [el.tag for el in pkg_children if el.tag != f"{BUNDLE_NS}Package"]
        if unexpected_children:
            raise ValueError(
                f"{label}: <Packages> contains unexpected child elements: {unexpected_children!r}"
            )

        app_packages_by_arch: dict[str, tuple[str, str]] = {}
        referenced_files: set[str] = set()
        for pkg in pkg_children:
            pkg_type = pkg.attrib.get("Type", "")
            pkg_arch = pkg.attrib.get("Architecture", "")
            pkg_ver = pkg.attrib.get("Version", "")
            pkg_file = pkg.attrib.get("FileName", "")

            if pkg_arch.lower() == "x86":
                raise ValueError(
                    f"{label}: forbidden 32-bit 'x86' architecture slice found in AppxBundleManifest.xml (ADR 0016)"
                )
            if pkg_type != "application":
                raise ValueError(
                    f"{label}: unexpected bundle <Package Type={pkg_type!r}> (expected 'application' slices only)"
                )
            if pkg_arch not in ("x64", "arm64"):
                raise ValueError(
                    f"{label}: unsupported bundle <Package Architecture={pkg_arch!r}> (expected 'x64' or 'arm64')"
                )
            if pkg_arch in app_packages_by_arch:
                raise ValueError(f"{label}: duplicate bundle <Package> slice for Architecture={pkg_arch!r}")
            if pkg_ver != b_ver:
                raise ValueError(
                    f"{label}: <Package Architecture={pkg_arch!r}> Version={pkg_ver!r} != bundle Version={b_ver!r}"
                )
            if not pkg_file or not pkg_file.lower().endswith(".msix") or pkg_file not in names:
                raise ValueError(
                    f"{label}: <Package Architecture={pkg_arch!r}> FileName={pkg_file!r} missing or not an .msix in bundle"
                )
            app_packages_by_arch[pkg_arch] = (pkg_file, pkg_ver)
            referenced_files.add(pkg_file)

        missing_arches = sorted({"x64", "arm64"} - set(app_packages_by_arch))
        if missing_arches:
            raise ValueError(
                f"{label}: .msixbundle missing required architecture slice(s): {missing_arches} "
                f"(present={sorted(app_packages_by_arch)})"
            )

        unreferenced_msix = sorted(
            n for n in raw_names if n.lower().endswith((".msix", ".appx")) and n not in referenced_files
        )
        if unreferenced_msix:
            raise ValueError(
                f"{label}: unreferenced .msix/.appx entries inside .msixbundle: {unreferenced_msix}"
            )

        inner_results: dict[str, dict[str, object]] = {}
        for arch in ("x64", "arm64"):
            pkg_file, _ = app_packages_by_arch[arch]
            inner_bytes = zf.read(pkg_file)
            res = verify_msix_archive(
                inner_bytes,
                f"{label}/{pkg_file}",
                arch=arch,
                expected_version=b_ver,
                expect_signed=False,
                store_mode=store_mode,
                allow_test_identity=allow_test_identity,
                run_live_smoke=run_live_smoke,
            )
            if res["name"] != b_name:
                raise ValueError(
                    f"{label}/{pkg_file}: inner Identity/@Name {res['name']!r} != bundle {b_name!r}"
                )
            if res["publisher"] != b_pub:
                raise ValueError(
                    f"{label}/{pkg_file}: inner Identity/@Publisher {res['publisher']!r} != bundle {b_pub!r}"
                )
            if res["version"] != b_ver:
                raise ValueError(
                    f"{label}/{pkg_file}: inner Identity/@Version {res['version']!r} != bundle {b_ver!r}"
                )
            inner_results[arch] = res

        # Cross-arch canonical XML parity across Properties, Dependencies, 35 Resources, Extensions, Capabilities.
        x64_canon = _canonicalize_manifest_for_parity(inner_results["x64"]["manifest_root"])  # type: ignore[arg-type]
        arm64_canon = _canonicalize_manifest_for_parity(inner_results["arm64"]["manifest_root"])  # type: ignore[arg-type]
        if x64_canon != arm64_canon:
            raise ValueError(
                f"{label}: x64 and arm64 inner AppxManifest.xml files diverge beyond Identity/@ProcessorArchitecture"
            )

    return {
        "name": b_name,
        "publisher": b_pub,
        "version": b_ver,
        "arches": ("x64", "arm64"),
        "size_bytes": len(raw_bytes),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }


def _verify_appxsym_bytes(data: bytes, label: str) -> set[str]:
    if len(data) < 4 or data[:4] != b"PK\x03\x04":
        raise ValueError(f"{label}: not a valid ZIP .appxsym archive (magic={data[:4]!r})")
    pdb_basenames: set[str] = set()
    forbidden_sym_exts = FORBIDDEN_KEY_EXTS + (".exe", ".dll", ".msix", ".appx", ".msixbundle")
    with zipfile.ZipFile(io.BytesIO(data), "r") as sym_zf:
        names = _check_opc_zip_entries(sym_zf, label, flat_root_only=False)
        for name in names:
            if name.endswith("/"):
                continue
            lower = name.lower()
            if lower.endswith(forbidden_sym_exts):
                raise ValueError(f"{label}: forbidden file inside .appxsym archive: {name!r}")
            if not lower.endswith(".pdb"):
                raise ValueError(f"{label}: unexpected non-PDB file inside .appxsym archive: {name!r}")
            if sym_zf.getinfo(name).file_size <= 0:
                raise ValueError(f"{label}: empty PDB entry inside .appxsym archive: {name!r}")
            pdb_basenames.add(Path(name).name.lower())
    if not pdb_basenames:
        raise ValueError(f"{label}: .appxsym archive contains zero .pdb entries")
    return pdb_basenames


def verify_msixupload_archive(
    upload_path: Path,
    *,
    expected_version: str | None,
    expect_signed: bool,
    store_mode: bool,
    allow_test_identity: bool,
    expected_bundle_path: Path | None = None,
    run_live_smoke: bool = True,
) -> dict[str, object]:
    """Deep-verify a Microsoft Store Partner Center .msixupload archive."""
    if not upload_path.is_file():
        raise ValueError(f"MSIX upload package not found: {upload_path}")
    raw_bytes = upload_path.read_bytes()
    label = upload_path.name
    if len(raw_bytes) < 4 or raw_bytes[:4] != b"PK\x03\x04":
        raise ValueError(f"{label}: not a ZIP .msixupload archive (magic={raw_bytes[:4]!r})")

    with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
        names = _check_opc_zip_entries(zf, label, flat_root_only=True)
        bundles: list[str] = []
        appxsyms: list[str] = []

        for name in names:
            lower = name.lower()
            if lower.endswith((".msix", ".appx")):
                raise ValueError(
                    f"{label}: bare standalone package {name!r} is forbidden inside .msixupload "
                    "(Microsoft Store enforces irreversible standalone .msix <-> .msixbundle format lock-in; "
                    "always wrap a dual-arch .msixbundle from Flight #1)"
                )
            if lower.endswith(FORBIDDEN_KEY_EXTS):
                raise ValueError(f"{label}: forbidden signing key/certificate file inside .msixupload: {name!r}")
            if lower.endswith(".msixbundle"):
                bundles.append(name)
            elif lower.endswith(".appxsym"):
                appxsyms.append(name)
            else:
                raise ValueError(
                    f"{label}: unexpected entry {name!r} inside .msixupload (expected only .msixbundle and .appxsym)"
                )

        if len(bundles) != 1:
            raise ValueError(
                f"{label}: .msixupload must contain exactly 1 .msixbundle entry, found {len(bundles)} ({bundles!r})"
            )
        if len(appxsyms) < 1:
            raise ValueError(
                f"{label}: .msixupload must contain at least 1 .appxsym PDB symbol archive"
            )

        bundle_name = bundles[0]
        bundle_bytes = zf.read(bundle_name)
        bundle_sha = hashlib.sha256(bundle_bytes).hexdigest()
        if expected_bundle_path is not None:
            disk_bytes = expected_bundle_path.read_bytes()
            disk_sha = hashlib.sha256(disk_bytes).hexdigest()
            if bundle_name != expected_bundle_path.name:
                raise ValueError(
                    f"{label}: embedded bundle name {bundle_name!r} != --bundle {expected_bundle_path.name!r}"
                )
            if bundle_sha != disk_sha:
                raise ValueError(
                    f"{label}: embedded {bundle_name} SHA-256 ({bundle_sha}) != --bundle ({disk_sha})"
                )

        bundle_info = verify_msixbundle_archive(
            bundle_bytes,
            f"{label}/{bundle_name}",
            expected_version=expected_version,
            expect_signed=expect_signed,
            store_mode=store_mode,
            allow_test_identity=allow_test_identity,
            run_live_smoke=run_live_smoke,
        )

        combined_pdbs: set[str] = set()
        for sym_name in sorted(appxsyms):
            combined_pdbs |= _verify_appxsym_bytes(zf.read(sym_name), f"{label}/{sym_name}")

        missing_pdbs = sorted(REQUIRED_SYMBOL_PDBS - combined_pdbs)
        if missing_pdbs:
            raise ValueError(
                f"{label}: .appxsym archive(s) missing required PDB symbol(s): {missing_pdbs} "
                f"(present={sorted(combined_pdbs)})"
            )

    return {
        "bundle_name": bundle_name,
        "bundle_info": bundle_info,
        "appxsym_count": len(appxsyms),
        "pdb_names": sorted(combined_pdbs),
        "size_bytes": len(raw_bytes),
    }


def _build_synthetic_pe64(
    *,
    machine: int,
    is_dll: bool,
    exports: tuple[str, ...] = (),
    cet_compat: bool = False,
    dependent_load_flags: int | None = None,
    include_icon_101: bool = False,
) -> bytes:
    """Build a minimal valid PE32+ image for pure-Python verifier self-tests (zero external tools)."""
    v_addr = 0x1000
    raw_ptr = 0x200
    sec = bytearray()

    def align4() -> None:
        while len(sec) % 4 != 0:
            sec.append(0)

    def cur_rva() -> int:
        return v_addr + len(sec)

    # 1. Export directory (DataDirectory[0])
    exp_rva, exp_size = 0, 0
    if exports:
        align4()
        exp_off = len(sec)
        exp_rva = v_addr + exp_off
        sec.extend(b"\x00" * 40)
        names_table_off = len(sec)
        names_table_rva = v_addr + names_table_off
        sec.extend(b"\x00" * (4 * len(exports)))
        name_rvas: list[int] = []
        for sym in exports:
            name_rvas.append(cur_rva())
            sec.extend(sym.encode("ascii") + b"\x00")
        struct.pack_into("<I", sec, exp_off + 24, len(exports))
        struct.pack_into("<I", sec, exp_off + 32, names_table_rva)
        for i, nrva in enumerate(name_rvas):
            struct.pack_into("<I", sec, names_table_off + i * 4, nrva)
        exp_size = len(sec) - exp_off

    # 2. Resource directory (DataDirectory[2]) — 2-level RT_ICON(3) & RT_GROUP_ICON(14) ID 101
    rsrc_rva, rsrc_size = 0, 0
    if include_icon_101:
        align4()
        rsrc_off = len(sec)
        rsrc_rva = v_addr + rsrc_off
        # Root dir: 16-byte header + 2*8=16-byte entries = 32 bytes.
        # Lvl2 RT_ICON at rel 32 (24 bytes), Lvl2 RT_GROUP_ICON at rel 56 (24 bytes).
        lvl2_icon_rel = 32
        lvl2_group_rel = 56
        sec.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 2))
        sec.extend(struct.pack("<II", RT_ICON, 0x8000_0000 | lvl2_icon_rel))
        sec.extend(struct.pack("<II", RT_GROUP_ICON, 0x8000_0000 | lvl2_group_rel))
        # Lvl2 RT_ICON
        sec.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
        sec.extend(struct.pack("<II", 1, 0))
        # Lvl2 RT_GROUP_ICON
        sec.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
        sec.extend(struct.pack("<II", EXPLORER_ICON_RESOURCE_ID, 0))
        rsrc_size = len(sec) - rsrc_off

    # 3. Debug directory (DataDirectory[6]) — Type 20 CET_COMPAT
    dbg_rva, dbg_size = 0, 0
    if cet_compat:
        align4()
        dbg_off = len(sec)
        dbg_rva = v_addr + dbg_off
        sec.extend(b"\x00" * 28)
        val_off = len(sec)
        val_rva = v_addr + val_off
        val_raw_ptr = raw_ptr + val_off
        sec.extend(struct.pack("<I", IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT))
        struct.pack_into(
            "<IIHHIIII",
            sec,
            dbg_off,
            0,
            0,
            0,
            0,
            IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS,
            4,
            val_rva,
            val_raw_ptr,
        )
        dbg_size = 28

    # 4. Load Config directory (DataDirectory[10]) — DependentLoadFlags at offset 0x4E
    lc_rva, lc_size = 0, 0
    if dependent_load_flags is not None:
        align4()
        lc_off = len(sec)
        lc_rva = v_addr + lc_off
        lc_buf = bytearray(0x50)
        struct.pack_into("<I", lc_buf, 0, 0x50)
        struct.pack_into("<H", lc_buf, 0x4E, dependent_load_flags)
        sec.extend(lc_buf)
        lc_size = 0x50

    if not sec:
        sec.extend(b"\x00" * 16)
    v_size = len(sec)
    while len(sec) % 0x200 != 0:
        sec.append(0)
    raw_size = len(sec)

    hdr = bytearray(raw_ptr)
    hdr[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    hdr[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"

    coff_off = e_lfanew + 4
    opt_size = 240
    characteristics = IMAGE_FILE_DLL if is_dll else 0x0002
    struct.pack_into("<HHIIIHH", hdr, coff_off, machine, 1, 0, 0, 0, opt_size, characteristics)

    opt_off = coff_off + 20
    struct.pack_into("<H", hdr, opt_off, IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    dll_chars = (
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    )
    struct.pack_into("<H", hdr, opt_off + 70, dll_chars)
    struct.pack_into("<I", hdr, opt_off + 108, 16)

    data_dirs_off = opt_off + 112
    for idx, (rva, size) in (
        (0, (exp_rva, exp_size)),
        (2, (rsrc_rva, rsrc_size)),
        (6, (dbg_rva, dbg_size)),
        (10, (lc_rva, lc_size)),
    ):
        struct.pack_into("<II", hdr, data_dirs_off + idx * 8, rva, size)

    sec_tbl_off = opt_off + opt_size
    struct.pack_into(
        "<8sIIIIIIHHI",
        hdr,
        sec_tbl_off,
        b".rdata\x00\x00",
        v_size,
        v_addr,
        raw_size,
        raw_ptr,
        0,
        0,
        0,
        0,
        0x4000_0040,
    )
    return bytes(hdr) + bytes(sec)


def _patch_manifest_xml(
    template_xml: str,
    *,
    name: str,
    publisher: str,
    version: str,
    arch: str,
    publisher_display_name: str = "TotalDrop",
    drop_run_full_trust: bool = False,
) -> bytes:
    xml = template_xml
    xml = re.sub(r'Name="TotalDrop\.TotalDrop"', f'Name="{name}"', xml, count=1)
    xml = re.sub(r'Publisher="CN=TotalDrop"', f'Publisher="{publisher}"', xml, count=1)
    xml = re.sub(r'Version="[^"]+"', f'Version="{version}"', xml, count=1)
    xml = re.sub(r'ProcessorArchitecture="[^"]+"', f'ProcessorArchitecture="{arch}"', xml, count=1)
    xml = re.sub(
        r"<PublisherDisplayName>[^<]*</PublisherDisplayName>",
        f"<PublisherDisplayName>{publisher_display_name}</PublisherDisplayName>",
        xml,
        count=1,
    )
    if drop_run_full_trust:
        xml = xml.replace('<rescap:Capability Name="runFullTrust" />', "")
    return xml.encode("utf-8")


def _make_synthetic_msix(
    template_xml: str,
    *,
    arch: str,
    name: str,
    publisher: str,
    version: str,
    publisher_display_name: str = "TotalDrop",
    ext_machine_override: int | None = None,
    drop_run_full_trust: bool = False,
) -> bytes:
    machine = IMAGE_FILE_MACHINE_AMD64 if arch == "x64" else IMAGE_FILE_MACHINE_ARM64
    is_x64 = arch == "x64"
    manifest_bytes = _patch_manifest_xml(
        template_xml,
        name=name,
        publisher=publisher,
        version=version,
        arch=arch,
        publisher_display_name=publisher_display_name,
        drop_run_full_trust=drop_run_full_trust,
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AppxManifest.xml", manifest_bytes)
        zf.writestr("AppxBlockMap.xml", b"<BlockMap />")
        zf.writestr("[Content_Types].xml", b"<Types />")
        zf.writestr("resources.pri", b"mrm_pri2\x00\x00\x00\x00")
        zf.writestr("App.xbf", b"XBF\x00")
        zf.writestr("MainWindow.xbf", b"XBF\x00")
        zf.writestr("Views/SendPage.xbf", b"XBF\x00")
        zf.writestr("Views/ReceivePage.xbf", b"XBF\x00")
        zf.writestr("Views/SettingsPage.xbf", b"XBF\x00")
        for asset in sorted(EXPECTED_ASSETS):
            zf.writestr(f"Assets/{asset}", b"\x89PNG\r\n\x1a\n" if asset.endswith(".png") else b"\x00\x00\x01\x00")
        zf.writestr(
            "totaldrop-winui.exe",
            _build_synthetic_pe64(machine=machine, is_dll=False, cet_compat=is_x64, include_icon_101=True),
        )
        zf.writestr(
            "totaldrop_windows_ffi.dll",
            _build_synthetic_pe64(
                machine=machine,
                is_dll=True,
                exports=REQUIRED_FFI_EXPORTS,
                cet_compat=is_x64,
                dependent_load_flags=LOAD_LIBRARY_SEARCH_SYSTEM32,
            ),
        )
        zf.writestr(
            "totaldrop_explorer_ext.dll",
            _build_synthetic_pe64(
                machine=ext_machine_override if ext_machine_override is not None else machine,
                is_dll=True,
                exports=REQUIRED_EXPLORER_EXT_EXPORTS,
                cet_compat=(ext_machine_override == IMAGE_FILE_MACHINE_AMD64) if ext_machine_override else is_x64,
                dependent_load_flags=LOAD_LIBRARY_SEARCH_SYSTEM32,
                include_icon_101=True,
            ),
        )
    return buf.getvalue()


def _make_synthetic_bundle(
    *,
    name: str,
    publisher: str,
    version: str,
    packages: list[tuple[str, str, str, bytes]],
    duplicate_identity: bool = False,
    duplicate_manifest_entry: bool = False,
) -> bytes:
    pkg_xml = "\n".join(
        f'    <Package Type="application" Version="{p_ver}" Architecture="{p_arch}" FileName="{p_file}" />'
        for p_arch, p_ver, p_file, _ in packages
    )
    extra_id = f'\n  <Identity Name="{name}" Publisher="{publisher}" Version="{version}" />' if duplicate_identity else ""
    bundle_manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Bundle SchemaVersion="5.0" xmlns="http://schemas.microsoft.com/appx/2013/bundle">\n'
        f'  <Identity Name="{name}" Publisher="{publisher}" Version="{version}" />{extra_id}\n'
        "  <Packages>\n"
        f"{pkg_xml}\n"
        "  </Packages>\n"
        "</Bundle>\n"
    ).encode("utf-8")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AppxMetadata/AppxBundleManifest.xml", bundle_manifest)
        if duplicate_manifest_entry:
            zf.writestr("appxmetadata/appxbundlemanifest.xml", bundle_manifest)
        zf.writestr("AppxBlockMap.xml", b"<BlockMap />")
        zf.writestr("[Content_Types].xml", b"<Types />")
        for _, _, p_file, p_bytes in packages:
            zf.writestr(p_file, p_bytes)
    return buf.getvalue()


def _make_synthetic_appxsym(pdb_names: tuple[str, ...]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for pdb in pdb_names:
            zf.writestr(pdb, b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")
    return buf.getvalue()


def _make_synthetic_upload(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buf.getvalue()


def run_self_test_bundle() -> int:
    """Run 16 positive and negative pure-Python synthetic self-tests against the real verifier."""
    repo_root = Path(__file__).resolve().parent.parent
    x64_tpl = (repo_root / "target-x86_64" / "Package.x64.appxmanifest").read_text(encoding="utf-8")
    arm64_tpl = (repo_root / "target-arm64" / "Package.arm64.appxmanifest").read_text(encoding="utf-8")

    store_name = "12345TotalDrop.TotalDrop"
    store_pub = "CN=11111111-2222-3333-4444-555555555555"
    store_ver = "1.0.1.0"
    all_pdbs = tuple(sorted(REQUIRED_SYMBOL_PDBS))

    def expect_fail(case_name: str, fn: object, expected_substr: str = "") -> None:
        try:
            fn()  # type: ignore[operator]
        except ValueError as exc:
            if expected_substr and expected_substr.lower() not in str(exc).lower():
                raise AssertionError(
                    f"self-test {case_name}: failed with unexpected error {exc!r} (expected {expected_substr!r})"
                ) from exc
            return
        raise AssertionError(f"self-test {case_name}: expected ValueError, but verification passed")

    with tempfile.TemporaryDirectory(prefix="totaldrop-bundle-selftest-") as tmp:
        tmp_dir = Path(tmp)
        x64_ok = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher=store_pub, version=store_ver)
        arm64_ok = _make_synthetic_msix(arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version=store_ver)
        bundle_ok_bytes = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
        )
        sym_ok = _make_synthetic_appxsym(all_pdbs)
        bundle_ok_path = tmp_dir / f"TotalDrop-{store_ver}.msixbundle"
        bundle_ok_path.write_bytes(bundle_ok_bytes)
        upload_ok_path = tmp_dir / f"TotalDrop-{store_ver}.msixupload"
        upload_ok_path.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", sym_ok),
                    (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                ]
            )
        )

        # Case 1: Positive valid dual-arch Store .msixbundle + .msixupload passes --store-mode.
        verify_msixbundle_archive(
            bundle_ok_path,
            bundle_ok_path.name,
            expected_version=store_ver,
            expect_signed=False,
            store_mode=True,
            allow_test_identity=False,
            run_live_smoke=False,
        )
        verify_msixupload_archive(
            upload_ok_path,
            expected_version=store_ver,
            expect_signed=False,
            store_mode=True,
            allow_test_identity=False,
            expected_bundle_path=bundle_ok_path,
            run_live_smoke=False,
        )

        # Case 2: Dry-run CN=TotalDrop bundle fails strict --store-mode, passes --store-mode --allow-test-identity.
        x64_dry = _make_synthetic_msix(x64_tpl, arch="x64", name="TotalDrop.TotalDrop", publisher="CN=TotalDrop", version=store_ver)
        arm64_dry = _make_synthetic_msix(arm64_tpl, arch="arm64", name="TotalDrop.TotalDrop", publisher="CN=TotalDrop", version=store_ver)
        bundle_dry = _make_synthetic_bundle(
            name="TotalDrop.TotalDrop",
            publisher="CN=TotalDrop",
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_dry),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_dry),
            ],
        )
        expect_fail(
            "case-2-dryrun-strict",
            lambda: verify_msixbundle_archive(
                bundle_dry, "dry.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "placeholder",
        )
        verify_msixbundle_archive(
            bundle_dry, "dry.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=True, run_live_smoke=False
        )

        # Case 3: Missing arm64 slice (x64 only).
        bundle_no_arm64 = _make_synthetic_bundle(
            name=store_name, publisher=store_pub, version=store_ver, packages=[("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok)]
        )
        expect_fail(
            "case-3-missing-arm64",
            lambda: verify_msixbundle_archive(
                bundle_no_arm64, "no-arm64.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "arm64",
        )

        # Case 4: Forbidden x86 slice.
        bundle_x86 = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
                ("x86", store_ver, f"TotalDrop_{store_ver}_x86.msix", x64_ok),
            ],
        )
        expect_fail(
            "case-4-forbidden-x86",
            lambda: verify_msixbundle_archive(
                bundle_x86, "x86.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "x86",
        )

        # Case 5: Bare .msix at root of .msixupload -> cites Store format lock-in rule.
        bad_upload_bare = tmp_dir / "bare.msixupload"
        bad_upload_bare.write_bytes(
            _make_synthetic_upload([(f"TotalDrop_{store_ver}_x64.msix", x64_ok), (f"TotalDrop_{store_ver}_x64.appxsym", sym_ok)])
        )
        expect_fail(
            "case-5-bare-msix-upload",
            lambda: verify_msixupload_archive(
                bad_upload_bare, expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "lock-in",
        )

        # Case 6: Cross-arch PE contamination (x64 0x8664 totaldrop_explorer_ext.dll inside arm64.msix).
        arm64_contaminated = _make_synthetic_msix(
            arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version=store_ver, ext_machine_override=IMAGE_FILE_MACHINE_AMD64
        )
        bundle_contam = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_contaminated),
            ],
        )
        expect_fail(
            "case-6-pe-arch-contamination",
            lambda: verify_msixbundle_archive(
                bundle_contam, "contam.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "expected machine",
        )

        # Case 7: Outer bundle version 1.0.2.0 vs inner arm64 version 1.0.1.0.
        x64_v2 = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher=store_pub, version="1.0.2.0")
        bundle_ver_drift = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version="1.0.2.0",
            packages=[
                ("x64", "1.0.2.0", "TotalDrop_1.0.2.0_x64.msix", x64_v2),
                ("arm64", "1.0.2.0", "TotalDrop_1.0.2.0_arm64.msix", arm64_ok),
            ],
        )
        expect_fail(
            "case-7-version-drift",
            lambda: verify_msixbundle_archive(
                bundle_ver_drift, "ver-drift.msixbundle", expected_version=None, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "Version mismatch",
        )

        # Case 8: Cross-arch Identity/@Publisher mismatch.
        arm64_diff_pub = _make_synthetic_msix(
            arm64_tpl, arch="arm64", name=store_name, publisher="CN=99999999-2222-3333-4444-555555555555", version=store_ver
        )
        bundle_pub_drift = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_diff_pub),
            ],
        )
        expect_fail(
            "case-8-publisher-drift",
            lambda: verify_msixbundle_archive(
                bundle_pub_drift, "pub-drift.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "Publisher",
        )

        # Case 9: Major == 0 (0.1.1.0) under --store-mode.
        x64_zero = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher=store_pub, version="0.1.1.0")
        arm64_zero = _make_synthetic_msix(arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version="0.1.1.0")
        bundle_zero = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version="0.1.1.0",
            packages=[
                ("x64", "0.1.1.0", "TotalDrop_0.1.1.0_x64.msix", x64_zero),
                ("arm64", "0.1.1.0", "TotalDrop_0.1.1.0_arm64.msix", arm64_zero),
            ],
        )
        expect_fail(
            "case-9-major-zero",
            lambda: verify_msixbundle_archive(
                bundle_zero, "major0.msixbundle", expected_version=None, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "Major >= 1",
        )

        # Case 10: Revision != 0 (1.0.0.1) and uint16 overflow (65536.0.0.0).
        for bad_ver, expected_msg in (("1.0.0.1", "Revision == 0"), ("65536.0.0.0", "0..=65535")):
            bx = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher=store_pub, version=bad_ver)
            ba = _make_synthetic_msix(arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version=bad_ver)
            bb = _make_synthetic_bundle(
                name=store_name,
                publisher=store_pub,
                version=bad_ver,
                packages=[
                    ("x64", bad_ver, f"TotalDrop_{bad_ver}_x64.msix", bx),
                    ("arm64", bad_ver, f"TotalDrop_{bad_ver}_arm64.msix", ba),
                ],
            )
            expect_fail(
                f"case-10-{bad_ver}",
                lambda bb=bb: verify_msixbundle_archive(
                    bb, "badver.msixbundle", expected_version=None, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
                ),
                expected_msg,
            )

        # Case 11: Unsigned-package OID in Publisher.
        oid_pub = f"CN=TotalDrop, OID.{UNSIGNED_PACKAGE_OID}=1"
        x64_oid = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher=oid_pub, version=store_ver)
        arm64_oid = _make_synthetic_msix(arm64_tpl, arch="arm64", name=store_name, publisher=oid_pub, version=store_ver)
        bundle_oid = _make_synthetic_bundle(
            name=store_name,
            publisher=oid_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_oid),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_oid),
            ],
        )
        expect_fail(
            "case-11-unsigned-oid",
            lambda: verify_msixbundle_archive(
                bundle_oid, "oid.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=True, run_live_smoke=False
            ),
            UNSIGNED_PACKAGE_OID,
        )

        # Case 12: Malformed Publisher without CN=.
        x64_badpub = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher="TotalDrop", version=store_ver)
        arm64_badpub = _make_synthetic_msix(arm64_tpl, arch="arm64", name=store_name, publisher="TotalDrop", version=store_ver)
        bundle_badpub = _make_synthetic_bundle(
            name=store_name,
            publisher="TotalDrop",
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_badpub),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_badpub),
            ],
        )
        expect_fail(
            "case-12-bad-publisher",
            lambda: verify_msixbundle_archive(
                bundle_badpub, "badpub.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "X.500",
        )

        # Case 13: Leaked .pfx and .snk inside .msixupload.
        for leak_name in ("signing.pfx", "strongname.snk"):
            bad_leak = tmp_dir / f"leak-{leak_name}.msixupload"
            bad_leak.write_bytes(
                _make_synthetic_upload(
                    [
                        (bundle_ok_path.name, bundle_ok_bytes),
                        (f"TotalDrop_{store_ver}_x64.appxsym", sym_ok),
                        (leak_name, b"SECRET"),
                    ]
                )
            )
            expect_fail(
                f"case-13-leak-{leak_name}",
                lambda p=bad_leak: verify_msixupload_archive(
                    p, expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
                ),
                "signing key",
            )

        # Case 14: Duplicate <Identity> and case-insensitive duplicate AppxBundleManifest.xml ZIP entry.
        bundle_dup_id = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
            duplicate_identity=True,
        )
        expect_fail(
            "case-14a-dup-identity",
            lambda: verify_msixbundle_archive(
                bundle_dup_id, "dupid.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "exactly 1 top-level <Identity>",
        )
        bundle_dup_zip = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
            duplicate_manifest_entry=True,
        )
        expect_fail(
            "case-14b-dup-manifest-zip",
            lambda: verify_msixbundle_archive(
                bundle_dup_zip, "dupzip.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "duplicate",
        )

        # Case 15: Missing PDB in .appxsym AND SHA-256 mismatch between --bundle and embedded bundle.
        sym_incomplete = _make_synthetic_appxsym(("totaldrop-winui.pdb", "totaldrop_windows_ffi.pdb"))
        bad_sym_upload = tmp_dir / "missing-pdb.msixupload"
        bad_sym_upload.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", sym_incomplete),
                ]
            )
        )
        expect_fail(
            "case-15a-missing-pdb",
            lambda: verify_msixupload_archive(
                bad_sym_upload, expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "totaldrop_explorer_ext.pdb",
        )
        other_bundle_path = tmp_dir / bundle_ok_path.name
        mismatch_dir = tmp_dir / "other"
        mismatch_dir.mkdir()
        other_bundle_path = mismatch_dir / bundle_ok_path.name
        other_bundle_path.write_bytes(bundle_dry)
        expect_fail(
            "case-15b-sha256-mismatch",
            lambda: verify_msixupload_archive(
                upload_ok_path,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                expected_bundle_path=other_bundle_path,
                run_live_smoke=False,
            ),
            "SHA-256",
        )

        # Case 16: Cross-arch manifest divergence (PublisherDisplayName mismatch & missing runFullTrust in arm64).
        arm64_diff_disp = _make_synthetic_msix(
            arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version=store_ver, publisher_display_name="Other Publisher"
        )
        bundle_disp_drift = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_diff_disp),
            ],
        )
        expect_fail(
            "case-16a-manifest-divergence",
            lambda: verify_msixbundle_archive(
                bundle_disp_drift, "disp-drift.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "diverge",
        )
        arm64_no_rft = _make_synthetic_msix(
            arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version=store_ver, drop_run_full_trust=True
        )
        bundle_no_rft = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_no_rft),
            ],
        )
        expect_fail(
            "case-16b-missing-runfulltrust",
            lambda: verify_msixbundle_archive(
                bundle_no_rft, "no-rft.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "runFullTrust",
        )

    print("self-test-bundle OK: 16/16 positive & negative bundle/msixupload/store-mode checks passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify packed TotalDrop .msix, .msixbundle, and .msixupload archives."
    )
    parser.add_argument("--msix", type=Path, default=None, help="Path to built single-arch .msix archive.")
    parser.add_argument("--bundle", type=Path, default=None, help="Path to unified dual-arch .msixbundle archive.")
    parser.add_argument("--msixupload", type=Path, default=None, help="Path to Partner Center .msixupload archive.")
    parser.add_argument(
        "--self-test-bundle",
        action="store_true",
        help="Run built-in pure-Python positive & negative bundle/msixupload/Store-mode self-tests.",
    )
    parser.add_argument("--arch", choices=("x64", "arm64"), default="x64")
    parser.add_argument("--expected-version", default=None)
    parser.add_argument(
        "--expect-signed",
        action="store_true",
        help="Require non-empty AppxSignature.p7x inside the package/bundle.",
    )
    parser.add_argument(
        "--pri-dump",
        type=Path,
        default=None,
        help="Optional MakePri.exe detailed XML dump to inspect (with --msix).",
    )
    parser.add_argument(
        "--store-mode",
        action="store_true",
        help="Enforce Microsoft Store MSIX rules (Major >= 1, Revision == 0, X.500 CN=, non-placeholder identity).",
    )
    parser.add_argument(
        "--allow-test-identity",
        action="store_true",
        help="Permit temporary CN=TotalDrop / TotalDrop.TotalDrop identity during --store-mode dry-runs.",
    )
    args = parser.parse_args(argv)

    if not any((args.msix, args.bundle, args.msixupload, args.self_test_bundle)):
        parser.error("Provide at least one of --msix, --bundle, --msixupload, or --self-test-bundle.")

    try:
        if args.self_test_bundle:
            run_self_test_bundle()

        if args.msix is not None:
            eff_ver = args.expected_version
            if eff_ver is None and not args.store_mode:
                eff_ver = EXPECTED_MSIX_VERSION
            res = verify_msix_archive(
                args.msix,
                args.msix.name,
                arch=args.arch,
                expected_version=eff_ver,
                expect_signed=args.expect_signed,
                store_mode=args.store_mode,
                allow_test_identity=args.allow_test_identity,
                pri_dump=args.pri_dump,
            )
            cet_note = " + CET_COMPAT" if args.arch == "x64" else ""
            print(
                f"msix-artifact verify OK: {args.msix.name} ({res['size_bytes']} bytes, "
                f"arch={args.arch}, version={res['version']}, 46 canonical Assets, "
                f"PE hardening{cet_note} + DependentLoadFlags=0x800 + zero VCRUNTIME140 + "
                f"{len(REQUIRED_FFI_EXPORTS)} C ABI exports + Explorer COM DLL (icon 101) + "
                f"COM/Toast/Firewall manifest + Native AOT verified)."
            )

        if args.bundle is not None:
            b_res = verify_msixbundle_archive(
                args.bundle,
                args.bundle.name,
                expected_version=args.expected_version,
                expect_signed=args.expect_signed,
                store_mode=args.store_mode,
                allow_test_identity=args.allow_test_identity,
            )
            print(
                f"msixbundle verify OK: {args.bundle.name} ({b_res['size_bytes']} bytes, "
                f"version={b_res['version']}, identity={b_res['name']}, arches=x64+arm64, "
                f"cross-arch manifest parity & PE32+ hardening verified)."
            )

        if args.msixupload is not None:
            u_res = verify_msixupload_archive(
                args.msixupload,
                expected_version=args.expected_version,
                expect_signed=args.expect_signed,
                store_mode=args.store_mode,
                allow_test_identity=args.allow_test_identity,
                expected_bundle_path=args.bundle,
            )
            b_info = u_res["bundle_info"]
            print(
                f"msixupload verify OK: {args.msixupload.name} ({u_res['size_bytes']} bytes, "
                f"bundle={u_res['bundle_name']}, version={b_info['version']}, "  # type: ignore[index]
                f"appxsym={u_res['appxsym_count']}, pdbs={len(u_res['pdb_names'])}, "  # type: ignore[arg-type]
                "zero bare .msix & zero signing keys verified)."
            )
    except (ValueError, ET.ParseError, zipfile.BadZipFile, subprocess.CalledProcessError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
