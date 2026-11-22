#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Master Phase B (M1-M2) opaque-box E2E test driver for TotalDrop for Windows x64.

Executes all 130 Linux/cross-platform M1+M2 tests (126 cross-platform +
4 linux-devbox), tracks all 44 Windows-only tests (30 windows-ci +
14 windows-interactive-wack) as WINDOWS_ONLY_READY, runs the static
anti-production-probing scanner, and emits a 174-test traceability matrix.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKSPACE_PARENT = REPO_ROOT.parent

REUSE_IMAGE = (
    "fsfe/reuse:6.2.0@sha256:"
    "85462a75c0f8efda09ddd190b92816b70e7662577c8427429e11e1b9f25a992e"
)

# Exact 30 windows-ci test IDs (22 M1 + 8 M2) executed by tools/e2e/Invoke-WindowsE2E.ps1
WINDOWS_CI_M1_IDS: tuple[str, ...] = (
    "T1-F02-03", "T1-F02-04", "T1-F02-05", "T2-F02-01", "T2-F02-04",
    "T1-F04-03", "T1-F04-04", "T1-F04-05", "T2-F04-04", "T2-F04-05",
    "T1-F05-02", "T1-F05-03", "T1-F05-04", "T1-F05-05",
    "T2-F05-02", "T2-F05-03", "T2-F05-04", "T2-F05-05",
    "T1-F06-04", "T3-14", "T3-15", "T4-06",
)

WINDOWS_CI_M2_IDS: tuple[str, ...] = (
    "T1-F10-05", "T1-F11-05", "T1-F12-05",
    "T1-F12-01", "T1-F12-02", "T2-F12-01", "T2-F12-02", "T3-04",
)

# Prefix-to-Test-ID map for Rust test functions in e2e_c_abi_m1.rs & e2e_loopback_m2.rs
RUST_TEST_PREFIX_RE = re.compile(
    r"^test\s+(t[1-4]_(?:f\d{2}_\d{2}|\d{2})(?:_part_a)?)[A-Za-z0-9_]*\s+\.\.\.\s+(ok|FAILED)$"
)


def _fn_prefix_to_test_id(prefix: str) -> str:
    raw = prefix.upper().replace("_", "-")
    if raw.endswith("-PART-A"):
        return raw
    return raw


def _run_cmd(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(cmd, cwd=str(cwd), env=merged_env, capture_output=True, text=True, check=False)


def _prepare_arch_a_servers(tmp_root: Path) -> tuple[Path | None, Path | None, str]:
    rdv_env = os.environ.get("TOTALDROP_TEST_RENDEZVOUS_BIN", "").strip()
    rly_env = os.environ.get("TOTALDROP_TEST_RELAY_BIN", "").strip()
    if rdv_env and rly_env:
        rdv = Path(rdv_env)
        rly = Path(rly_env)
        if not rdv.is_file() or not rly.is_file():
            raise RuntimeError(f"Configured Arch A binaries missing: rdv={rdv}, rly={rly}")
        return rdv, rly, "Arch A (env-configured totaldrop-servers)"

    servers_repo = WORKSPACE_PARENT / "totaldrop-servers"
    manifest = servers_repo / "Cargo.toml"
    if not manifest.is_file():
        return None, None, "Arch B fallback (sibling totaldrop-servers not present)"

    srv_target = tmp_root / "totaldrop-servers-target"
    proc = _run_cmd(
        ["cargo", "build", "--manifest-path", str(manifest), "--locked", "--bins"],
        cwd=REPO_ROOT,
        env={"CARGO_TARGET_DIR": str(srv_target)},
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to build Arch A totaldrop-servers binaries:\n{proc.stderr}")

    ext = ".exe" if os.name == "nt" else ""
    rdv = srv_target / "debug" / f"totaldrop-rendezvous{ext}"
    rly = srv_target / "debug" / f"totaldrop-relay{ext}"
    if not rdv.is_file() or not rly.is_file():
        raise RuntimeError(f"Expected Arch A binaries not produced at {rdv} / {rly}")
    return rdv, rly, f"Arch A (out-of-tree built in {srv_target})"


def _run_rust_suite(
    test_target: str,
    env: dict[str, str] | None = None,
) -> tuple[dict[str, dict[str, Any]], int, str]:
    proc = _run_cmd(
        ["cargo", "test", "--workspace", "--locked", "--test", test_target],
        cwd=REPO_ROOT,
        env=env,
    )
    parsed: dict[str, dict[str, Any]] = {}
    for line in proc.stdout.splitlines():
        m = RUST_TEST_PREFIX_RE.match(line.strip())
        if m:
            tid = _fn_prefix_to_test_id(m.group(1))
            status = "PASS" if m.group(2) == "ok" else "FAIL"
            parsed[tid] = {
                "status": status,
                "runner": f"cargo test --test {test_target}",
                "detail": line.strip(),
            }
    return parsed, proc.returncode, proc.stdout + "\n" + proc.stderr


def _run_t1_f04_02(tmp_root: Path) -> dict[str, Any]:
    codegen = WORKSPACE_PARENT / "totaldrop-core" / "tools" / "l10n_codegen.py"
    if not codegen.is_file():
        return {"status": "FAIL", "detail": f"missing sibling l10n_codegen.py at {codegen}"}
    out_dir = tmp_root / "winui-resw-check"
    p1 = _run_cmd(
        [
            sys.executable,
            str(codegen),
            "--l10n-dir",
            "l10n",
            "--check",
            "--emit",
            "winui-resw",
            "--out",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )
    if p1.returncode != 0:
        return {"status": "FAIL", "detail": f"l10n_codegen.py failed: {p1.stdout}\n{p1.stderr}"}
    p2 = _run_cmd(["diff", "-ru", str(out_dir), "ui-winui3-fluent2/Strings"], cwd=REPO_ROOT)
    if p2.returncode != 0:
        return {"status": "FAIL", "detail": f"diff -ru found .resw drift:\n{p2.stdout[:1000]}"}
    return {"status": "PASS", "detail": p1.stdout.strip() + "; diff -ru 0 byte diffs"}


def _run_fuzz_checks(tmp_root: Path, t3_22_ffi_ok: bool) -> dict[str, dict[str, Any]]:
    fuzz_repo = WORKSPACE_PARENT / "totaldrop-formal-fuzz"
    results: dict[str, dict[str, Any]] = {}
    if not fuzz_repo.is_dir():
        err = f"sibling totaldrop-formal-fuzz repo missing at {fuzz_repo}"
        return {
            "T1-F15-01": {"status": "FAIL", "detail": err},
            "T1-F15-02": {"status": "FAIL", "detail": err},
            "T3-22": {"status": "FAIL", "detail": err},
        }

    fuzz_target_dir = tmp_root / "formal-fuzz-target"
    fuzz_env = {"CARGO_TARGET_DIR": str(fuzz_target_dir)}

    # T1-F15-01: 5 Windows fuzz targets + SPDX + cargo check --bins --locked
    expected_targets = (
        "windows_ipc",
        "windows_path",
        "windows_cmdline",
        "windows_uri",
        "windows_ndjson",
    )
    try:
        fuzz_toml = tomllib.loads((fuzz_repo / "fuzz" / "Cargo.toml").read_text(encoding="utf-8"))
        bins_by_name = {b.get("name"): b for b in fuzz_toml.get("bin", [])}
        spdx_c = "SPDX-File" + "CopyrightText:"
        spdx_l = "SPDX-License-" + "Identifier:"
        for name in expected_targets:
            b = bins_by_name.get(name)
            if not b:
                raise AssertionError(f"missing [[bin]] target {name} in fuzz/Cargo.toml")
            if b.get("test") is not False or b.get("doc") is not False or b.get("bench") is not False:
                raise AssertionError(f"target {name} must set test=false, doc=false, bench=false")
            rs = fuzz_repo / "fuzz" / "fuzz_targets" / f"{name}.rs"
            if not rs.is_file():
                raise AssertionError(f"missing {rs}")
            top6 = "\n".join(rs.read_text(encoding="utf-8").splitlines()[:6])
            if spdx_c not in top6 or f"{spdx_l} MIT OR Apache-2.0" not in top6:
                raise AssertionError(f"{rs.name}: missing top-6-line MIT OR Apache-2.0 SPDX header")

        ipc_rs = (fuzz_repo / "fuzz" / "fuzz_targets" / "windows_ipc.rs").read_text(encoding="utf-8")
        if "payload_capacity()" not in ipc_rs:
            raise AssertionError("windows_ipc.rs missing payload_capacity() zero-preallocation guard")

        p_chk = _run_cmd(
            ["cargo", "check", "--manifest-path", "fuzz/Cargo.toml", "--bins", "--locked"],
            cwd=fuzz_repo,
            env=fuzz_env,
        )
        if p_chk.returncode != 0:
            raise AssertionError(f"cargo check fuzz bins failed:\n{p_chk.stderr}")
        results["T1-F15-01"] = {
            "status": "PASS",
            "detail": "5 Windows fuzz targets verified (SPDX, Cargo.toml flags, cargo check --bins --locked exit 0)",
        }
    except Exception as exc:  # noqa: BLE001
        results["T1-F15-01"] = {"status": "FAIL", "detail": str(exc)}

    # T1-F15-02: fmt, fuzz fmt, clippy, test, check-spdx, reuse lint, unsafe_code=forbid
    try:
        bridge_toml = tomllib.loads((fuzz_repo / "crates" / "totaldrop-windows-bridge" / "Cargo.toml").read_text(encoding="utf-8"))
        root_toml = tomllib.loads((fuzz_repo / "Cargo.toml").read_text(encoding="utf-8"))
        if root_toml.get("workspace", {}).get("lints", {}).get("rust", {}).get("unsafe_code") != "forbid":
            raise AssertionError("totaldrop-formal-fuzz root Cargo.toml missing unsafe_code = 'forbid'")
        if bridge_toml.get("lints", {}).get("workspace") is not True:
            raise AssertionError("totaldrop-formal-fuzz totaldrop-windows-bridge missing workspace lints")
        for dep in bridge_toml.get("dependencies", {}):
            if "win" in dep.lower() and dep != "totaldrop-windows-bridge":
                raise AssertionError(f"unexpected Windows dependency {dep} in totaldrop-windows-bridge")

        gates: list[tuple[str, list[str]]] = [
            ("cargo fmt", ["cargo", "fmt", "--all", "--", "--check"]),
            ("cargo fmt fuzz", ["cargo", "fmt", "--manifest-path", "fuzz/Cargo.toml", "--all", "--", "--check"]),
            ("cargo clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"]),
            ("cargo test", ["cargo", "test", "--workspace", "--locked"]),
            ("check-spdx", ["./tools/check-spdx.sh"]),
        ]
        if shutil.which("reuse"):
            gates.append(("reuse lint", ["reuse", "lint"]))
        else:
            gates.append((
                "reuse lint (docker)",
                ["docker", "run", "--rm", "--volume", f"{fuzz_repo}:/data:ro", REUSE_IMAGE, "lint"],
            ))

        for label, cmd in gates:
            p = _run_cmd(cmd, cwd=fuzz_repo, env=fuzz_env)
            if p.returncode != 0:
                raise AssertionError(f"{label} failed (rc={p.returncode}):\n{p.stdout}\n{p.stderr}")
        results["T1-F15-02"] = {
            "status": "PASS",
            "detail": "all 6 totaldrop-formal-fuzz gates + unsafe_code=forbid + 0 Win32 deps PASS",
        }
    except Exception as exc:  # noqa: BLE001
        results["T1-F15-02"] = {"status": "FAIL", "detail": str(exc)}

    # T3-22: combines fuzz check + FFI adversarial corpus
    if results["T1-F15-01"]["status"] == "PASS" and t3_22_ffi_ok:
        results["T3-22"] = {
            "status": "PASS",
            "detail": "5 fuzz targets compile + windows_ipc payload_capacity()==0 + M1/M2 FFI adversarial corpus PASS",
        }
    else:
        results["T3-22"] = {
            "status": "FAIL",
            "detail": f"T1-F15-01={results['T1-F15-01']['status']}, t3_22_ffi_ok={t3_22_ffi_ok}",
        }
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run all 130 Linux/cross-platform M1+M2 opaque-box E2E tests.")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional path for full 174-test matrix JSON.")
    parser.add_argument("--skip-arch-a-build", action="store_true", help="Do not auto-build sibling totaldrop-servers.")
    args = parser.parse_args(argv)

    matrix: dict[str, dict[str, Any]] = {}

    with tempfile.TemporaryDirectory(prefix="totaldrop-m1-m2-e2e-") as tmp:
        tmp_root = Path(tmp)

        # 0. Anti-production-probing scanner (TEST_INFRA.md section 3.3)
        p_probe = _run_cmd(
            [sys.executable, "tools/e2e/verify_static_contracts.py", "--scan-no-prod-probing"],
            cwd=REPO_ROOT,
        )
        if p_probe.returncode != 0:
            print(f"[FAIL] anti-production-probing scanner:\n{p_probe.stderr}", file=sys.stderr)
            return 1
        print(f"[GATE] {p_probe.stdout.strip()}")

        # 1. PE32+ oracle synthetic unit self-test (validates Windows-CI binary parser on Linux)
        p_pe = _run_cmd(
            [sys.executable, "tools/e2e/verify_pe_hardening.py", "--unit-test-synthetic"],
            cwd=REPO_ROOT,
        )
        if p_pe.returncode != 0:
            print(f"[FAIL] verify_pe_hardening synthetic self-test:\n{p_pe.stderr}", file=sys.stderr)
            return 1
        print(f"[GATE] {p_pe.stdout.strip()}")

        # 2. Architecture A loopback server setup
        rust_m2_env: dict[str, str] = {}
        if not args.skip_arch_a_build:
            rdv_bin, rly_bin, mode_desc = _prepare_arch_a_servers(tmp_root)
            if rdv_bin and rly_bin:
                rust_m2_env["TOTALDROP_TEST_RENDEZVOUS_BIN"] = str(rdv_bin)
                rust_m2_env["TOTALDROP_TEST_RELAY_BIN"] = str(rly_bin)
            print(f"[INFO] Loopback server mode: {mode_desc}")

        # 3. Rust M1 (8 tests)
        m1_rust, m1_rc, m1_log = _run_rust_suite("e2e_c_abi_m1")
        if m1_rc != 0:
            print(m1_log, file=sys.stderr)
        for tid, info in m1_rust.items():
            matrix[tid] = {"milestone": "M1", "env": "cross-platform", **info}

        # 4. Rust M2 (70 Rust tests -> 69 M2 cross-platform IDs + T3-22 FFI half)
        m2_rust, m2_rc, m2_log = _run_rust_suite("e2e_loopback_m2", env=rust_m2_env)
        if m2_rc != 0:
            print(m2_log, file=sys.stderr)
        t2_f13_01_a = m2_rust.pop("T2-F13-01-PART-A", {"status": "FAIL", "detail": "missing T2-F13-01 part a"})
        t3_22_ffi = m2_rust.pop("T3-22", {"status": "FAIL", "detail": "missing t3_22_ffi_adversarial_corpus"})
        for tid, info in m2_rust.items():
            matrix[tid] = {"milestone": "M2", "env": "cross-platform", **info}

        # 5. Assets Kose oracle (10 M1 cross-platform tests)
        assets_json = tmp_root / "assets.json"
        _run_cmd(
            [sys.executable, "tools/e2e/verify_assets_kose.py", "--run-tests", "--json-out", str(assets_json)],
            cwd=REPO_ROOT,
        )
        for tid, info in json.loads(assets_json.read_text(encoding="utf-8")).items():
            matrix[tid] = {"milestone": "M1", "env": "cross-platform", "runner": "verify_assets_kose.py", **info}

        # 6. MSIX/OPC subplatform cross-platform tests (5 M1 tests)
        opc_json = tmp_root / "opc.json"
        _run_cmd(
            [sys.executable, "tools/e2e/verify_msix_opc.py", "--run-tests", "--json-out", str(opc_json)],
            cwd=REPO_ROOT,
        )
        for tid, info in json.loads(opc_json.read_text(encoding="utf-8")).items():
            matrix[tid] = {"milestone": "M1", "env": "cross-platform", "runner": "verify_msix_opc.py", **info}

        # 7. Static & mutation contracts (28 M1 + 6 M2 + T2-F13-01 part b)
        static_json = tmp_root / "static.json"
        _run_cmd(
            [
                sys.executable,
                "tools/e2e/verify_static_contracts.py",
                "--milestone",
                "M2",
                "--run-tests",
                "--json-out",
                str(static_json),
            ],
            cwd=REPO_ROOT,
        )
        static_data = json.loads(static_json.read_text(encoding="utf-8"))
        t2_f13_01_b = static_data.pop("T2-F13-01-part-b", {"status": "FAIL", "detail": "missing part b"})
        if t2_f13_01_a["status"] == "PASS" and t2_f13_01_b["status"] == "PASS":
            matrix["T2-F13-01"] = {
                "milestone": "M2",
                "env": "cross-platform",
                "status": "PASS",
                "runner": "e2e_loopback_m2 + verify_static_contracts.py",
                "detail": f"part(a) PASS + part(b) {t2_f13_01_b['detail']}",
            }
        else:
            matrix["T2-F13-01"] = {
                "milestone": "M2",
                "env": "cross-platform",
                "status": "FAIL",
                "runner": "e2e_loopback_m2 + verify_static_contracts.py",
                "detail": f"part(a)={t2_f13_01_a}, part(b)={t2_f13_01_b}",
            }

        m2_static_ids = {"T2-F12-05", "T2-F13-06", "T1-F14-01", "T1-F14-02", "T1-F14-03", "T2-F14-01"}
        for tid, info in static_data.items():
            ms = "M2" if tid in m2_static_ids else "M1"
            matrix[tid] = {"milestone": ms, "env": "cross-platform", "runner": "verify_static_contracts.py", **info}

        # 8. Linux-devbox sibling-repo checks (4 tests: T1-F04-02, T1-F15-01, T1-F15-02, T3-22)
        matrix["T1-F04-02"] = {
            "milestone": "M1",
            "env": "linux-devbox",
            "runner": "l10n_codegen.py + diff -ru",
            **_run_t1_f04_02(tmp_root),
        }
        fuzz_res = _run_fuzz_checks(tmp_root, t3_22_ffi["status"] == "PASS")
        for tid, info in fuzz_res.items():
            matrix[tid] = {"milestone": "M2", "env": "linux-devbox", "runner": "totaldrop-formal-fuzz", **info}

    # 9. Track all 44 Windows-only tests honestly as WINDOWS_ONLY_READY
    for tid in WINDOWS_CI_M1_IDS:
        matrix[tid] = {
            "milestone": "M1",
            "env": "windows-ci",
            "status": "WINDOWS_ONLY_READY",
            "runner": "tools/e2e/Invoke-WindowsE2E.ps1 -Milestone M1",
            "detail": "Ready for headless Windows CI runner (windows-latest)",
        }
    for tid in WINDOWS_CI_M2_IDS:
        matrix[tid] = {
            "milestone": "M2",
            "env": "windows-ci",
            "status": "WINDOWS_ONLY_READY",
            "runner": "tools/e2e/Invoke-WindowsE2E.ps1 -Milestone M2",
            "detail": "Ready for headless Windows CI runner (windows-latest)",
        }

    wack_path = REPO_ROOT / "tools" / "e2e" / "windows_interactive_wack_checklist.json"
    wack_data = json.loads(wack_path.read_text(encoding="utf-8"))
    for entry in wack_data["tests"]:
        tid = entry["test_id"]
        matrix[tid] = {
            "milestone": entry["milestone"],
            "env": "windows-interactive-wack",
            "status": "WINDOWS_ONLY_READY",
            "runner": "tools/e2e/windows_interactive_wack_checklist.json",
            "detail": "Tracked interactive Windows 11 desktop / WACK checklist item",
        }

    # Tally & verify exact counts
    passed = sorted(k for k, v in matrix.items() if v["status"] == "PASS")
    failed = sorted(k for k, v in matrix.items() if v["status"] == "FAIL")
    win_ready = sorted(k for k, v in matrix.items() if v["status"] == "WINDOWS_ONLY_READY")

    m1_pass = [k for k in passed if matrix[k]["milestone"] == "M1"]
    m2_pass = [k for k in passed if matrix[k]["milestone"] == "M2"]
    m1_win = [k for k in win_ready if matrix[k]["milestone"] == "M1"]
    m2_win = [k for k in win_ready if matrix[k]["milestone"] == "M2"]

    summary = {
        "total_mapped": len(matrix),
        "runnable_total": len(passed) + len(failed),
        "passed": len(passed),
        "failed": len(failed),
        "windows_only_ready": len(win_ready),
        "breakdown": {
            "M1_runnable_pass": len(m1_pass),
            "M1_windows_only_ready": len(m1_win),
            "M2_runnable_pass": len(m2_pass),
            "M2_windows_only_ready": len(m2_win),
        },
        "failed_ids": failed,
        "tests": dict(sorted(matrix.items())),
    }

    if args.json_out is not None:
        args.json_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("\n=== Phase B (M1-M2) Opaque-Box E2E Summary ===")
    print(f"Total Mapped Tests : {len(matrix)} (expected 174)")
    print(f"Runnable Passed    : {len(passed)}/{len(passed) + len(failed)} (M1={len(m1_pass)}, M2={len(m2_pass)})")
    print(f"Runnable Failed    : {len(failed)}")
    print(f"WINDOWS_ONLY_READY : {len(win_ready)} (M1={len(m1_win)}, M2={len(m2_win)})")
    if failed:
        print("\nFAILED TEST IDS:")
        for tid in failed:
            print(f"  - {tid}: {matrix[tid].get('detail')}")
        return 1
    if len(matrix) != 174 or len(passed) != 130 or len(win_ready) != 44:
        print(
            f"error: unexpected matrix count total={len(matrix)} pass={len(passed)} win_ready={len(win_ready)} "
            "(expected 174 / 130 / 44)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
