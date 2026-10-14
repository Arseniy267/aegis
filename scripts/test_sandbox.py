# scripts/test_sandbox.py — smoke tests for safety/sandbox.py
"""
Runs a battery of tests to verify sandbox isolation.

Tests:
    1. hello world + env       — базовая работа
    2. read-only FS            — нельзя писать в /
    3. tmpfs writable          — можно писать в /tmp
    4. DNS blocked             — нет резолва доменов
    5. no root                 — нельзя sudo/su
    6. resource limits         — timeout срабатывает
    7. reach target (optional) — если target доступен

Usage:
    python scripts/test_sandbox.py --target 192.168.64.7
    python scripts/test_sandbox.py --target dvwa
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from safety.sandbox import run_in_sandbox, SandboxResult


# ============================================================================
# Test harness
# ============================================================================
@dataclass
class TestCase:
    name: str
    script: str
    timeout: int = 30
    port: int | None = None
    check_ok: callable = None       # fn(SandboxResult) -> bool
    expect_contains: list[str] = None
    expect_not_contains: list[str] = None
    optional: bool = False


def _check(*contains: str, forbid: list[str] = None):
    forbid = forbid or []
    def _f(r: SandboxResult) -> bool:
        blob = (r.stdout + "\n" + r.stderr)
        for c in contains:
            if c not in blob:
                return False
        for f in forbid:
            if f in blob:
                return False
        return True
    return _f


TESTS: list[TestCase] = [
    TestCase(
        name="01. hello world + env vars",
        script="""
import os
print("TARGET=" + os.environ.get("TARGET", "MISSING"))
print("PORT=" + os.environ.get("TARGET_PORT", "NONE"))
print("hello from sandbox")
""",
        check_ok=_check("hello from sandbox", "TARGET=", "PORT="),
    ),

    TestCase(
        name="02. root filesystem is read-only",
        script="""
try:
    with open("/evil.txt", "w") as f:
        f.write("x")
    print("WRITE_SUCCEEDED_NOT_ISOLATED")
except Exception as e:
    print("WRITE_BLOCKED: " + type(e).__name__)
""",
        check_ok=_check("WRITE_BLOCKED", forbid=["WRITE_SUCCEEDED_NOT_ISOLATED"]),
    ),

    TestCase(
        name="03. /tmp is writable (tmpfs)",
        script="""
try:
    with open("/tmp/ok.txt", "w") as f:
        f.write("works")
    with open("/tmp/ok.txt") as f:
        print("TMP_READ_BACK=" + f.read())
except Exception as e:
    print("TMP_FAILED: " + type(e).__name__)
""",
        check_ok=_check("TMP_READ_BACK=works"),
    ),

    TestCase(
        name="04. DNS resolution blocked",
        script="""
import socket
try:
    ip = socket.gethostbyname("google.com")
    print("DNS_WORKS_NOT_ISOLATED ip=" + ip)
except Exception as e:
    print("DNS_BLOCKED: " + type(e).__name__)
""",
        check_ok=_check("DNS_BLOCKED", forbid=["DNS_WORKS_NOT_ISOLATED"]),
    ),

    TestCase(
        name="05. running as non-root uid 1000",
        script="""
import os
print("UID=" + str(os.getuid()))
print("USER=" + os.environ.get("USER", "?"))
""",
        check_ok=_check("UID=1000"),
    ),

    TestCase(
        name="06. timeout enforced",
        script="""
import time
print("sleeping...", flush=True)
time.sleep(120)
print("NEVER_REACHED")
""",
        timeout=5,
        check_ok=lambda r: r.timed_out and r.duration_s < 15,
    ),
]


# ============================================================================
# Runner
# ============================================================================
def _fmt_status(ok: bool, optional: bool = False) -> str:
    if ok:
        return "[ PASS ]"
    if optional:
        return "[ SKIP ]"
    return "[ FAIL ]"


def _short(s: str, n: int = 200) -> str:
    s = s.strip().replace("\n", " | ")
    return s if len(s) <= n else s[:n] + "..."


def run_test(tc: TestCase, target: str, verbose: bool) -> tuple[bool, SandboxResult]:
    print(f"\n{'-'*72}")
    print(f"  {tc.name}")
    print(f"{'-'*72}")

    result = run_in_sandbox(
        script=tc.script,
        target_ip=target,
        target_port=tc.port,
        timeout=tc.timeout,
    )

    if verbose:
        print(f"  exit_code:   {result.exit_code}")
        print(f"  timed_out:   {result.timed_out}")
        print(f"  duration_s:  {result.duration_s}")
        if result.error:
            print(f"  error:       {result.error}")
        if result.stdout:
            print(f"  stdout:      {_short(result.stdout, 400)}")
        if result.stderr:
            print(f"  stderr:      {_short(result.stderr, 400)}")
    else:
        print(f"  duration: {result.duration_s}s  exit: {result.exit_code}  "
              f"timeout: {result.timed_out}")

    ok = False
    if tc.check_ok is not None:
        try:
            ok = bool(tc.check_ok(result))
        except Exception as e:
            print(f"  check raised: {e}")
            ok = False

    print(f"  → {_fmt_status(ok, tc.optional)}")
    return ok, result


def main() -> int:
    p = argparse.ArgumentParser(description="Sandbox smoke tests")
    p.add_argument("--target", default="127.0.0.1",
                   help="target IP or hostname (used as env TARGET)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--json", action="store_true",
                   help="dump results as JSON at the end")
    args = p.parse_args()

    print()
    print("=" * 72)
    print(f"  AEGIS sandbox smoke tests")
    print(f"  target: {args.target}")
    print(f"  python: {sys.version.split()[0]}  platform: {sys.platform}")
    print("=" * 72)

    t0 = time.time()
    results: list[dict] = []
    n_pass = n_fail = n_skip = 0

    for tc in TESTS:
        ok, r = run_test(tc, args.target, args.verbose)
        if ok:
            n_pass += 1
        elif tc.optional:
            n_skip += 1
        else:
            n_fail += 1
        results.append({
            "name": tc.name,
            "ok": ok,
            "optional": tc.optional,
            **r.to_dict(),
        })

    elapsed = round(time.time() - t0, 2)

    print()
    print("=" * 72)
    print(f"  SUMMARY  |  pass: {n_pass}  fail: {n_fail}  skip: {n_skip}  "
          f"|  total: {elapsed}s")
    print("=" * 72)

    if args.json:
        out = _ROOT / "logs" / "sandbox_test_results.json"
        out.parent.mkdir(exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"  JSON: {out}")

    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
