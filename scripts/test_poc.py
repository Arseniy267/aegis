# scripts/test_poc.py — run a single PoC inside safety/sandbox.py
"""
Запускает один PoC-скрипт в Docker sandbox и печатает результат.

Usage:
    python scripts/test_poc.py modules/exploits/_smoke.py --target 127.0.0.1 --port 80 -v
    python scripts/test_poc.py modules/exploits/vsftpd_234.py --target 192.168.64.7 --port 21
    python scripts/test_poc.py modules/exploits/apache_2449_rce.py --target dvwa --port 80 --json

Опции:
    --env KEY=VALUE   дополнительная переменная окружения (можно повторять)
    -v / --verbose    показать stdout/stderr полностью
    --json            сохранить результат в logs/poc_<name>_result.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# --- project root on sys.path ---
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from safety.sandbox import run_in_sandbox


def parse_extra_env(pairs: list[str]) -> dict[str, str]:
    """--env KEY=VALUE → dict. Падает на кривом формате."""
    out: dict[str, str] = {}
    for kv in pairs:
        if "=" not in kv:
            raise SystemExit(f"[-] Bad --env (expected KEY=VALUE): {kv!r}")
        k, v = kv.split("=", 1)
        out[k.strip()] = v
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="Run a PoC in Docker sandbox")
    p.add_argument("poc", help="path to .py PoC file")
    p.add_argument("--target", required=True, help="target IP or hostname")
    p.add_argument("--port", type=int, help="target port")
    p.add_argument("--timeout", type=int, default=60,
                   help="sandbox timeout in seconds (default 60)")
    p.add_argument("--env", action="append", default=[],
                   help="extra env: KEY=VALUE (repeatable)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show full stdout/stderr")
    p.add_argument("--json", action="store_true",
                   help="dump result to logs/poc_<name>_result.json")
    args = p.parse_args()

    # --- validate PoC path ---
    poc_path = Path(args.poc)
    if not poc_path.is_absolute():
        poc_path = _ROOT / poc_path
    if not poc_path.exists():
        print(f"[-] PoC not found: {poc_path}", file=sys.stderr)
        return 2
    if poc_path.suffix != ".py":
        print(f"[-] PoC must be a .py file: {poc_path}", file=sys.stderr)
        return 2

    script = poc_path.read_text(encoding="utf-8")
    if not script.strip():
        print(f"[-] PoC file is empty: {poc_path}", file=sys.stderr)
        return 2

    # --- extra env ---
    try:
        extra_env = parse_extra_env(args.env)
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 2

    # --- banner ---
    print(f"[*] Running {poc_path.name} in sandbox")
    print(f"[*] Target:    {args.target}" + (f":{args.port}" if args.port else ""))
    print(f"[*] Timeout:   {args.timeout}s")
    if extra_env:
        print(f"[*] Extra env: {extra_env}")
    print()

    # --- execute ---
    result = run_in_sandbox(
        script=script,
        target_ip=args.target,
        target_port=args.port,
        timeout=args.timeout,
        extra_env=extra_env or None,
    )

    # --- summary ---
    print("=" * 64)
    print(f"  exit_code:   {result.exit_code}")
    print(f"  success:     {result.success}")
    print(f"  timed_out:   {result.timed_out}")
    print(f"  duration_s:  {result.duration_s}")
    if result.error:
        print(f"  error:       {result.error}")
    print("=" * 64)

    # --- output ---
    print("\n--- stdout ---")
    if args.verbose:
        print(result.stdout or "<empty>")
    else:
        print((result.stdout or "<empty>")[:1500])
        if result.stdout and len(result.stdout) > 1500:
            print(f"... ({len(result.stdout) - 1500} more chars, use -v)")

    if result.stderr:
        print("\n--- stderr ---")
        if args.verbose:
            print(result.stderr)
        else:
            print(result.stderr[:800])
            if len(result.stderr) > 800:
                print(f"... ({len(result.stderr) - 800} more chars, use -v)")

    # --- JSON dump ---
    if args.json:
        out_dir = _ROOT / "logs"
        out_dir.mkdir(exist_ok=True)
        out_file = out_dir / f"poc_{poc_path.stem}_result.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "poc": poc_path.name,
                    "target": args.target,
                    "port": args.port,
                    "timeout": args.timeout,
                    "extra_env": extra_env,
                    **result.to_dict(),
                },
                f, indent=2, ensure_ascii=False,
            )
        print(f"\nJSON: {out_file}")

    # exit code: 0 если PoC успешен, 1 если нет
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
