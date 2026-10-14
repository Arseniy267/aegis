# safety/sandbox.py — Docker-based isolated PoC runner (v2)
"""
Runs PoC scripts in an isolated Docker container.

Isolation:
    - read-only rootfs, only /tmp writable
    - non-root user (uid 1000)
    - no new privileges, all caps dropped
    - 256 MB RAM, 1 CPU, 64 PIDs
    - DNS disabled (--dns 127.0.0.1) — cannot resolve domains
    - timeout enforced by subprocess + docker kill

NOT isolated (by design, MVP):
    - container can reach target IP over bridge network
    - no egress firewall — will be added in v3 with iptables-sidecar

Prerequisite:
    docker build -f docker/sandbox.Dockerfile -t aegis-sandbox:latest .
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass

import structlog

log = structlog.get_logger("sandbox")

# --- config --------------------------------------------------------------
SANDBOX_IMAGE = os.environ.get("AEGIS_SANDBOX_IMAGE", "aegis-sandbox:latest")
NETWORK_NAME = os.environ.get("AEGIS_SANDBOX_NETWORK", "aegis-sandbox")

MEMORY_LIMIT = "256m"
CPU_LIMIT = "1.0"
PIDS_LIMIT = "64"
TMPFS_SIZE = "32m"
DEFAULT_TIMEOUT = 60


# --- result model --------------------------------------------------------
@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None
    container_name: str | None = None
    duration_s: float = 0.0

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.error

    def to_dict(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "error": self.error,
            "success": self.success,
            "duration_s": self.duration_s,
        }


# --- helpers -------------------------------------------------------------
def _docker_available() -> bool:
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _ensure_network() -> None:
    r = subprocess.run(
        ["docker", "network", "inspect", NETWORK_NAME],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        subprocess.run(
            ["docker", "network", "create",
             "--driver", "bridge",
             NETWORK_NAME],
            check=True, capture_output=True,
        )
        log.info("sandbox_network_created", network=NETWORK_NAME)


def _kill_container(name: str) -> None:
    subprocess.run(
        ["docker", "kill", name],
        capture_output=True,
    )


# --- public API ----------------------------------------------------------
def run_in_sandbox(
    script: str,
    target_ip: str,
    target_port: int | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    extra_env: dict[str, str] | None = None,
) -> SandboxResult:
    """Запускает Python-скрипт в изолированном контейнере."""
    t0 = time.time()

    if not _docker_available():
        log.error("docker_unavailable")
        return SandboxResult(
            exit_code=-1, stdout="", stderr="",
            error="docker daemon not available",
        )

    _ensure_network()
    container_name = f"aegis-sbx-{uuid.uuid4().hex[:8]}"

    # проверка образа
    check = subprocess.run(
        ["docker", "image", "inspect", SANDBOX_IMAGE],
        capture_output=True, text=True,
    )
    if check.returncode != 0:
        log.error("sandbox_image_missing", image=SANDBOX_IMAGE)
        return SandboxResult(
            exit_code=-1, stdout="", stderr="",
            error=f"image '{SANDBOX_IMAGE}' not found. "
                  f"Build: docker build -f docker/sandbox.Dockerfile -t {SANDBOX_IMAGE} .",
        )

    with tempfile.TemporaryDirectory(prefix="aegis-sbx-") as tmpdir:
        script_path = os.path.join(tmpdir, "poc.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)
        os.chmod(script_path, 0o644)

        cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--network", NETWORK_NAME,
            "--add-host", f"target:{target_ip}",
            "--dns", "127.0.0.1",
            "--memory", MEMORY_LIMIT,
            "--memory-swap", MEMORY_LIMIT,
            "--cpus", CPU_LIMIT,
            "--pids-limit", PIDS_LIMIT,
            "--read-only",
            "--tmpfs", f"/tmp:rw,size={TMPFS_SIZE},noexec,nosuid",
            "--user", "1000:1000",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-v", f"{script_path}:/poc.py:ro",
            "-e", f"TARGET={target_ip}",
            "-e", "PYTHONUNBUFFERED=1",
        ]
        if target_port:
            cmd += ["-e", f"TARGET_PORT={target_port}"]
        if extra_env:
            for k, v in extra_env.items():
                cmd += ["-e", f"{k}={v}"]

        cmd += [SANDBOX_IMAGE, "python", "/poc.py"]

        log.info(
            "sandbox_run_started",
            target=target_ip, port=target_port,
            timeout=timeout, container=container_name,
        )

        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            dur = round(time.time() - t0, 2)
            result = SandboxResult(
                exit_code=r.returncode,
                stdout=(r.stdout or "")[-16000:],
                stderr=(r.stderr or "")[-8000:],
                container_name=container_name,
                duration_s=dur,
            )
            log.info("sandbox_run_done",
                     target=target_ip, exit=result.exit_code, duration_s=dur)
            return result

        except subprocess.TimeoutExpired:
            _kill_container(container_name)
            dur = round(time.time() - t0, 2)
            log.warning("sandbox_timeout",
                        target=target_ip, timeout=timeout, duration_s=dur)
            return SandboxResult(
                exit_code=-1, stdout="", stderr="",
                timed_out=True, container_name=container_name,
                duration_s=dur,
            )

        except Exception as e:
            _kill_container(container_name)
            log.exception("sandbox_run_failed", target=target_ip)
            return SandboxResult(
                exit_code=-1, stdout="", stderr="",
                error=str(e), container_name=container_name,
                duration_s=round(time.time() - t0, 2),
            )


# --- CLI --------------------------------------------------------------
def _main() -> int:
    import argparse
    import json
    import logging

    p = argparse.ArgumentParser(description="AEGIS sandbox test runner")
    p.add_argument("target", help="target IP")
    p.add_argument("script", help="path to .py file to run")
    p.add_argument("--port", type=int)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )

    with open(args.script, encoding="utf-8") as f:
        script = f.read()

    result = run_in_sandbox(
        script=script,
        target_ip=args.target,
        target_port=args.port,
        timeout=args.timeout,
    )
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(_main())
