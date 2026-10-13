"""
Whitelist for authorized targets only.

Loads allowed targets from (in order of precedence):
  1. WHITELIST env var (comma-separated)
  2. whitelist.txt in project root (one per line, # comments)
  3. Falls back to localhost only (safe default)

Supports:
  - Exact IP:        192.168.64.7
  - CIDR:            192.168.64.0/24, 10.0.0.0/8
  - Domain:          dvwa.local, example.com
  - Wildcard domain: *.htb.local, *.tryhackme.com
  - Port-scoped:     192.168.64.7:8080  (only this port allowed)

Any URL/hostname/port combination is normalized before matching.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_VAR = "WHITELIST"
_FILE = _PROJECT_ROOT / "whitelist.txt"

# Safe default — if nothing configured, allow only localhost
_DEFAULT = "localhost,127.0.0.1,::1"

# --- internal types -------------------------------------------------------
class _Rule:
    """A single whitelist rule."""
    __slots__ = ("raw", "kind", "value", "port")

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.kind, self.value, self.port = self._parse(raw)

    @staticmethod
    def _parse(raw: str) -> tuple[str, object, int | None]:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            raise ValueError("empty or comment")

        # port-scoped: host:port  (but NOT ipv6)
        port: int | None = None
        if raw.count(":") == 1:
            host, _, port_s = raw.partition(":")
            if port_s.isdigit():
                port = int(port_s)
                raw = host

        # CIDR
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return "cidr", net, port
        except ValueError:
            pass

        # single IP
        try:
            ip = ipaddress.ip_address(raw)
            return "ip", ip, port
        except ValueError:
            pass

        # wildcard domain
        if raw.startswith("*."):
            return "wildcard", raw[2:].lower().rstrip("."), port

        # plain domain
        return "domain", raw.lower().rstrip("."), port

    def matches(self, ip_or_host: str, port: int | None) -> bool:
        # port must match if rule has port
        if self.port is not None and port is not None and self.port != port:
            return False

        if self.kind == "cidr":
            try:
                addr = ipaddress.ip_address(ip_or_host)
                return addr in self.value
            except ValueError:
                return False

        if self.kind == "ip":
            try:
                return ipaddress.ip_address(ip_or_host) == self.value
            except ValueError:
                return False

        if self.kind == "domain":
            return ip_or_host.lower().rstrip(".") == self.value

        if self.kind == "wildcard":
            h = ip_or_host.lower().rstrip(".")
            return h == self.value or h.endswith("." + self.value)

        return False


# --- normalization --------------------------------------------------------
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def normalize_target(target: str) -> tuple[str, int | None]:
    """
    Accepts: URL, host, host:port, IP, IP:port, [v6]:port
    Returns: (host_or_ip, port_or_None)
    """
    target = target.strip()
    if not target:
        raise ValueError("empty target")

    # has scheme → parse as URL
    if "://" in target:
        u = urlparse(target)
        host = u.hostname or ""
        port = u.port
        if not host:
            raise ValueError(f"cannot extract host from {target!r}")
        return host, port

    # plain host or host:port
    if target.startswith("["):  # [::1]:8080
        host, _, rest = target[1:].partition("]")
        port = None
        if rest.startswith(":"):
            maybe = rest[1:]
            if maybe.isdigit():
                port = int(maybe)
        return host, port

    # bare IP without port
    if _IP_RE.match(target):
        return target, None

    # bare host or host:port
    if target.count(":") == 1:
        host, _, p = target.partition(":")
        if p.isdigit():
            return host, int(p)

    return target, None


# --- loading --------------------------------------------------------------
def _load_rules() -> list[_Rule]:
    sources: list[str] = []

    env = os.environ.get(_ENV_VAR, "").strip()
    if env:
        sources.extend(s.strip() for s in env.split(",") if s.strip())

    if _FILE.exists():
        for line in _FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                sources.append(line)

    if not sources:
        log.warning(
            "No whitelist configured (env WHITELIST or whitelist.txt). "
            "Falling back to localhost only."
        )
        sources = [s.strip() for s in _DEFAULT.split(",")]

    rules: list[_Rule] = []
    for s in sources:
        try:
            rules.append(_Rule(s))
        except ValueError as e:
            log.warning("Skipping bad whitelist entry %r: %s", s, e)
    return rules


_RULES: list[_Rule] | None = None


def _rules() -> list[_Rule]:
    global _RULES
    if _RULES is None:
        _RULES = _load_rules()
        log.info("Whitelist loaded: %d rules", len(_RULES))
    return _RULES


def reload() -> None:
    """Force re-read of env/file (useful in tests)."""
    global _RULES
    _RULES = None


# --- public API -----------------------------------------------------------
def is_whitelisted(target: str) -> bool:
    """
    Check if target is allowed.

    Accepts URL, host, host:port, IP, IP:port, CIDR is not a target.
    Returns False on unparseable input (never raises).
    """
    if not target or not isinstance(target, str):
        return False
    try:
        host, port = normalize_target(target)
    except ValueError:
        log.debug("Cannot normalize target %r", target)
        return False

    for rule in _rules():
        if rule.matches(host, port):
            log.debug("Whitelist: %r matched rule %r", target, rule.raw)
            return True

    log.info("Whitelist: %r NOT allowed", target)
    return False


class WhitelistError(PermissionError):
    """Raised when a target is not whitelisted."""


def ensure_whitelisted(target: str) -> None:
    """
    Raise WhitelistError if target is not allowed.
    Use this in orchestrator entry points — fail fast.
    """
    if not is_whitelisted(target):
        allowed = ", ".join(sorted(r.raw for r in _rules()))
        raise WhitelistError(
            f"Target '{target}' is not in whitelist.\n"
            f"Allowed: {allowed}\n"
            f"Add to WHITELIST env var or whitelist.txt."
        )


# --- CLI for debugging ----------------------------------------------------
def _main() -> int:
    import argparse

    p = argparse.ArgumentParser(description="Whitelist checker")
    p.add_argument("target", nargs="?")
    p.add_argument("--list", action="store_true", help="list current rules")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(message)s",
    )

    if args.list or not args.target:
        print(f"Loaded {len(_rules())} rules:")
        for r in _rules():
            print(f"  [{r.kind:8}] {r.raw}  (value={r.value}, port={r.port})")
        return 0

    try:
        host, port = normalize_target(args.target)
        print(f"Normalized: host={host!r} port={port}")
    except ValueError as e:
        print(f"Cannot normalize: {e}")
        return 2

    if is_whitelisted(args.target):
        print(f"✓ ALLOWED: {args.target}")
        return 0
    else:
        print(f"✗ DENIED:  {args.target}")
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
