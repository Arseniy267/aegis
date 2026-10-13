# Recon — разведка цели (v3: +nuclei +sslscan deep)

import subprocess
import sys
import os
import re

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import (
    WORDLIST, TIMEOUT_NMAP, TIMEOUT_GOBUSTER, TIMEOUT_NIKTO,
    TIMEOUT_CURL, TIMEOUT_NC, TIMEOUT_SSLSCAN, TIMEOUT_SEARCHSPLOIT,
    TIMEOUT_WHOIS, TIMEOUT_DIG
)

from templates.ftp import check_ftp

COMMIX = os.path.expanduser("~/tools/commix/commix.py")
ENUM4LINUX = os.path.expanduser("~/tools/enum4linux/enum4linux.pl")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_USERS = os.path.join(_PROJECT_ROOT, "wordlists", "users_top.txt")
DEFAULT_PASS = os.path.join(_PROJECT_ROOT, "wordlists", "msf_defaults.txt")


def _run(cmd, timeout=60, stderr_to_stdout=False):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout
        if stderr_to_stdout:
            output += "\n" + result.stderr
        return output.strip() or "нет вывода"
    except subprocess.TimeoutExpired:
        return f"timeout ({timeout}s)"
    except FileNotFoundError:
        return f"команда не найдена: {cmd[0]}"
    except Exception as e:
        return f"ошибка: {e}"


# ============ БАЗОВЫЕ ============

def run_nmap(target, scripts=None):
    cmd = ["nmap", "-sV", "-T4", "--top-ports", "100", target]
    if scripts:
        cmd.extend(["--script", scripts])
    return _run(cmd, timeout=TIMEOUT_NMAP)


def run_gobuster(url, wordlist=None):
    if wordlist is None:
        wordlist = WORDLIST
    if not os.path.exists(wordlist):
        return f"словарь {wordlist} не найден"
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "20"]
    return "\n".join(_run(cmd, timeout=TIMEOUT_GOBUSTER).split("\n")[:30])


def run_curl(url):
    return _run(["curl", "-sI", "-m", "10", url], timeout=TIMEOUT_CURL)


def run_nc(host, port):
    return _run(["nc", "-zv", "-w", "3", host, str(port)],
                timeout=TIMEOUT_NC, stderr_to_stdout=True)


def run_dig(domain, record_type="ANY"):
    return "\n".join(_run(["dig", "+short", domain, record_type],
                          timeout=TIMEOUT_DIG).split("\n")[:15])


def run_whois(domain):
    return _run(["whois", domain], timeout=TIMEOUT_WHOIS)[:1000]


def run_searchsploit(query):
    output = _run(["searchsploit", "--disable-colour"] + query.split(),
                  timeout=TIMEOUT_SEARCHSPLOIT)
    lines = output.split("\n")[:20]
    return "\n".join(lines) if lines else "ничего не найдено"


def run_sslscan(host, port=443):
    return "\n".join(_run(["sslscan", f"{host}:{port}"],
                          timeout=TIMEOUT_SSLSCAN).split("\n")[:30])


def run_nikto(url):
    cmd = ["nikto", "-h", url, "-maxtime", "25s", "-nointeractive"]
    return "\n".join(_run(cmd, timeout=TIMEOUT_NIKTO).split("\n")[:30])


def compress_nmap_output(nmap_output):
    lines = nmap_output.split("\n")
    compressed = [l for l in lines if "open" in l or "PORT" in l or "Nmap scan" in l]
    return "\n".join(compressed) or "нет открытых портов"


# ============ FTP (structured) ============

def run_ftp_check(host: str, port: int = 21) -> dict:
    """Структурированная FTP-разведка. Возвращает dict."""
    return check_ftp(
        host, port,
        try_anonymous=True,
        try_ftps=True,
        list_anon_root=True,
    )


def format_ftp_summary(result: dict) -> str:
    """Превращает dict в текст для LLM-промпта."""
    if not result.get("reachable"):
        return f"FTP {result['host']}:{result['port']} unreachable: {result.get('errors')}"

    lines = [f"FTP banner: {result.get('banner')}"]
    if result.get("server"):
        lines.append(f"Server: {result['server']} {result.get('version') or ''}".strip())
    if result.get("os_hint"):
        lines.append(f"OS hint: {result['os_hint']}")
    if result.get("feat"):
        lines.append(f"FEAT: {', '.join(result['feat'])}")
    if result.get("ftps_supported"):
        cn = result.get("ftps_cert_cn") or "?"
        lines.append(f"FTPS: supported (cert CN={cn})")
    if result.get("pasv_works"):
        lines.append("PASV: works")
    if result.get("anonymous_login"):
        lines.append(f"🔴 ANONYMOUS LOGIN WORKS (user={result['anonymous_user']})")
        if result.get("anon_cwd"):
            lines.append(f"Root listing: {', '.join(result['anon_cwd'][:20])}")
    else:
        lines.append("Anonymous login: not allowed")
    if result.get("errors"):
        lines.append(f"Errors: {'; '.join(result['errors'][:3])}")
    return "\n".join(lines)


# ============ РАСШИРЕННЫЕ (SSL / nuclei) ============

def run_sslscan_deep(host, port=443):
    """
    Глубокое SSL/TLS-сканирование через sslscan.
    Возвращает структурированный результат: протоколы, шифры, HSTS.
    """
    out = _run(["sslscan", "--no-colour", f"{host}:{port}"],
               timeout=TIMEOUT_SSLSCAN)
    # Вытаскиваем самое важное
    lines = out.split("\n")
    keep = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if any(k in s for k in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1",
                                 "TLSv1.2", "TLSv1.3", "Accepted", "Preferred",
                                 "Certificate", "Expired", "Self-signed",
                                 "HSTS", "Compression", "Heartbleed",
                                 "CVE-", "WARNING", "weak", "ERROR")):
            keep.append(s)
    return "\n".join(keep[:40]) if keep else out[:1500]


def run_nuclei(url, severity="critical,high,medium", timeout=180):
    """
    Nuclei — поиск уязвимостей в веб-приложении.
    Категории: CVE, misconfig, exposed panels, open redirect, sqli, xss.
    """
    cmd = [
        "nuclei",
        "-u", url,
        "-severity", severity,
        "-silent",
        "-no-color",
        "-timeout", "5",
        "-retries", "1",
        "-rate-limit", "100",
    ]
    out = _run(cmd, timeout=timeout)
    # nuclei возвращает "нет вывода" если ничего не нашёл
    if "нет вывода" in out or not out.strip():
        return "nuclei: уязвимостей не найдено"
    lines = out.split("\n")
    return "\n".join(lines[:50])


# ============ HYDRA ============

def _hydra(service, host, port, userlist, passlist, extra_args=None, timeout=180):
    if not os.path.exists(userlist):
        return f"userlist не найден: {userlist}"
    if not os.path.exists(passlist):
        return f"passlist не найден: {passlist}"

    cmd = [
        "hydra",
        "-L", userlist,
        "-P", passlist,
        "-s", str(port),
        "-t", "4",
        "-f", "-I",
        "-o", "/tmp/aegis_hydra.txt",
    ]
    if extra_args:
        cmd.extend(extra_args)
    cmd += [host, service]

    out = _run(cmd, timeout=timeout, stderr_to_stdout=True)
    lines = []
    for line in out.split("\n"):
        if any(k in line for k in ("[22]", "[21]", "[3306]", "password:", "login:", "host:", "[SUCCESS]")):
            lines.append(line)
    return "\n".join(lines) if lines else out[:1500]


def run_hydra_ssh(host, port=22, userlist=None, passlist=None):
    return _hydra("ssh", host, port, userlist or DEFAULT_USERS, passlist or DEFAULT_PASS, timeout=180)


def run_hydra_ftp(host, port=21, userlist=None, passlist=None):
    return _hydra("ftp", host, port, userlist or DEFAULT_USERS, passlist or DEFAULT_PASS, timeout=180)


def run_hydra_mysql(host, port=3306, userlist=None, passlist=None):
    return _hydra("mysql", host, port, userlist or DEFAULT_USERS, passlist or DEFAULT_PASS, timeout=180)


def run_wpscan(url, timeout=300):
    cmd = ["wpscan", "--url", url, "--no-banner", "--no-update",
           "--disable-tls-checks", "--random-user-agent",
           "-e", "vp,vt,u", "--plugins-detection", "passive"]
    out = _run(cmd, timeout=timeout, stderr_to_stdout=True)
    keep = []
    for line in out.split("\n"):
        s = line.strip()
        if not s:
            continue
        if any(k in s for k in ("[+]", "[!]", "WordPress", "Version", "Plugin", "Theme", "User", "Vulnerab", "XML-RPC", "readme", "Title")):
            keep.append(s)
    return "\n".join(keep[:60]) if keep else out[:2000]


def run_enum4linux(host, timeout=120):
    if not os.path.exists(ENUM4LINUX):
        return f"enum4linux не найден: {ENUM4LINUX}"
    cmd = ["perl", ENUM4LINUX, "-a", host]
    out = _run(cmd, timeout=timeout, stderr_to_stdout=True)
    keep = []
    for line in out.split("\n"):
        s = line.strip()
        if not s:
            continue
        if any(k in s for k in ("[+]", "Target", "Workgroup", "OS:", "Users", "Sharename", "SID", "Password", "Domain")):
            keep.append(s)
    return "\n".join(keep[:80]) if keep else out[:2000]


def run_commix(url, timeout=90):
    if not os.path.exists(COMMIX):
        return f"commix не найден: {COMMIX}"
    cmd = ["python3", COMMIX, "--url", url, "--batch", "--output-dir=/tmp/aegis_commix"]
    out = _run(cmd, timeout=timeout, stderr_to_stdout=True)
    keep = []
    for line in out.split("\n"):
        s = line.strip()
        if not s:
            continue
        if any(k in s for k in ("[+]", "[!]", "[*]", "vulnerable", "injection", "payload", "Testing", "injectable")):
            keep.append(s)
    return "\n".join(keep[:60]) if keep else out[:2000]


def full_recon(target):
    print(f"[*] Запуск nmap на {target}...")
    nmap_out = run_nmap(target)
    compressed = compress_nmap_output(nmap_out)
    print(f"[+] nmap завершён:")
    print(compressed)
    return {"target": target, "nmap_raw": nmap_out, "nmap_compressed": compressed}


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"=== AEGIS Recon v3: {target} ===\n")
    for name, func, args in [
        ("nmap", run_nmap, (target,)),
        ("sslscan_deep", run_sslscan_deep, (target,)),
        ("nuclei", run_nuclei, (f"http://{target}",)),
    ]:
        print(f"[{name}]")
        print(func(*args)[:400])
        print()
