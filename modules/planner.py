# Planner — полный анализ цели (v4: +nuclei +sslscan deep)

import sys
import os
import re
import hashlib
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from modules.analyzer import ask_llm
from modules.rag import get_cve_context
from modules.recon import (
    run_nmap, run_gobuster, run_curl, run_nc,
    run_dig, run_whois, run_searchsploit,
    run_sslscan, run_sslscan_deep, run_nikto, compress_nmap_output,
    run_hydra_ssh, run_hydra_ftp, run_hydra_mysql,
    run_wpscan, run_enum4linux, run_commix,
    run_nuclei,
    run_ftp_check, format_ftp_summary,
)

ENABLE_BRUTEFORCE = os.environ.get("AEGIS_BRUTEFORCE", "0") == "1"
ENABLE_NUCLEI = os.environ.get("AEGIS_NO_NUCLEI", "0") != "1"

CACHE_DIR = os.path.expanduser("~/.aegis_cache/nmap")
CACHE_TTL = 3600
USE_CACHE = os.environ.get("AEGIS_NO_CACHE", "0") != "1"

SKIP_CVE_SERVICES = {"login", "shell", "tcpwrapped", "unknown", "X11", "rpcbind"}


def _cache_key(target):
    return hashlib.sha1(target.encode()).hexdigest()


def _cache_get(target):
    if not USE_CACHE:
        return None
    path = os.path.join(CACHE_DIR, f"{_cache_key(target)}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        if time.time() - data.get("ts", 0) > CACHE_TTL:
            return None
        return data.get("nmap_raw")
    except Exception:
        return None


def _cache_set(target, nmap_raw):
    if not USE_CACHE:
        return
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, f"{_cache_key(target)}.json")
    try:
        with open(path, "w") as f:
            json.dump({"ts": time.time(), "nmap_raw": nmap_raw}, f)
    except Exception:
        pass


def parse_nmap_ports(nmap_output):
    ports = []
    for line in nmap_output.split("\n"):
        match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?$", line.strip())
        if match:
            ports.append({
                "port": int(match.group(1)),
                "service": match.group(2),
                "version": (match.group(3) or "").strip()
            })
    return ports


def detect_target_type(target):
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        return "ip"
    return "domain"


def _cve_stats(cve_text):
    ids = re.findall(r"CVE-\d{4}-\d{4,}", cve_text or "")
    count = len(set(ids))
    scores = re.findall(r"CVSS:\s*([\d.]+)", cve_text or "")
    max_score = max([float(s) for s in scores], default=0.0)
    return count, max_score


def full_analysis(target, quiet=False):
    def log(*a):
        if not quiet:
            print(*a)

    log(f"\n[*] Начинаю полную разведку: {target}\n")

    data = {"target": target, "type": detect_target_type(target)}

    # 1. DNS / WHOIS
    if data["type"] == "domain":
        log("[1/7] DNS + WHOIS...")
        data["dig"] = run_dig(target)
        data["whois"] = run_whois(target)
    else:
        data["dig"] = None
        data["whois"] = None

    # 2. nmap
    log("[2/7] nmap...")
    cached = _cache_get(target)
    if cached:
        log("     [cache] использую кэш")
        data["nmap_raw"] = cached
    else:
        data["nmap_raw"] = run_nmap(target)
        _cache_set(target, data["nmap_raw"])
    data["nmap_compressed"] = compress_nmap_output(data["nmap_raw"])
    data["ports"] = parse_nmap_ports(data["nmap_raw"])
    log(f"     Открыто портов: {len(data['ports'])}")
    for p in data["ports"]:
        log(f"     - {p['port']}/{p['service']} {p['version'][:50]}")

    # 3. Сервисы
    log("[3/7] Проверка сервисов...")
    data["services"] = {}

    for p in data["ports"]:
        port, svc = p["port"], p["service"]
        res = {}

       # СТАЛО:
    if port == 21:
        ftp_result = run_ftp_check(target, port)
        res["ftp"] = format_ftp_summary(ftp_result)
        res["ftp_structured"] = ftp_result       # пригодится для script_gen / exploit
        if ENABLE_BRUTEFORCE:
            res["hydra_ftp"] = run_hydra_ftp(target, port)

        elif port == 22:
            res["nc"] = run_nc(target, port)
            if ENABLE_BRUTEFORCE:
                res["hydra_ssh"] = run_hydra_ssh(target, port)

        elif port in (80, 8080, 8000):
            url = f"http://{target}:{port}" if port != 80 else f"http://{target}"
            res["curl"] = run_curl(url)
            res["nikto"] = run_nikto(url)[:1500]
            if ENABLE_NUCLEI:
                res["nuclei"] = run_nuclei(url)[:2500]
            if "?" in url:
                res["commix"] = run_commix(url)[:1500]
            curl_txt = (res.get("curl") or "").lower()
            if "wordpress" in curl_txt or "wp-" in curl_txt:
                res["wpscan"] = run_wpscan(url)[:2000]

        elif port in (443, 8443, 9443):
            url = f"https://{target}" if port == 443 else f"https://{target}:{port}"
            res["curl"] = run_curl(url)
            res["sslscan"] = run_sslscan_deep(target, port)[:2000]
            if ENABLE_NUCLEI:
                res["nuclei"] = run_nuclei(url)[:2500]

        elif port in (139, 445):
            res["enum4linux"] = run_enum4linux(target)[:2000]

        elif port == 3306:
            res["nc"] = run_nc(target, port)
            if ENABLE_BRUTEFORCE:
                res["hydra_mysql"] = run_hydra_mysql(target, port)

        else:
            res["nc"] = run_nc(target, port)

        data["services"][port] = res

    # 4. searchsploit
    log("[4/7] searchsploit...")
    data["exploits"] = {}
    for p in data["ports"]:
        if p["version"]:
            data["exploits"][p["port"]] = run_searchsploit(p["version"][:40])[:1500]

    # 5. RAG — CVE
    log("[5/7] RAG — CVE...")
    data["cves"] = {}
    for p in data["ports"]:
        svc = p["service"]
        ver = p["version"]
        if not ver:
            continue
        if svc in SKIP_CVE_SERVICES:
            continue
        data["cves"][p["port"]] = get_cve_context(svc, ver)

    for p in data["ports"]:
        cve_text = data["cves"].get(p["port"], "")
        cnt, mx = _cve_stats(cve_text)
        p["cve_count"] = cnt
        p["max_score"] = mx

    # 6. LLM
    log("[6/7] LLM анализ...")
    data["analysis"] = _build_analysis(target, data)

    log("[7/7] Анализ завершён\n")
    return data


def _build_analysis(target, data):
    parts = [f"ЦЕЛЬ: {target}\n"]
    parts.append("=== ОТКРЫТЫЕ ПОРТЫ ===")
    parts.append(data["nmap_compressed"])

    if data.get("dig"):
        parts.append(f"\n=== DNS ===\n{data['dig'][:500]}")

    if data.get("services"):
        parts.append("\n=== ПРОВЕРКА СЕРВИСОВ ===")
        for port, svc in data["services"].items():
            parts.append(f"\n--- Порт {port} ---")
            for tool, output in svc.items():
                parts.append(f"[{tool}]\n{output[:800]}")

    if data.get("cves"):
        parts.append("\n=== CVE ИЗ БАЗЫ (реальные, не выдумывай другие) ===")
        for port, cves in data["cves"].items():
            parts.append(f"\n--- Порт {port} ---\n{cves[:800]}")

    prompt = "\n".join(parts) + """

ВАЖНО:
- Используй ТОЛЬКО те CVE, что даны в секции "CVE ИЗ БАЗЫ".
- НЕ придумывай CVE.
- Если CVE не найдены — так и напиши: "CVE не найдены, поверхность атаки — N портов".
- Обращай внимание на результат nuclei и sslscan — это реальные находки, отражай их.
- Не пиши общих фраз типа "multiple vulnerabilities allow attackers".

Проанализируй результаты и дай:
1. Список запущенных сервисов — строго по nmap-выводу.
2. Реальные CVE — только из секции "CVE ИЗ БАЗЫ". Если пусто — так и скажи.
3. Результаты nuclei/sslscan — что важно.
4. Векторы атаки — по приоритету.
5. Рекомендации по защите.

Отвечай технически, кратко. Без общих слов.
"""
    return ask_llm(prompt)


def full_analysis_multi(targets, max_workers=3):
    print(f"\n[*] Multi-target: {len(targets)} целей, workers={max_workers}\n")
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(full_analysis, t, quiet=True): t for t in targets}
        for fut in as_completed(futures):
            t = futures[fut]
            try:
                results[t] = fut.result()
                print(f"[+] {t}: ок, портов = {len(results[t]['ports'])}")
            except Exception as e:
                print(f"[!] {t}: ошибка — {e}")
                results[t] = {"target": t, "error": str(e), "ports": []}
    return results


def read_targets_file(path="targets.txt"):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    data = full_analysis(target)
    print("\n=== ИТОГ ===")
    print(f"Портов: {len(data['ports'])}")
    print(f"\nАнализ:\n{data['analysis'][:1000]}")
