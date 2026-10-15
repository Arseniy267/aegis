# modules/planner.py — полный анализ цели (v4 + whitelist + parallel safe)
"""
Pipeline:
    1. DNS / WHOIS
    2. nmap
    3. Проверка сервисов (nc, curl, nikto, nuclei, sslscan, ...)
    4. searchsploit
    5. RAG — CVE (NVD + Chroma)
    6. LLM анализ
    7. Возврат dict

Multi-target: см. full_analysis_multi (whitelist-фильтр, max_workers=1 для 18 GB RAM).
"""
from __future__ import annotations

import sys
import os
import re
import hashlib
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import structlog

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
from safety.whitelist import is_whitelisted, ensure_whitelisted

log = structlog.get_logger("planner")


# --- настройки ---
ENABLE_BRUTEFORCE = os.environ.get("AEGIS_BRUTEFORCE", "0") == "1"
ENABLE_NUCLEI = os.environ.get("AEGIS_NO_NUCLEI", "0") != "1"

CACHE_DIR = os.path.expanduser("~/.aegis_cache/nmap")
CACHE_TTL = 3600
USE_CACHE = os.environ.get("AEGIS_NO_CACHE", "0") != "1"

SKIP_CVE_SERVICES = {"login", "shell", "tcpwrapped", "unknown", "X11", "rpcbind"}


# ============================================================================
# Кэш nmap
# ============================================================================
def _cache_key(target: str) -> str:
    return hashlib.sha1(target.encode()).hexdigest()


def _cache_get(target: str) -> str | None:
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


def _cache_set(target: str, nmap_raw: str) -> None:
    if not USE_CACHE:
        return
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, f"{_cache_key(target)}.json")
    try:
        with open(path, "w") as f:
            json.dump({"ts": time.time(), "nmap_raw": nmap_raw}, f)
    except Exception:
        pass


# ============================================================================
# Парсинг
# ============================================================================
def parse_nmap_ports(nmap_output: str) -> list[dict]:
    ports = []
    for line in nmap_output.split("\n"):
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?$", line.strip())
        if m:
            ports.append({
                "port": int(m.group(1)),
                "service": m.group(2),
                "version": (m.group(3) or "").strip(),
            })
    return ports


def detect_target_type(target: str) -> str:
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        return "ip"
    return "domain"


def _cve_stats(cve_text: str) -> tuple[int, float]:
    ids = re.findall(r"CVE-\d{4}-\d{4,}", cve_text or "")
    count = len(set(ids))
    scores = re.findall(r"CVSS:\s*([\d.]+)", cve_text or "")
    max_score = max([float(s) for s in scores], default=0.0)
    return count, max_score


# ============================================================================
# Основной pipeline
# ============================================================================
def full_analysis(target: str, quiet: bool = False) -> dict:
    def _print(*a):
        if not quiet:
            print(*a)

    # 🔴 whitelist ДО любых сетевых вызовов
    ensure_whitelisted(target)

    log.info("full_analysis_started", target=target)
    _print(f"\n[*] Начинаю полную разведку: {target}\n")

    data: dict = {"target": target, "type": detect_target_type(target)}

    # --- 1. DNS / WHOIS ---
    if data["type"] == "domain":
        _print("[1/7] DNS + WHOIS...")
        data["dig"] = run_dig(target)
        data["whois"] = run_whois(target)
    else:
        data["dig"] = None
        data["whois"] = None

    # --- 2. nmap ---
    _print("[2/7] nmap...")
    cached = _cache_get(target)
    if cached:
        _print("     [cache] использую кэш")
        log.debug("nmap_cache_hit", target=target)
        data["nmap_raw"] = cached
    else:
        t0 = time.time()
        data["nmap_raw"] = run_nmap(target)
        log.info("stage_nmap_done", target=target,
                 elapsed_s=round(time.time() - t0, 1))
        _cache_set(target, data["nmap_raw"])
    data["nmap_compressed"] = compress_nmap_output(data["nmap_raw"])
    data["ports"] = parse_nmap_ports(data["nmap_raw"])
    _print(f"     Открыто портов: {len(data['ports'])}")
    for p in data["ports"]:
        _print(f"     - {p['port']}/{p['service']} {p['version'][:50]}")
    log.info("stage_ports_parsed", target=target, n=len(data["ports"]))

    # --- 3. Проверка сервисов ---
    _print("[3/7] Проверка сервисов...")
    data["services"] = {}

    for p in data["ports"]:
        port, svc = p["port"], p["service"]
        res: dict = {}
        log.debug("service_check_started", target=target, port=port, service=svc)

        if port == 21:
            ftp_result = run_ftp_check(target, port)
            res["ftp"] = format_ftp_summary(ftp_result)
            res["ftp_structured"] = ftp_result
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
        log.debug("service_check_done", target=target, port=port,
                  tools=list(res.keys()))

    # --- 4. searchsploit ---
    _print("[4/7] searchsploit...")
    data["exploits"] = {}
    for p in data["ports"]:
        if p["version"]:
            data["exploits"][p["port"]] = run_searchsploit(p["version"][:40])[:1500]

    # --- 5. RAG — CVE ---
    _print("[5/7] RAG — CVE...")
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

    n_with_cve = sum(1 for p in data["ports"] if p.get("cve_count", 0) > 0)
    log.info("stage_cve_done", target=target, ports_with_cve=n_with_cve)

    # --- 6. LLM ---
    _print("[6/7] LLM анализ...")
    t0 = time.time()
    data["analysis"] = _build_analysis(target, data)
    log.info("stage_llm_done", target=target,
             elapsed_s=round(time.time() - t0, 1),
             resp_len=len(data.get("analysis", "")))

    _print("[7/7] Анализ завершён\n")
    log.info("full_analysis_finished", target=target,
             ports=len(data["ports"]),
             cves=sum(p.get("cve_count", 0) for p in data["ports"]))
    return data


def _build_analysis(target: str, data: dict) -> str:
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
                if tool == "ftp_structured":
                    continue   # это dict, не для промпта
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
- Обращай внимание на результат nuclei и sslscan — это реальные находки.
- Если сервис помечен "[!] версия не определена" — перенеси оговорку в отчёт.

Проанализируй результаты и дай:
1. Список запущенных сервисов — строго по nmap-выводу.
2. Реальные CVE — только из секции "CVE ИЗ БАЗЫ".
3. Результаты nuclei/sslscan — что важно.
4. Векторы атаки — по приоритету.
5. Рекомендации по защите.

Отвечай технически, кратко. Без общих слов.
"""
    log.debug("llm_prompt_built", target=target, prompt_len=len(prompt))
    return ask_llm(prompt)


# ============================================================================
# Multi-target
# ============================================================================
def full_analysis_multi(targets: list[str], max_workers: int = 1) -> dict:
    """
    Multi-target анализ.

    max_workers=1 (рекомендуется для 18 GB RAM): последовательно.
    max_workers>1: через ThreadPoolExecutor.
    Цели не в whitelist пропускаются с логом.
    """
    safe = [t for t in targets if is_whitelisted(t)]
    skipped = [t for t in targets if t not in set(safe)]

    if skipped:
        log.warning("multi_skipped_not_whitelisted", skipped=skipped)
        print(f"[!] Пропущено (не в whitelist): {', '.join(skipped)}")

    if not safe:
        log.error("multi_no_valid_targets", input_count=len(targets))
        print("[!] Ни одной цели в whitelist — выход")
        return {}

    log.info("multi_started", n=len(safe), workers=max_workers)
    print(f"\n[*] Multi-target: {len(safe)} целей, workers={max_workers}\n")

    results: dict = {}

    if max_workers <= 1:
        for t in safe:
            try:
                log.info("multi_target_started", target=t)
                results[t] = full_analysis(t, quiet=True)
                n_ports = len(results[t].get("ports", []))
                print(f"[+] {t}: ок, портов = {n_ports}")
                log.info("multi_target_done", target=t, ports=n_ports)
            except Exception as e:
                print(f"[!] {t}: ошибка — {e}")
                log.exception("multi_target_failed", target=t)
                results[t] = {"target": t, "error": str(e), "ports": []}
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(full_analysis, t, quiet=True): t for t in safe}
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    results[t] = fut.result()
                    n_ports = len(results[t].get("ports", []))
                    print(f"[+] {t}: ок, портов = {n_ports}")
                    log.info("multi_target_done", target=t, ports=n_ports)
                except Exception as e:
                    print(f"[!] {t}: ошибка — {e}")
                    log.exception("multi_target_failed", target=t)
                    results[t] = {"target": t, "error": str(e), "ports": []}

    n_ok = sum(1 for r in results.values() if not r.get("error"))
    n_fail = len(results) - n_ok
    log.info("multi_finished",
             total_input=len(targets), scanned=len(safe),
             skipped=len(skipped), ok=n_ok, failed=n_fail)
    print(f"\n[*] Итог: {n_ok} ок, {n_fail} ошибок, "
          f"{len(skipped)} пропущено (не в whitelist)\n")
    return results


# ============================================================================
# targets.txt reader
# ============================================================================
def read_targets_file(path: str = "targets.txt") -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]
