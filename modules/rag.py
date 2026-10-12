# RAG — CVE через NVD + ChromaDB (v4: +Angie +Mikrotik)

import sys
import os
import re
import time
import asyncio
import requests
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(_ROOT, ".env"))
except ImportError:
    pass

import chromadb

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


DB_PATH = os.path.expanduser("~/Projects/aegis/knowledge/chroma_db")
COLLECTION_NAME = "cve_exploits"
YEARS_BACK = 5
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_DELAY = 0.7 if NVD_API_KEY else 6.5
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


KNOWN_CVES = [
    # ===== Старые системы =====
    {
        "pattern": r"vsftpd\s*2\.3\.4",
        "cves": [
            {"cve_id": "CVE-2011-2523", "score": 10.0, "year": 2011,
             "desc": "vsftpd 2.3.4 backdoor: логин с ':)' открывает root shell на порту 6200."},
        ],
    },
    {
        "pattern": r"Samba\s*3\.[0-9]|smbd\s*3\.",
        "cves": [
            {"cve_id": "CVE-2007-2447", "score": 10.0, "year": 2007,
             "desc": "Samba 3.0.0-3.0.25rc3: username map script RCE."},
        ],
    },
    {
        "pattern": r"UnrealIRCd",
        "cves": [
            {"cve_id": "CVE-2010-2075", "score": 10.0, "year": 2010,
             "desc": "UnrealIRCd 3.2.8.1: backdoor."},
        ],
    },
    {
        "pattern": r"PHP/5\.",
        "cves": [
            {"cve_id": "CVE-2012-1823", "score": 9.8, "year": 2012,
             "desc": "PHP-CGI 5.3.12/5.4.2: RCE через query string."},
        ],
    },
    {
        "pattern": r"VNC.*3\.3",
        "cves": [
            {"cve_id": "CVE-2006-2369", "score": 7.5, "year": 2006,
             "desc": "RealVNC 4.1.1: обход аутентификации через security type None."},
        ],
    },
    {
        "pattern": r"OpenSSH\s*[4-7]\.",
        "cves": [
            {"cve_id": "CVE-2016-0777", "score": 6.5, "year": 2016,
             "desc": "OpenSSH client roaming: утечка приватного ключа."},
            {"cve_id": "CVE-2018-15473", "score": 5.3, "year": 2018,
             "desc": "OpenSSH < 7.7: user enumeration."},
        ],
    },
    {
        "pattern": r"Apache\s*httpd\s*2\.2",
        "cves": [
            {"cve_id": "CVE-2017-7659", "score": 7.5, "year": 2017,
             "desc": "Apache 2.2.x: DoS через malformed HTTP/2 request."},
        ],
    },
    {
        "pattern": r"MySQL\s*5\.0",
        "cves": [
            {"cve_id": "CVE-2012-2122", "score": 5.1, "year": 2012,
             "desc": "MySQL 5.0.x: обход аутентификации через повторные попытки."},
        ],
    },
    {
        "pattern": r"PostgreSQL.*8\.3",
        "cves": [
            {"cve_id": "CVE-2013-1900", "score": 4.9, "year": 2013,
             "desc": "PostgreSQL 8.3.x: утечка памяти через RNG."},
        ],
    },
    {
        "pattern": r"ProFTPD\s*1\.3\.1",
        "cves": [
            {"cve_id": "CVE-2010-4221", "score": 10.0, "year": 2010,
             "desc": "ProFTPD 1.3.1: stack overflow в mod_tls (pre-auth RCE)."},
        ],
    },
    {
        "pattern": r"ISC\s*BIND\s*9\.4",
        "cves": [
            {"cve_id": "CVE-2008-0122", "score": 5.0, "year": 2008,
             "desc": "BIND 9.4.x: off-by-one в inet_network(), DoS."},
        ],
    },

    # ===== Современные сервисы =====
    # Angie — форк nginx. CVE совпадают с nginx.
    {
        "pattern": r"Angie",
        "cves": [
            {"cve_id": "CVE-2024-7347", "score": 4.7, "year": 2024,
             "desc": "nginx/1.27.0 (Angie < 1.8.0): out-of-bounds read в ngx_http_mp4_module."},
            {"cve_id": "CVE-2023-44487", "score": 7.5, "year": 2023,
             "desc": "HTTP/2 Rapid Reset (все HTTP/2-серверы, включая nginx/Angie). DoS."},
            {"cve_id": "CVE-2021-23017", "score": 7.7, "year": 2021,
             "desc": "nginx resolver: off-by-one в DNS-ответе (при use resolver)."},
        ],
    },
    # Mikrotik dnsd
    {
        "pattern": r"Mikrotik\s*dnsd|RouterOS",
        "cves": [
            {"cve_id": "CVE-2023-30800", "score": 7.5, "year": 2023,
             "desc": "MikroTik RouterOS: DoS в DNS-сервере через malformed DNS-пакет."},
            {"cve_id": "CVE-2018-14847", "score": 9.8, "year": 2018,
             "desc": "MikroTik RouterOS 6.29-6.42: Winbox auth bypass (не dnsd, но актуально)."},
        ],
    },
]


def known_cves_for(service, version):
    haystack = f"{service} {version}".strip()
    result = []
    for entry in KNOWN_CVES:
        if re.search(entry["pattern"], haystack, re.IGNORECASE):
            result.extend(entry["cves"])
    return result


def format_known_cves(cves):
    lines = []
    for c in sorted(cves, key=lambda x: -x["score"]):
        lines.append(f"- {c['cve_id']} ({c['year']}, CVSS: {c['score']}): {c['desc']}")
    return "\n".join(lines)


# ============ NVD fallback ============

def get_client():
    os.makedirs(DB_PATH, exist_ok=True)
    return chromadb.PersistentClient(path=DB_PATH)


def get_collection(client):
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"}
    )


def extract_year(cve_id):
    try:
        return int(cve_id.split("-")[1])
    except (ValueError, IndexError):
        return 0


def _parse_nvd_response(data, keyword, years_back=None):
    results = []
    min_year = 0
    if years_back:
        min_year = datetime.now().year - years_back
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cve_id = cve.get("id", "N/A")
        year = extract_year(cve_id)
        if years_back and year < min_year:
            continue
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        metrics = cve.get("metrics", {})
        score = 0.0
        for mt in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if mt in metrics and metrics[mt]:
                cvss = metrics[mt][0].get("cvssData", {})
                score = cvss.get("baseScore", 0.0)
                break
        results.append({
            "cve_id": cve_id, "description": description, "score": score,
            "keyword": keyword, "year": year,
        })
    return results


def fetch_cve_from_nvd(keyword, max_results=30, years_back=None):
    time.sleep(NVD_DELAY)
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
        if r.status_code == 429:
            print("[!] NVD rate limit — жду 10 сек...")
            time.sleep(10)
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
        if r.status_code != 200:
            return []
        return _parse_nvd_response(r.json(), keyword, years_back)
    except requests.RequestException:
        return []


def sort_cve(cve_list):
    return sorted(cve_list, key=lambda c: (c.get("year", 0), c.get("score", 0.0)), reverse=True)


def index_cve(cve_list):
    if not cve_list:
        return 0
    client = get_client()
    collection = get_collection(client)
    documents, metadatas, ids = [], [], []
    for i, cve in enumerate(cve_list):
        text = f"{cve['cve_id']} [{cve.get('keyword', '')}] [{cve.get('year', '')}]: {cve['description']} (CVSS: {cve['score']})"
        documents.append(text)
        metadatas.append({
            "cve_id": cve["cve_id"], "score": float(cve["score"]),
            "keyword": cve.get("keyword", ""), "year": cve.get("year", 0),
        })
        ids.append(f"cve_{cve['cve_id']}_{i}")
    try:
        collection.add(documents=documents, metadatas=metadatas, ids=ids)
        return len(documents)
    except Exception:
        return 0


def search_cve_local(query, n_results=5, keyword_filter=None, min_year=None):
    client = get_client()
    collection = get_collection(client)
    if collection.count() == 0:
        return []
    conditions = []
    if keyword_filter:
        conditions.append({"keyword": keyword_filter})
    if min_year:
        conditions.append({"year": {"$gte": min_year}})
    where = None
    if len(conditions) == 1:
        where = conditions[0]
    elif len(conditions) > 1:
        where = {"$and": conditions}
    try:
        results = collection.query(
            query_texts=[query],
            n_results=min(n_results, collection.count()),
            where=where,
        )
        if not results["documents"] or not results["documents"][0]:
            return []
        return results["documents"][0]
    except Exception:
        return []


def get_cve_context(service, version=None, n=5, years_back=YEARS_BACK):
    """Приоритет: KNOWN_CVES → ChromaDB → NVD."""
    ver = version or ""
    known = known_cves_for(service, ver)
    if known:
        return format_known_cves(known[:n])

    query = f"{service} {ver}".strip()
    min_year = datetime.now().year - years_back
    cached = search_cve_local(query, n_results=n, keyword_filter=service, min_year=min_year)
    if cached:
        return "\n".join(cached)

    cves = fetch_cve_from_nvd(query, max_results=50)
    if not cves:
        return ""
    cves = sort_cve(cves)
    fresh = [c for c in cves if c["year"] >= min_year]
    chosen = fresh[:n] if fresh else cves[:n]
    index_cve(chosen)
    return "\n".join([
        f"- {c['cve_id']} ({c.get('year', '?')}, CVSS: {c['score']}): {c['description'][:200]}"
        for c in chosen
    ])


def get_cve_batch(queries):
    return {port: get_cve_context(svc, ver) for port, (svc, ver) in queries.items()}


if __name__ == "__main__":
    print("API key:", "да" if NVD_API_KEY else "НЕТ")
    print("\n=== vsftpd ===")
    print(get_cve_context("ftp", "vsftpd 2.3.4"))
    print("\n=== Angie ===")
    print(get_cve_context("http", "Angie"))
    print("\n=== Mikrotik dnsd ===")
    print(get_cve_context("domain", "Mikrotik dnsd"))
