# modules/rag.py — CVE lookup (v5: priority fix + cache + logging)
"""
CVE lookup pipeline.

Priority (correct order):
    1. ChromaDB local cache    (мгновенно, offline)
    2. NVD API                 (точный, требует интернет)
    3. KNOWN_CVES              (fallback, захардкоженные для offline)

Requires NVD_API_KEY env var for fast access (0.7s delay vs 6.5s).
"""
from __future__ import annotations

import os
import re
import sys
import time
from datetime import datetime, timezone

import requests
import structlog
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(_ROOT, ".env"))
except ImportError:
    pass

import chromadb

log = structlog.get_logger("rag")


# --- paths & config -----------------------------------------------------
# ChromaDB: prefer external SSD via env; fallback to project dir
DB_PATH = os.environ.get(
    "CHROMA_PATH",
    os.path.join(_ROOT, "knowledge", "chroma_db"),
)
COLLECTION_NAME = "cve_exploits"

# NVD
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
NVD_DELAY = 0.7 if NVD_API_KEY else 6.5
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
YEARS_BACK = 5


# --- http session with retries ------------------------------------------
_session: requests.Session | None = None


def _get_session() -> requests.Session:
    global _session
    if _session is not None:
        return _session
    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=("GET",),
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    _session = s
    return s


# ========================================================================
# KNOWN_CVES — fallback only (offline / NVD down)
# ========================================================================
KNOWN_CVES = [
    # ====================================================================
    # LEGACY (Metasploitable2, старые CTF)
    # ====================================================================
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
    {
        "pattern": r"Tomcat",
        "cves": [
            {"cve_id": "CVE-2017-12615", "score": 9.8, "year": 2017,
             "desc": "Tomcat 7.0.0-7.0.79: RCE через PUT-запрос (требует readonly=false)."},
            {"cve_id": "CVE-2020-1938", "score": 9.8, "year": 2020,
             "desc": "Tomcat AJP Ghostcat: file read / RCE через AJP (порт 8009)."},
        ],
    },

    # ====================================================================
    # WEB APPS (HTB/THM)
    # ====================================================================
    {
        "pattern": r"Drupal\s*[78]\.",
        "cves": [
            {"cve_id": "CVE-2018-7600", "score": 9.8, "year": 2018,
             "desc": "Drupal 7.x < 7.58 / 8.x < 8.5.1: RCE через Form API (Drupalgeddon2)."},
            {"cve_id": "CVE-2014-3704", "score": 7.5, "year": 2014,
             "desc": "Drupal 7.x < 7.32: SQL injection (Drupalgeddon1)."},
        ],
    },
    {
        "pattern": r"WordPress",
        "cves": [
            {"cve_id": "CVE-2017-8295", "score": 5.9, "year": 2017,
             "desc": "WordPress < 4.8.2: password reset через Host header."},
            {"cve_id": "CVE-2019-8943", "score": 5.4, "year": 2019,
             "desc": "WordPress < 5.0.1: path traversal в wp_crop_image (нужен admin)."},
        ],
    },
    {
        "pattern": r"Jenkins",
        "cves": [
            {"cve_id": "CVE-2018-1000861", "score": 9.8, "year": 2018,
             "desc": "Jenkins < 2.150.1: RCE через Stapler routing (unauthenticated)."},
            {"cve_id": "CVE-2019-1003000", "score": 8.8, "year": 2019,
             "desc": "Jenkins < 2.150.2: sandbox bypass в Script Security (нужен Groovy)."},
        ],
    },
    {
        "pattern": r"GitLab",
        "cves": [
            {"cve_id": "CVE-2021-22205", "score": 10.0, "year": 2021,
             "desc": "GitLab CE/EE < 13.10.3: unauthenticated RCE через ExifTool DjVu."},
        ],
    },
    {
        "pattern": r"Confluence",
        "cves": [
            {"cve_id": "CVE-2021-26084", "score": 9.8, "year": 2021,
             "desc": "Confluence Server < 7.13.0: OGNL injection RCE (unauthenticated)."},
            {"cve_id": "CVE-2023-22515", "score": 10.0, "year": 2023,
             "desc": "Confluence Data Center < 8.5.1: broken access control — создать admin."},
        ],
    },
    {
        "pattern": r"WebLogic",
        "cves": [
            {"cve_id": "CVE-2020-14882", "score": 9.8, "year": 2020,
             "desc": "Oracle WebLogic: RCE через console (unauthenticated)."},
            {"cve_id": "CVE-2019-2725", "score": 9.8, "year": 2019,
             "desc": "WebLogic < 10.3.6 / 12.1.3: RCE через wls-wsat (unauthenticated)."},
        ],
    },

    # ====================================================================
    # UNIVERSAL WEB-TECH
    # ====================================================================
    {
        "pattern": r"Apache\s*httpd\s*2\.4\.(49|50)",
        "cves": [
            {"cve_id": "CVE-2021-41773", "score": 9.8, "year": 2021,
             "desc": "Apache 2.4.49: path traversal + RCE (mod_cgi)."},
            {"cve_id": "CVE-2021-42013", "score": 9.8, "year": 2021,
             "desc": "Apache 2.4.50: неполный фикс CVE-2021-41773, обход через '.%2e'."},
        ],
    },
    {
        "pattern": r"OpenSSL\s*1\.0\.1",
        "cves": [
            {"cve_id": "CVE-2014-0160", "score": 7.5, "year": 2014,
             "desc": "OpenSSL 1.0.1-1.0.1f: Heartbleed — утечка памяти (ключа) через TLS heartbeat."},
        ],
    },
    {
        "pattern": r"PHP[- ]?FPM",
        "cves": [
            {"cve_id": "CVE-2019-11043", "score": 9.8, "year": 2019,
             "desc": "PHP-FPM < 7.1.33: buffer underflow RCE через fastcgi_split_path_info."},
        ],
    },
    {
        "pattern": r"(Log4j|Log4Shell)",
        "cves": [
            {"cve_id": "CVE-2021-44228", "score": 10.0, "year": 2021,
             "desc": "Apache Log4j2 < 2.15.0: JNDI RCE через лог-сообщение."},
            {"cve_id": "CVE-2021-45046", "score": 9.0, "year": 2021,
             "desc": "Log4j2 < 2.16.0: обход фикса CVE-2021-44228 через context lookup."},
        ],
    },
    {
        "pattern": r"Spring",
        "cves": [
            {"cve_id": "CVE-2022-22965", "score": 9.8, "year": 2022,
             "desc": "Spring Framework < 5.3.18: RCE через data binding (Spring4Shell). Требует Java 9+ и WAR на Tomcat."},
        ],
    },
    {
    "pattern": r"(Bash|CGI|CGI-BIN|shellshock)",
    "cves": [
        {"cve_id": "CVE-2014-6271", "score": 9.8, "year": 2014,
         "desc": "GNU Bash < 4.3: Shellshock, RCE через env-переменные. "
                 "Применимо ТОЛЬКО если на цели есть CGI-скрипты на bash."},
    ],
    },

    # ====================================================================
    # NETWORK SERVICES
    # ====================================================================
    {
        "pattern": r"Microsoft.*SMB|Windows.*SMB",
        "cves": [
            {"cve_id": "CVE-2017-0144", "score": 8.1, "year": 2017,
             "desc": "SMBv1 EternalBlue: RCE (MS17-010). Требует SMBv1 включённым."},
            {"cve_id": "CVE-2020-0796", "score": 10.0, "year": 2020,
             "desc": "SMBv3 compression SMBGhost: RCE на Windows 10 1903/1909."},
        ],
    },
    {
        "pattern": r"RDP|ms-wbt-server",
        "cves": [
            {"cve_id": "CVE-2019-0708", "score": 9.8, "year": 2019,
             "desc": "RDP BlueKeep: pre-auth RCE на Windows 7 / Server 2008."},
        ],
    },
    {
        "pattern": r"OpenSSH\s*[89]\.[0-7]",
        "cves": [
            {"cve_id": "CVE-2024-6387", "score": 8.1, "year": 2024,
             "desc": "OpenSSH 8.5p1-9.7p1: regreSSHion — race condition RCE (glibc-based)."},
        ],
    },
    {
        "pattern": r"Elasticsearch",
        "cves": [
            {"cve_id": "CVE-2015-1427", "score": 9.8, "year": 2015,
             "desc": "Elasticsearch < 1.4.3: Groovy sandbox bypass RCE."},
            {"cve_id": "CVE-2014-3120", "score": 9.8, "year": 2014,
             "desc": "Elasticsearch < 1.2.0: RCE через MVEL script (dynamic scripting)."},
        ],
    },
    {
        "pattern": r"Redis",
        "cves": [
            {"cve_id": "CVE-2022-0543", "score": 10.0, "year": 2022,
             "desc": "Redis Lua sandbox escape RCE (Debian/Ubuntu package-specific)."},
        ],
    },

    # ====================================================================
    # VPN APPLIANCES
    # ====================================================================
    {
        "pattern": r"Fortinet|FortiGate|FortiOS",
        "cves": [
            {"cve_id": "CVE-2018-13379", "score": 9.8, "year": 2018,
             "desc": "FortiOS SSL VPN path traversal — чтение creds из session-файла."},
        ],
    },
    {
        "pattern": r"Citrix|NetScaler",
        "cves": [
            {"cve_id": "CVE-2019-19781", "score": 9.8, "year": 2019,
             "desc": "Citrix ADC path traversal + RCE (unauthenticated)."},
        ],
    },
    {
        "pattern": r"Pulse|PulseSecure",
        "cves": [
            {"cve_id": "CVE-2019-11510", "score": 10.0, "year": 2019,
             "desc": "Pulse Secure SSL VPN: произвольное чтение файлов, включая сессии и creds."},
        ],
    },

    # ====================================================================
    # EXCHANGE
    # ====================================================================
    {
        "pattern": r"Microsoft.*Exchange|Exchange Server",
        "cves": [
            {"cve_id": "CVE-2021-26855", "score": 9.8, "year": 2021,
             "desc": "Exchange ProxyLogon: SSRF → RCE (комплекс с CVE-2021-26857/26858/27065)."},
            {"cve_id": "CVE-2021-34473", "score": 9.8, "year": 2021,
             "desc": "Exchange ProxyShell: pre-auth RCE (комплекс с CVE-2021-34523/31207)."},
        ],
    },

    # ====================================================================
    # ANGIE / MIKROTIK (специфика твоих тестов)
    # ====================================================================
    {
        "pattern": r"Angie",
        "cves": [
            {"cve_id": "CVE-2024-7347", "score": 4.7, "year": 2024,
             "desc": "Angie < 1.8.0 (nginx < 1.27.0): OOB read в ngx_http_mp4_module. Требуется версия для подтверждения."},
            {"cve_id": "CVE-2023-44487", "score": 7.5, "year": 2023,
             "desc": "HTTP/2 Rapid Reset — универсальная DoS для всех HTTP/2-серверов (nginx, Angie, Apache, IIS, Envoy)."},
            {"cve_id": "CVE-2021-23017", "score": 7.7, "year": 2021,
             "desc": "nginx resolver off-by-one. Применимо ТОЛЬКО если в конфиге используется resolver (use resolver)."},
        ],
    },
    {
        "pattern": r"Mikrotik\s*dnsd",
        "cves": [
            {"cve_id": "CVE-2023-30800", "score": 7.5, "year": 2023,
             "desc": "MikroTik RouterOS: DoS в DNS-сервере через malformed DNS-пакет."},
        ],
    },
    {
        "pattern": r"(RouterOS|Winbox)",
        "cves": [
            {"cve_id": "CVE-2018-14847", "score": 9.8, "year": 2018,
             "desc": "MikroTik RouterOS 6.29-6.42: Winbox auth bypass (порт 8291)."},
        ],
    },
]


def known_cves_for(service: str, version: str) -> list[dict]:
    haystack = f"{service} {version}".strip()
    out: list[dict] = []
    for entry in KNOWN_CVES:
        if re.search(entry["pattern"], haystack, re.IGNORECASE):
            out.extend(entry["cves"])
    return out


def format_known_cves(cves: list[dict]) -> str:
    lines = []
    for c in sorted(cves, key=lambda x: -x["score"]):
        lines.append(
            f"- {c['cve_id']} ({c['year']}, CVSS: {c['score']}): {c['desc']}"
        )
    return "\n".join(lines)


# ========================================================================
# ChromaDB
# ========================================================================
_client = None


def get_client():
    global _client
    if _client is None:
        os.makedirs(DB_PATH, exist_ok=True)
        _client = chromadb.PersistentClient(path=DB_PATH)
        log.info("chroma_client_ready", path=DB_PATH)
    return _client


def get_collection(client):
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )


# ========================================================================
# NVD
# ========================================================================
def extract_year(cve_id: str) -> int:
    try:
        return int(cve_id.split("-")[1])
    except (ValueError, IndexError):
        return 0


def _parse_nvd_response(data: dict, keyword: str, years_back: int | None = None) -> list[dict]:
    results: list[dict] = []
    min_year = 0
    if years_back:
        min_year = datetime.now(timezone.utc).year - years_back

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
        for mt in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(mt):
                cvss = metrics[mt][0].get("cvssData", {})
                score = float(cvss.get("baseScore", 0.0))
                break

        results.append({
            "cve_id": cve_id,
            "description": description,
            "score": score,
            "keyword": keyword,
            "year": year,
        })
    return results


def fetch_cve_from_nvd(keyword: str, max_results: int = 30,
                       years_back: int | None = None) -> list[dict]:
    time.sleep(NVD_DELAY)   # rate limit (0.7s with key, 6.5s without)

    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        r = _get_session().get(NVD_URL, params=params, headers=headers, timeout=60)

        if r.status_code == 429:
            log.warning("nvd_rate_limit", keyword=keyword)
            time.sleep(10)
            r = _get_session().get(NVD_URL, params=params, headers=headers, timeout=60)

        if r.status_code != 200:
            log.warning("nvd_bad_status", keyword=keyword, status=r.status_code)
            return []

        return _parse_nvd_response(r.json(), keyword, years_back)

    except requests.RequestException as e:
        log.warning("nvd_request_failed", keyword=keyword, err=str(e))
        return []


def sort_cve(cve_list: list[dict]) -> list[dict]:
    return sorted(
        cve_list,
        key=lambda c: (c.get("year", 0), c.get("score", 0.0)),
        reverse=True,
    )


# ========================================================================
# Indexing / searching
# ========================================================================
def index_cve(cve_list: list[dict], service_hint: str = "") -> int:
    """
    Сохраняет CVE в ChromaDB.

    ВАЖНО: keyword = service_hint (например "ftp"), НЕ полный NVD-запрос.
    Это исправляет баг, из-за которого search_cve_local никогда не находил записи.
    """
    if not cve_list:
        return 0

    collection = get_collection(get_client())
    documents, metadatas, ids = [], [], []

    for i, cve in enumerate(cve_list):
        cve_id = cve.get("cve_id", "")
        # пропустить, если уже есть (id детерминирован)
        doc_id = f"cve_{cve_id}"

        text = (
            f"{cve_id} [{service_hint or cve.get('keyword', '')}] "
            f"[{cve.get('year', '')}]: {cve['description']} "
            f"(CVSS: {cve['score']})"
        )
        documents.append(text)
        metadatas.append({
            "cve_id": cve_id,
            "score": float(cve["score"]),
            "keyword": service_hint or cve.get("keyword", ""),
            "year": int(cve.get("year", 0)),
        })
        ids.append(doc_id)

    try:
        # upsert — не падаем, если запись уже есть
        collection.upsert(documents=documents, metadatas=metadatas, ids=ids)
        log.debug("chroma_indexed", count=len(documents), service=service_hint)
        return len(documents)
    except Exception as e:
        log.error("chroma_index_failed", err=str(e), service=service_hint)
        return 0


def search_cve_local(query: str, n_results: int = 5,
                     keyword_filter: str | None = None,
                     min_year: int | None = None) -> list[str]:
    try:
        collection = get_collection(get_client())
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

        results = collection.query(
            query_texts=[query],
            n_results=min(n_results, collection.count()),
            where=where,
        )
        docs = (results.get("documents") or [[]])[0]
        if docs:
            log.debug("chroma_cache_hit", query=query, n=len(docs))
        return docs or []
    except Exception as e:
        log.warning("chroma_search_failed", err=str(e), query=query)
        return []


# ========================================================================
# Public API
# ========================================================================
def get_cve_context(service, version=None, n=5, years_back=YEARS_BACK):
    ver = (version or "").strip()
    query = f"{service} {ver}".strip()
    min_year = datetime.now(timezone.utc).year - years_back

    log.debug("cve_lookup_started", service=service, version=ver)

    # --- ПРОВЕРКА: версия не определена ---
    version_known = (
        ver
        and ver.lower() not in ("unknown", "?", "-", service.lower())
        and any(ch.isdigit() for ch in ver)   # есть хоть одна цифра
    )

    if not version_known:
        # NVD-запрос по имени без версии — мусор, не делаем
        known = known_cves_for(service, ver)
        if known:
            header = (f"[!] {service}: версия не определена — "
                      f"CVE требуют ручной проверки:\n")
            return header + format_known_cves(known[:n])
        return (f"[!] {service}: версия не определена, "
                f"CVE не найдены без уточнения версии.")

    # 1. Кеш
    cached = search_cve_local(
        query,
        n_results=n,
        keyword_filter=service,      # ← теперь совпадает с index_cve
        min_year=min_year,
    )
    if cached:
        log.info("cve_lookup_cache_hit", service=service, version=ver, n=len(cached))
        return "\n".join(cached)

    # 2. NVD
    cves = fetch_cve_from_nvd(query, max_results=50)
    if cves:
        cves = sort_cve(cves)
        fresh = [c for c in cves if c["year"] >= min_year]
        chosen = fresh[:n] if fresh else cves[:n]
        index_cve(chosen, service_hint=service)
        log.info("cve_lookup_nvd_hit", service=service, version=ver, n=len(chosen))
        return "\n".join(
            f"- {c['cve_id']} ({c.get('year', '?')}, CVSS: {c['score']}): "
            f"{c['description'][:200]}"
            for c in chosen
        )

    # 3. Fallback
    known = known_cves_for(service, ver)
    if known:
        log.info("cve_lookup_fallback_known", service=service, version=ver,
                 n=len(known))
        return format_known_cves(known[:n])

    log.info("cve_lookup_empty", service=service, version=ver)
    return ""


def get_cve_batch(queries: dict) -> dict:
    """queries: {port: (service, version)}"""
    return {port: get_cve_context(svc, ver) for port, (svc, ver) in queries.items()}


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)-7s %(message)s")

    print("NVD API key:", "да" if NVD_API_KEY else "НЕТ")
    print("ChromaDB path:", DB_PATH)
    print()
    print("=== vsftpd 2.3.4 ===")
    print(get_cve_context("ftp", "vsftpd 2.3.4"))
    print("\n=== Angie ===")
    print(get_cve_context("http", "Angie"))
    print("\n=== Mikrotik dnsd ===")
    print(get_cve_context("domain", "Mikrotik dnsd"))
