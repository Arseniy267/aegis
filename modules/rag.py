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
    # ... оставить весь твой текущий список без изменений ...
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
def get_cve_context(service: str, version: str | None = None,
                    n: int = 5, years_back: int = YEARS_BACK) -> str:
    """
    Приоритет:
        1. ChromaDB (быстро, offline)
        2. NVD      (точно, online)
        3. KNOWN_CVES (fallback при offline)
    """
    ver = version or ""
    query = f"{service} {ver}".strip()
    min_year = datetime.now(timezone.utc).year - years_back

    log.debug("cve_lookup_started", service=service, version=ver)

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
