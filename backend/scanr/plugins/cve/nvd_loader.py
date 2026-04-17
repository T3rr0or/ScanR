"""NVD CVE feed loader.

Downloads NVD JSON feeds and stores them in a local SQLite database
for offline CPE-to-CVE matching.
"""
from __future__ import annotations

import gzip
import json
import logging
import sqlite3
from pathlib import Path
from typing import Iterator

import httpx

from scanr.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

NVD_FEEDS = [
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz",
] + [
    f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
    for year in range(2020, 2026)
]

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DB_PATH = settings.nvd_cache_dir / "nvd.db"
KEV_DB_PATH = settings.nvd_cache_dir / "kev.db"
LAST_UPDATED_PATH = settings.nvd_cache_dir / "last_updated.txt"


def _get_conn() -> sqlite3.Connection:
    settings.nvd_cache_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            severity TEXT,
            cpe_matches TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cpe ON cves(cpe_matches)")
    conn.commit()
    return conn


def download_feeds() -> None:
    """Download and index NVD feeds + CISA KEV into local SQLite DBs."""
    conn = _get_conn()
    cache_dir = settings.nvd_cache_dir

    for url in NVD_FEEDS:
        gz_path = cache_dir / Path(url).name
        try:
            logger.info("Downloading NVD feed: %s", url)
            with httpx.Client(timeout=120) as client:
                resp = client.get(url)
                resp.raise_for_status()
            gz_path.write_bytes(resp.content)

            with gzip.open(gz_path, "rt", encoding="utf-8") as f:
                data = json.load(f)

            _index_feed(conn, data)
            logger.info("Indexed feed: %s (%d CVEs)", url, len(data.get("CVE_Items", [])))
        except Exception as exc:
            logger.warning("Failed to process feed %s: %s", url, exc)

    conn.close()
    download_cisa_kev()
    LAST_UPDATED_PATH.write_text(__import__("datetime").datetime.utcnow().isoformat())


def download_cisa_kev() -> None:
    """Download CISA Known Exploited Vulnerabilities catalog."""
    try:
        settings.nvd_cache_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading CISA KEV catalog...")
        with httpx.Client(timeout=30) as client:
            resp = client.get(CISA_KEV_URL)
            resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])

        conn = sqlite3.connect(str(KEV_DB_PATH))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT
            )
        """)
        for v in vulns:
            conn.execute(
                "INSERT OR REPLACE INTO kev VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    v.get("cveID"), v.get("vendorProject"), v.get("product"),
                    v.get("vulnerabilityName"), v.get("dateAdded"),
                    v.get("shortDescription"), v.get("requiredAction"),
                ),
            )
        conn.commit()
        conn.close()
        logger.info("CISA KEV: indexed %d known exploited CVEs", len(vulns))
    except Exception as exc:
        logger.warning("Failed to download CISA KEV: %s", exc)


def get_kev_cve_ids() -> set[str]:
    """Return set of CVE IDs that are actively exploited per CISA KEV."""
    if not KEV_DB_PATH.exists():
        return set()
    try:
        conn = sqlite3.connect(str(KEV_DB_PATH))
        rows = conn.execute("SELECT cve_id FROM kev").fetchall()
        conn.close()
        return {r[0] for r in rows}
    except Exception:
        return set()


def get_last_updated() -> str | None:
    """Return ISO timestamp of last CVE feed refresh, or None."""
    try:
        return LAST_UPDATED_PATH.read_text().strip() if LAST_UPDATED_PATH.exists() else None
    except Exception:
        return None


def _index_feed(conn: sqlite3.Connection, data: dict) -> None:
    for item in data.get("CVE_Items", []):
        try:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            desc = ""
            for d in item["cve"]["description"]["description_data"]:
                if d["lang"] == "en":
                    desc = d["value"]
                    break

            cvss_score = None
            cvss_vector = None
            severity = "unknown"

            impact = item.get("impact", {})
            if "baseMetricV3" in impact:
                cvss_score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
                cvss_vector = impact["baseMetricV3"]["cvssV3"]["vectorString"]
                severity = impact["baseMetricV3"]["cvssV3"]["baseSeverity"].lower()
            elif "baseMetricV2" in impact:
                cvss_score = impact["baseMetricV2"]["cvssV2"]["baseScore"]
                severity = impact["baseMetricV2"]["severity"].lower()

            # Collect CPE strings
            cpes: list[str] = []
            for config_node in item.get("configurations", {}).get("nodes", []):
                for cpe_match in config_node.get("cpe_match", []):
                    if cpe_match.get("vulnerable"):
                        cpes.append(cpe_match["cpe23Uri"])

            conn.execute(
                "INSERT OR REPLACE INTO cves VALUES (?, ?, ?, ?, ?, ?)",
                (cve_id, desc, cvss_score, cvss_vector, severity, json.dumps(cpes)),
            )
        except Exception:
            continue
    conn.commit()


def search_by_product(product: str, version: str) -> list[dict]:
    """Find CVEs matching a product/version string."""
    if not DB_PATH.exists():
        return []
    conn = _get_conn()
    product_lower = product.lower()
    rows = conn.execute(
        "SELECT cve_id, description, cvss_score, cvss_vector, severity, cpe_matches FROM cves"
    ).fetchall()
    conn.close()

    matches = []
    for cve_id, desc, score, vector, sev, cpe_json in rows:
        cpes = json.loads(cpe_json) if cpe_json else []
        for cpe in cpes:
            parts = cpe.split(":")
            # cpe:2.3:a:vendor:product:version:...
            if len(parts) >= 5:
                cpe_product = parts[4].lower()
                cpe_version = parts[5] if len(parts) > 5 else "*"
                if product_lower in cpe_product and (cpe_version == "*" or version in cpe_version):
                    matches.append({
                        "cve_id": cve_id,
                        "description": desc,
                        "cvss_score": score,
                        "cvss_vector": vector,
                        "severity": sev,
                    })
                    break
    return matches
