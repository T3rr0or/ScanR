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
    for year in range(2020, 2025)
]

DB_PATH = settings.nvd_cache_dir / "nvd.db"


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
    """Download and index NVD feeds into local SQLite DB."""
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
