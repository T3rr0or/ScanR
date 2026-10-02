"""FIRST EPSS scores: the daily probability that a CVE is exploited in the wild.

The full feed (~300k CVEs, ~3 MB gzipped) is published once a day and stored
in a SQLite file beside the NVD and KEV catalogs, so scoring a finding is a
local primary-key lookup and scans never wait on the network.
"""
from __future__ import annotations

import csv
import gzip
import io
import logging
import sqlite3
from datetime import datetime, timezone

import httpx

from scanr.config import get_settings

logger = logging.getLogger(__name__)

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def _db_path():
    return get_settings().nvd_cache_dir / "epss.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path()))
    conn.execute("CREATE TABLE IF NOT EXISTS epss (cve_id TEXT PRIMARY KEY, score REAL, percentile REAL)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    return conn


def parse_feed(raw: bytes) -> tuple[str | None, list[tuple[str, float, float]]]:
    """Return (score_date, rows) from the gzipped CSV.

    The first line is a comment like
    ``#model_version:v2026.06.15,score_date:2026-10-02T12:00:20Z``.
    """
    text = gzip.decompress(raw).decode("utf-8")
    lines = text.splitlines()
    score_date = None
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            key, _, value = part.partition(":")
            if key.strip() == "score_date":
                score_date = value.strip()
        lines = lines[1:]
    rows = []
    for record in csv.DictReader(io.StringIO("\n".join(lines))):
        try:
            rows.append((record["cve"].strip().upper(), float(record["epss"]), float(record["percentile"])))
        except (KeyError, ValueError, AttributeError):
            continue
    return score_date, rows


def _fetch_feed() -> bytes:
    """GET the feed, following only HTTPS redirects on the feed's own host.

    The "current" URL redirects to the dated file. Redirects are authorized one
    by one rather than followed blindly, like every other client in ScanR.
    """
    url = httpx.URL(EPSS_URL)
    with httpx.Client(timeout=120) as client:
        for _ in range(4):
            resp = client.get(url)
            if not resp.is_redirect:
                resp.raise_for_status()
                return resp.content
            target = url.join(resp.headers.get("location", ""))
            if target.scheme != "https" or target.host != url.host:
                raise ValueError(f"EPSS feed redirected off-site to {target}")
            url = target
    raise ValueError("EPSS feed redirected too many times")


def download_epss() -> int:
    """Fetch and store today's scores. Returns the number of CVEs indexed."""
    settings = get_settings()
    settings.nvd_cache_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Downloading EPSS scores...")
    score_date, rows = parse_feed(_fetch_feed())
    if len(rows) < 1000:
        # A truncated or changed feed must not wipe yesterday's good data.
        raise ValueError(f"EPSS feed looks wrong: only {len(rows)} rows")
    conn = _connect()
    try:
        with conn:
            conn.execute("DELETE FROM epss")
            conn.executemany("INSERT OR REPLACE INTO epss VALUES (?, ?, ?)", rows)
            fetched = datetime.now(timezone.utc).isoformat()
            conn.executemany(
                "INSERT OR REPLACE INTO meta VALUES (?, ?)",
                [("score_date", score_date or ""), ("fetched_at", fetched)],
            )
    finally:
        conn.close()
    logger.info("EPSS: indexed %d CVEs (score date %s)", len(rows), score_date)
    return len(rows)


def lookup(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """Map each known CVE id to (score, percentile). Unknown ids are omitted."""
    ids = sorted({c.strip().upper() for c in cve_ids if c})
    if not ids or not _db_path().exists():
        return {}
    try:
        conn = _connect()
        try:
            rows = []
            # Chunked: older SQLite builds cap a statement at 999 parameters.
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                placeholders = ",".join("?" * len(chunk))
                rows += conn.execute(
                    f"SELECT cve_id, score, percentile FROM epss WHERE cve_id IN ({placeholders})", chunk
                ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.warning("EPSS lookup failed: %s", exc)
        return {}
    return {cve: (score, pct) for cve, score, pct in rows}


def status() -> dict[str, str | int | None]:
    if not _db_path().exists():
        return {"score_date": None, "fetched_at": None, "count": 0}
    try:
        conn = _connect()
        try:
            meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
            count = conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error:
        return {"score_date": None, "fetched_at": None, "count": 0}
    return {"score_date": meta.get("score_date") or None, "fetched_at": meta.get("fetched_at"), "count": count}
