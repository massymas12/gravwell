"""CVE enrichment: CISA KEV + FIRST.org EPSS.

Two free, no-API-key sources:
  - CISA KEV  : CVEs confirmed actively exploited in the wild.
  - EPSS      : Machine-learning probability (0–100 %) a CVE will be exploited.

Call enrich_cves(db_path) to fetch and cache results in the local SQLite DB.
"""
from __future__ import annotations
import json
import threading
import urllib.request
from datetime import datetime, timezone

from gravwell.database import get_session
from gravwell.models.orm import CVERefORM, CVEEnrichmentORM

# ── Data-source URLs ──────────────────────────────────────────────────────────

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_EPSS_URL = "https://api.first.org/data/v1/epss"
_EPSS_BATCH = 100      # CVEs per EPSS request (comma-separated in query string)
_HTTP_TIMEOUT = 30     # seconds

# ── Public API ────────────────────────────────────────────────────────────────


def enrich_cves(db_path: str, progress_cb=None) -> dict:
    """Fetch KEV + EPSS data for every CVE stored in the DB.

    Returns a stats dict: {cve_count, kev_count, epss_count}.
    progress_cb(message: str) is called with human-readable status updates.
    """
    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    # Collect unique CVE IDs already in the DB
    with get_session(db_path) as session:
        cve_ids: list[str] = sorted({
            r.cve_id for r in session.query(CVERefORM.cve_id).all()
        })

    if not cve_ids:
        return {"cve_count": 0, "kev_count": 0, "epss_count": 0}

    _cb(f"Fetching CISA KEV catalog...")
    kev_map = _fetch_kev()

    _cb(f"Fetching EPSS scores for {len(cve_ids):,} CVEs...")
    epss_map = _fetch_epss(cve_ids, _cb)

    now = datetime.now(timezone.utc)
    with get_session(db_path) as session:
        for cve_id in cve_ids:
            rec = session.query(CVEEnrichmentORM).filter_by(cve_id=cve_id).first()
            if not rec:
                rec = CVEEnrichmentORM(cve_id=cve_id)
                session.add(rec)

            kev = kev_map.get(cve_id.upper())
            rec.in_kev = kev is not None
            rec.kev_date_added = kev.get("dateAdded") if kev else None
            rec.kev_name = (kev.get("vulnerabilityName") or "")[:256] if kev else None

            epss = epss_map.get(cve_id.upper())
            rec.epss_score = float(epss["epss"]) if epss else None
            rec.epss_percentile = float(epss["percentile"]) if epss else None
            rec.fetched_at = now

        session.commit()

    kev_count = sum(1 for c in cve_ids if c.upper() in kev_map)
    epss_count = sum(1 for c in cve_ids if c.upper() in epss_map)
    return {"cve_count": len(cve_ids), "kev_count": kev_count, "epss_count": epss_count}


# ── Private fetch helpers ─────────────────────────────────────────────────────


def _fetch_kev() -> dict:
    """Download the full CISA KEV JSON. Returns {CVE-ID-UPPER: record}."""
    req = urllib.request.Request(
        _KEV_URL, headers={"User-Agent": "gravwell/1.0", "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        data = json.loads(resp.read())
    return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}


def _fetch_epss(cve_ids: list[str], progress_cb=None) -> dict:
    """Fetch EPSS scores in batches. Returns {CVE-ID-UPPER: {epss, percentile}}."""
    result: dict[str, dict] = {}
    total = len(cve_ids)

    for i in range(0, total, _EPSS_BATCH):
        batch = cve_ids[i : i + _EPSS_BATCH]
        url = _EPSS_URL + "?cve=" + ",".join(batch)
        req = urllib.request.Request(
            url, headers={"User-Agent": "gravwell/1.0", "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read())
            for item in data.get("data", []):
                result[item["cve"].upper()] = {
                    "epss": item["epss"],
                    "percentile": item["percentile"],
                }
        except Exception:
            pass  # network hiccup — skip this batch, not fatal

        done = min(i + _EPSS_BATCH, total)
        if progress_cb and done < total:
            progress_cb(f"EPSS: {done:,}/{total:,} CVEs...")

    return result


# ── Shared display helper (used by callbacks) ─────────────────────────────────


def exploit_label(cve_ids: list[str], enrich_map: dict) -> str:
    """Return a short exploit-signal string for a set of CVE IDs.

    Examples:  "KEV | 97%"   "KEV"   "97%"   ""
    enrich_map is {cve_id.upper(): CVEEnrichmentORM}.
    """
    in_kev = any(
        enrich_map.get(c.upper()) and enrich_map[c.upper()].in_kev
        for c in cve_ids
    )
    epss_scores = [
        enrich_map[c.upper()].epss_score
        for c in cve_ids
        if c.upper() in enrich_map and enrich_map[c.upper()].epss_score is not None
    ]
    max_epss = max(epss_scores) if epss_scores else None

    parts: list[str] = []
    if in_kev:
        parts.append("KEV")
    if max_epss is not None:
        parts.append(f"{max_epss * 100:.0f}%")
    return " | ".join(parts)
