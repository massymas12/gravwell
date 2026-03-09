"""CVE enrichment: CISA KEV + FIRST.org EPSS + NIST NVD CVSS.

Three free, no-API-key sources:
  - CISA KEV  : CVEs confirmed actively exploited in the wild.
  - EPSS      : Machine-learning probability (0–100 %) a CVE will be exploited.
  - NIST NVD  : Authoritative CVSS v3 base scores.

Call enrich_cves(db_path) to fetch and cache results in the local SQLite DB.
"""
from __future__ import annotations
import json
import threading
import time
import urllib.request
from datetime import datetime, timezone

from gravwell.database import get_session
from gravwell.models.orm import CVERefORM, CVEEnrichmentORM, VulnerabilityORM

# ── Data-source URLs ──────────────────────────────────────────────────────────

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_EPSS_URL = "https://api.first.org/data/v1/epss"
_NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EPSS_BATCH = 100      # CVEs per EPSS request (comma-separated in query string)
_NVD_DELAY  = 0.7      # seconds between NVD requests (public rate limit: 5/30s)
_HTTP_TIMEOUT = 30     # seconds

# ── Public API ────────────────────────────────────────────────────────────────


def enrich_cves(db_path: str, progress_cb=None) -> dict:
    """Fetch KEV + EPSS + NVD CVSS data for every CVE stored in the DB.

    Returns a stats dict: {cve_count, kev_count, epss_count, nvd_count}.
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
        # CVEs that already have a cached NVD score — skip re-fetching
        already_cached: set[str] = {
            r.cve_id.upper()
            for r in session.query(CVEEnrichmentORM).all()
            if r.nvd_cvss is not None
        }

    if not cve_ids:
        return {"cve_count": 0, "kev_count": 0, "epss_count": 0, "nvd_count": 0}

    _cb("Fetching CISA KEV catalog...")
    kev_map = _fetch_kev()

    _cb(f"Fetching EPSS scores for {len(cve_ids):,} CVEs...")
    epss_map = _fetch_epss(cve_ids, _cb)

    # NVD CVSS — only fetch CVEs not already cached
    nvd_needed = [c for c in cve_ids if c.upper() not in already_cached]
    nvd_map: dict[str, float] = {}
    if nvd_needed:
        _cb(f"Fetching NVD CVSS scores for {len(nvd_needed):,} CVEs "
            f"(~{len(nvd_needed) * _NVD_DELAY:.0f}s)...")
        nvd_map = _fetch_nvd_cvss(nvd_needed, _cb)

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

            nvd_score = nvd_map.get(cve_id.upper())
            if nvd_score is not None:
                rec.nvd_cvss = nvd_score

            rec.fetched_at = now

        # Write NVD CVSS scores back to VulnerabilityORM so the CVSS column
        # shows real values (overwriting severity-approximated scores).
        if nvd_map:
            _apply_nvd_cvss_to_vulns(session, nvd_map)

        session.commit()

    kev_count = sum(1 for c in cve_ids if c.upper() in kev_map)
    epss_count = sum(1 for c in cve_ids if c.upper() in epss_map)
    nvd_count  = len(nvd_map)
    return {
        "cve_count": len(cve_ids),
        "kev_count": kev_count,
        "epss_count": epss_count,
        "nvd_count": nvd_count,
    }


# ── Private fetch helpers ─────────────────────────────────────────────────────


def _fetch_kev() -> dict:
    """Download the full CISA KEV JSON. Returns {CVE-ID-UPPER: record}."""
    req = urllib.request.Request(
        _KEV_URL, headers={"User-Agent": "gravwell/1.0", "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        data = json.loads(resp.read())
    return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}


def _fetch_nvd_cvss(cve_ids: list[str], progress_cb=None) -> dict[str, float]:
    """Fetch CVSS v3 base scores from the NVD API (one request per CVE).

    Returns {CVE-ID-UPPER: base_score}.  CVEs not found or errored are omitted.
    Rate limit: 5 public requests / 30 s — enforced by _NVD_DELAY between calls.
    """
    result: dict[str, float] = {}
    total = len(cve_ids)

    for i, cve_id in enumerate(cve_ids):
        url = f"{_NVD_URL}?cveId={cve_id}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "gravwell/1.0", "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read())
            vulns = data.get("vulnerabilities", [])
            if vulns:
                metrics = vulns[0].get("cve", {}).get("metrics", {})
                # Prefer v3.1, fall back to v3.0, then v2
                score = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entries = metrics.get(key, [])
                    if entries:
                        score = entries[0].get("cvssData", {}).get("baseScore")
                        if score is not None:
                            break
                if score is not None:
                    result[cve_id.upper()] = float(score)
        except Exception:
            pass  # network hiccup or CVE not in NVD — skip

        if progress_cb and (i + 1) % 25 == 0:
            progress_cb(f"NVD CVSS: {i + 1:,}/{total:,} CVEs...")

        if i < total - 1:
            time.sleep(_NVD_DELAY)

    return result


def _apply_nvd_cvss_to_vulns(session, nvd_map: dict[str, float]) -> None:
    """Update VulnerabilityORM.cvss_score using real NVD data, then refresh host aggregates.

    Looks up each CVE reference and overwrites the stored score.  This
    replaces any severity-approximated scores (9.5 / 7.5 / 5.5 / 2.0)
    set during import with the authoritative NVD CVSS base score.
    """
    from gravwell.models.orm import CVERefORM, HostORM
    from sqlalchemy import func, case

    affected_host_ids: set[int] = set()

    for cve_id_upper, nvd_score in nvd_map.items():
        refs = session.query(CVERefORM).filter(
            CVERefORM.cve_id == cve_id_upper
        ).all()
        vuln_ids = {r.vuln_id for r in refs}
        if not vuln_ids:
            continue
        # Collect affected host IDs before updating
        host_ids = {
            v.host_id for v in
            session.query(VulnerabilityORM.host_id).filter(
                VulnerabilityORM.id.in_(vuln_ids)
            ).all()
        }
        affected_host_ids.update(host_ids)
        session.query(VulnerabilityORM).filter(
            VulnerabilityORM.id.in_(vuln_ids)
        ).update({"cvss_score": nvd_score}, synchronize_session=False)

    # Recompute max_cvss for every host whose vulnerability scores changed
    session.flush()
    for host_id in affected_host_ids:
        row = session.query(
            func.max(VulnerabilityORM.cvss_score),
        ).filter(VulnerabilityORM.host_id == host_id).scalar()
        session.query(HostORM).filter(HostORM.id == host_id).update(
            {"max_cvss": float(row or 0.0)}, synchronize_session=False
        )


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
