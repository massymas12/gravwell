"""Export callbacks — CSV, XLSX, and graph PNG downloads."""
from __future__ import annotations
import csv
import io
from datetime import datetime

import dash
from dash import Input, Output, State, no_update, dcc
from flask import current_app
from flask_login import current_user


# ── Query helpers ─────────────────────────────────────────────────────────────

def _fetch_data(db_path: str):
    """Return (host_rows, vuln_rows) as lists of dicts for export."""
    from gravwell.database import get_session
    from gravwell.models.orm import HostORM, VulnerabilityORM, CVERefORM, CVEEnrichmentORM

    host_rows = []
    vuln_rows = []

    with get_session(db_path) as session:
        hosts = session.query(HostORM).order_by(HostORM.ip).all()
        for h in hosts:
            open_ports = sorted(
                s.port for s in h.services if s.state == "open"
            )
            host_rows.append({
                "IP":           h.ip,
                "Hostnames":    "; ".join(h.hostnames),
                "OS Family":    h.os_family or "",
                "OS Name":      h.os_name or "",
                "Status":       h.status or "",
                "MAC":          h.mac or "",
                "MAC Vendor":   h.mac_vendor or "",
                "Open Ports":   "; ".join(str(p) for p in open_ports),
                "Max CVSS":     h.max_cvss or 0.0,
                "Critical":     h.vuln_count_critical or 0,
                "High":         h.vuln_count_high or 0,
                "Medium":       h.vuln_count_medium or 0,
                "Low":          h.vuln_count_low or 0,
                "Tags":         "; ".join(h.tags),
                "Notes":        (h.notes or "").replace("\n", " "),
            })

            for v in h.vulnerabilities:
                cve_ids = [r.cve_id for r in v.cve_refs]
                # KEV / EPSS: pick best signal across all CVEs on this vuln
                in_kev = False
                kev_date = ""
                epss_score = ""
                epss_pct = ""
                if cve_ids:
                    enrichments = (
                        session.query(CVEEnrichmentORM)
                        .filter(CVEEnrichmentORM.cve_id.in_(
                            [c.upper() for c in cve_ids]
                        ))
                        .all()
                    )
                    for e in enrichments:
                        if e.in_kev:
                            in_kev = True
                            kev_date = e.kev_date_added or ""
                        if e.epss_score is not None:
                            cur = float(e.epss_score)
                            if epss_score == "" or cur > float(epss_score):
                                epss_score = round(cur, 4)
                                epss_pct = round(float(e.epss_percentile or 0), 4)

                vuln_rows.append({
                    "IP":          h.ip,
                    "Hostname":    h.hostnames[0] if h.hostnames else "",
                    "OS Family":   h.os_family or "",
                    "Port":        v.port or "",
                    "Plugin ID":   v.plugin_id or "",
                    "CVE IDs":     "; ".join(cve_ids),
                    "Name":        v.name or "",
                    "Severity":    v.severity or "",
                    "CVSS":        v.cvss_score or "",
                    "In KEV":      "Yes" if in_kev else "",
                    "KEV Date":    kev_date,
                    "EPSS Score":  epss_score,
                    "EPSS %ile":   epss_pct,
                    "Description": (v.description or "")[:1000],
                    "Solution":    (v.solution or "")[:500],
                })

    return host_rows, vuln_rows


def _to_csv(host_rows: list[dict], vuln_rows: list[dict]) -> str:
    """Single CSV file with a Hosts section then a Vulnerabilities section."""
    buf = io.StringIO()
    w = csv.writer(buf)

    if host_rows:
        w.writerow(["# HOSTS"])
        w.writerow(list(host_rows[0].keys()))
        for r in host_rows:
            w.writerow(list(r.values()))
        w.writerow([])

    w.writerow(["# VULNERABILITIES"])
    if vuln_rows:
        w.writerow(list(vuln_rows[0].keys()))
        for r in vuln_rows:
            w.writerow(list(r.values()))

    return buf.getvalue()


def _to_xlsx(host_rows: list[dict], vuln_rows: list[dict]) -> bytes:
    """Two-sheet XLSX workbook: Hosts + Vulnerabilities."""
    import openpyxl
    from openpyxl.styles import PatternFill, Font, Alignment

    wb = openpyxl.Workbook()

    # ── Colour palette ────────────────────────────────────────────────────
    HDR_FILL = PatternFill("solid", fgColor="1A1A2E")
    HDR_FONT = Font(bold=True, color="5DADE2", size=10)
    SEV_COLOURS = {
        "critical": "E74C3C",
        "high":     "E67E22",
        "medium":   "F1C40F",
        "low":      "27AE60",
        "info":     "5DADE2",
    }

    def _write_sheet(ws, rows: list[dict], title: str):
        ws.title = title
        if not rows:
            ws.append(["No data"])
            return
        headers = list(rows[0].keys())
        ws.append(headers)
        for cell in ws[1]:
            cell.fill = HDR_FILL
            cell.font = HDR_FONT
            cell.alignment = Alignment(horizontal="center")

        for row in rows:
            ws.append(list(row.values()))

        # Auto-width (capped at 60)
        for col in ws.columns:
            max_len = max((len(str(c.value or "")) for c in col), default=8)
            ws.column_dimensions[col[0].column_letter].width = min(max_len + 2, 60)

    # ── Hosts sheet ───────────────────────────────────────────────────────
    ws_hosts = wb.active
    _write_sheet(ws_hosts, host_rows, "Hosts")

    # ── Vulns sheet ───────────────────────────────────────────────────────
    ws_vulns = wb.create_sheet("Vulnerabilities")
    _write_sheet(ws_vulns, vuln_rows, "Vulnerabilities")

    # Colour-code severity column
    try:
        sev_col = list(vuln_rows[0].keys()).index("Severity") + 1 if vuln_rows else None
        if sev_col:
            for row in ws_vulns.iter_rows(min_row=2, min_col=sev_col, max_col=sev_col):
                for cell in row:
                    sev = str(cell.value or "").lower()
                    colour = SEV_COLOURS.get(sev)
                    if colour:
                        cell.fill = PatternFill("solid", fgColor=colour)
                        cell.font = Font(bold=True, color="FFFFFF", size=9)
    except Exception:
        pass

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# ── Callbacks ─────────────────────────────────────────────────────────────────

def register(app: dash.Dash) -> None:

    @app.callback(
        Output("export-download", "data"),
        Output("hamburger-menu", "style", allow_duplicate=True),
        Output("hamburger-backdrop", "style", allow_duplicate=True),
        Input("export-csv-menu-item", "n_clicks"),
        Input("export-xlsx-menu-item", "n_clicks"),
        prevent_initial_call=True,
    )
    def export_data(csv_clicks, xlsx_clicks):
        from dash import ctx
        triggered = ctx.triggered_id
        if not triggered:
            return no_update, no_update, no_update

        closed = {"display": "none"}

        if not current_user.is_authenticated or not current_user.can("export"):
            return no_update, closed, closed

        db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
        host_rows, vuln_rows = _fetch_data(db_path)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if triggered == "export-csv-menu-item":
            content = _to_csv(host_rows, vuln_rows)
            return (
                dcc.send_string(content, f"gravwell_{stamp}.csv",
                                type="text/csv"),
                closed, closed,
            )
        else:
            content = _to_xlsx(host_rows, vuln_rows)
            return (
                dcc.send_bytes(content, f"gravwell_{stamp}.xlsx"),
                closed, closed,
            )

    # PNG export is handled entirely client-side; this callback closes the menu
    @app.callback(
        Output("export-png-dummy", "data"),
        Output("hamburger-menu", "style", allow_duplicate=True),
        Output("hamburger-backdrop", "style", allow_duplicate=True),
        Input("export-png-menu-item", "n_clicks"),
        prevent_initial_call=True,
    )
    def trigger_png_export(n_clicks):
        if not n_clicks:
            return no_update, no_update, no_update
        # The actual download is done by a clientside callback watching this store
        return (
            {"_t": n_clicks},
            {"display": "none"},
            {"display": "none"},
        )
