from __future__ import annotations
import sys
from getpass import getpass
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table
from rich.progress import track

from gravwell.config import get_db_path
from gravwell.database import get_session
from gravwell.parsers.registry import ParserRegistry
from gravwell.models.ingestion import ingest_parse_result
from gravwell.models.orm import HostORM, ServiceORM, VulnerabilityORM, ScanFileORM
from gravwell.graph.builder import build_graph
from gravwell.graph import analysis

console = Console()

_VALID_FORMATS = [
    "nmap", "nessus", "masscan", "openvas", "nuclei",
    "enum4linux", "crowdstrike", "cisco", "juniper", "fortinet", "paloalto",
]

_BANNER = r"""  ___  _ __    __ _ __   __  __      __    ___  | || |
 / __|  | '__|/ _` \ \ \ / / \ \    / /  / _ \ | || |
| (_ \  | |  | (_| |\ V /   \ \/\/ /  |  __/ | || |
 \___/  |_|   \__,_| \_/     \_/\_/    \___|  |_||_|
"""

_TAGLINE = "network mapping + attack path analysis"


def _print_banner() -> None:
    console.print(_BANNER, style="bold magenta", markup=False, highlight=False)
    console.print(f"  {_TAGLINE}\n", style="dim")


@click.group(invoke_without_command=True)
@click.option("--db", default=None, envvar="GRAVWELL_DB",
              help="Path to SQLite database (default: ~/.gravwell/gravwell.db)")
@click.pass_context
def cli(ctx, db):
    """GravWell — Network mapping and attack path analysis tool."""
    ctx.ensure_object(dict)
    ctx.obj["db"] = get_db_path(db)
    if ctx.invoked_subcommand is None:
        _print_banner()
        console.print(ctx.get_help())
    # DB is opened lazily after the MEK is unlocked — do not call init_db here


def _unlock_db(db_path: str) -> None:
    """Prompt for credentials, decrypt the MEK, and open the encrypted DB."""
    import gravwell.keystore as ks_mod
    from gravwell.database import set_cli_mek, init_db as _init_db
    ks = ks_mod.load(db_path)
    if not ks["users"]:
        raise click.ClickException(
            "No users configured. Run: gravwell user add admin --admin"
        )
    username = click.prompt("Username")
    password = getpass("Password: ")
    mek = ks_mod.authenticate(db_path, username, password)
    if mek is None:
        raise click.ClickException("Invalid credentials.")
    set_cli_mek(mek)
    _init_db(db_path)


@cli.command()
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--format", "fmt", default=None,
              type=click.Choice(_VALID_FORMATS, case_sensitive=False),
              help="Force parser format instead of auto-detecting")
@click.pass_context
def ingest(ctx, files, fmt):
    """Ingest one or more scan files (nmap XML, .nessus, masscan, openvas)."""
    db_path = ctx.obj["db"]
    _unlock_db(db_path)
    total_hosts = 0
    total_vulns = 0

    for filepath_str in track(files, description="Ingesting..."):
        filepath = Path(filepath_str)
        try:
            result = ParserRegistry.parse(filepath, format=fmt)
            if result.errors:
                for e in result.errors:
                    console.print(f"[red]  Error in {filepath.name}: {e}[/red]")
            if result.warnings:
                for w in result.warnings:
                    console.print(f"[yellow]  Warning: {w}[/yellow]")
            with get_session(db_path) as session:
                h, v, already = ingest_parse_result(session, result)
            if already:
                console.print(f"[dim]SKIP[/dim] {filepath.name} (already ingested)")
                continue
            total_hosts += h
            total_vulns += v
            fmt_used = result.parser_name
            console.print(
                f"[green]OK[/green] {filepath.name} "
                f"([cyan]{fmt_used}[/cyan]) — "
                f"{h} hosts, {v} vulns"
            )
        except ValueError as e:
            console.print(f"[red]SKIP[/red] {filepath.name}: {e}")
        except Exception as e:
            console.print(f"[red]FAIL[/red] {filepath.name}: {e}")

    console.print(
        f"\n[bold]Total:[/bold] {total_hosts} hosts, {total_vulns} vulnerabilities ingested"
    )


@cli.group()
def list():
    """List hosts, services, or vulnerabilities."""


@list.command("hosts")
@click.option("--min-cvss", default=0.0, type=float,
              help="Minimum CVSS score filter")
@click.option("--os", "os_filter", default=None,
              help="Filter by OS family (Windows, Linux, Network, Unknown)")
@click.option("--subnet", default=None, help="Filter by CIDR (e.g. 192.168.1.0/24)")
@click.pass_context
def list_hosts(ctx, min_cvss, os_filter, subnet):
    """List all discovered hosts."""
    import ipaddress as _ip

    db_path = ctx.obj["db"]
    _unlock_db(db_path)
    with get_session(db_path) as session:
        query = session.query(HostORM)
        if min_cvss:
            query = query.filter(HostORM.max_cvss >= min_cvss)
        if os_filter:
            query = query.filter(HostORM.os_family.ilike(f"%{os_filter}%"))
        hosts = query.order_by(HostORM.max_cvss.desc()).all()

        rows = []
        for h in hosts:
            if subnet:
                try:
                    net = _ip.ip_network(subnet, strict=False)
                    if _ip.ip_address(h.ip) not in net:
                        continue
                except ValueError:
                    pass
            open_count = session.query(ServiceORM).filter_by(
                host_id=h.id, state="open"
            ).count()
            rows.append((
                h.ip,
                (h.hostnames or [""])[0] if h.hostnames else "",
                h.os_family or "",
                str(open_count),
                f"{h.max_cvss:.1f}",
                str(h.vuln_count_critical),
                str(h.vuln_count_high),
                str(h.vuln_count_medium),
            ))

    table = Table(title=f"Hosts ({len(rows)})", show_lines=False)
    table.add_column("IP", style="cyan")
    table.add_column("Hostname")
    table.add_column("OS")
    table.add_column("Open Ports", justify="right")
    table.add_column("Max CVSS", justify="right")
    table.add_column("Crit", justify="right", style="red")
    table.add_column("High", justify="right", style="yellow")
    table.add_column("Med", justify="right")
    for row in rows:
        table.add_row(*row)
    console.print(table)


@list.command("services")
@click.option("--ip", default=None, help="Filter by IP address")
@click.option("--port", default=None, type=int, help="Filter by port")
@click.pass_context
def list_services(ctx, ip, port):
    """List open services."""
    db_path = ctx.obj["db"]
    _unlock_db(db_path)
    with get_session(db_path) as session:
        query = session.query(ServiceORM).filter_by(state="open")
        if ip:
            host = session.query(HostORM).filter_by(ip=ip).first()
            if host:
                query = query.filter_by(host_id=host.id)
            else:
                console.print(f"[red]Host {ip} not found[/red]")
                return
        if port:
            query = query.filter_by(port=port)
        svcs = query.order_by(ServiceORM.port).all()
        rows = []
        for s in svcs:
            host = session.query(HostORM).filter_by(id=s.host_id).first()
            rows.append((
                host.ip if host else "?",
                str(s.port),
                s.protocol,
                s.service_name or "",
                s.product or "",
                s.version or "",
            ))

    table = Table(title=f"Services ({len(rows)})")
    table.add_column("IP", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("Proto")
    table.add_column("Service")
    table.add_column("Product")
    table.add_column("Version")
    for row in rows:
        table.add_row(*row)
    console.print(table)


@list.command("vulns")
@click.option("--min-cvss", default=0.0, type=float)
@click.option("--severity", default=None,
              type=click.Choice(["critical", "high", "medium", "low", "info"],
                                case_sensitive=False))
@click.option("--ip", default=None)
@click.pass_context
def list_vulns(ctx, min_cvss, severity, ip):
    """List vulnerabilities."""
    db_path = ctx.obj["db"]
    _unlock_db(db_path)
    with get_session(db_path) as session:
        query = session.query(VulnerabilityORM)
        if min_cvss:
            query = query.filter(VulnerabilityORM.cvss_score >= min_cvss)
        if severity:
            query = query.filter_by(severity=severity.lower())
        if ip:
            host = session.query(HostORM).filter_by(ip=ip).first()
            if host:
                query = query.filter_by(host_id=host.id)
        vulns = query.order_by(VulnerabilityORM.cvss_score.desc()).all()
        rows = []
        for v in vulns:
            host = session.query(HostORM).filter_by(id=v.host_id).first()
            cves = ", ".join(r.cve_id for r in v.cve_refs)[:40]
            rows.append((
                host.ip if host else "?",
                v.severity.upper(),
                f"{v.cvss_score:.1f}",
                v.name[:60],
                str(v.port or ""),
                cves,
            ))

    sev_colors = {
        "CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "white",
        "LOW": "green", "INFO": "dim"
    }
    table = Table(title=f"Vulnerabilities ({len(rows)})")
    table.add_column("IP", style="cyan")
    table.add_column("Severity")
    table.add_column("CVSS", justify="right")
    table.add_column("Name")
    table.add_column("Port", justify="right")
    table.add_column("CVEs")
    for row in rows:
        sev_style = sev_colors.get(row[1], "")
        table.add_row(row[0], f"[{sev_style}]{row[1]}[/{sev_style}]",
                      row[2], row[3], row[4], row[5])
    console.print(table)


@cli.command()
@click.argument("src_ip")
@click.argument("dst_ip")
@click.option("--cutoff", default=8, type=int,
              help="Maximum hop count (default: 8)")
@click.pass_context
def path(ctx, src_ip, dst_ip, cutoff):
    """Find attack paths between two hosts."""
    db_path = ctx.obj["db"]
    _unlock_db(db_path)
    with get_session(db_path) as session:
        G = build_graph(session)

    paths = analysis.find_attack_paths(G, src_ip, dst_ip, cutoff=cutoff)
    if not paths:
        console.print(f"[red]No paths found from {src_ip} to {dst_ip}[/red]")
        return

    console.print(f"\n[bold]Attack paths: {src_ip} -> {dst_ip}[/bold] ({len(paths)} found)\n")
    for i, ap in enumerate(paths, 1):
        console.print(f"[bold]Path {i}[/bold] | {ap.hop_count} hops | "
                      f"risk score: [yellow]{ap.total_risk_score:.1f}[/yellow]")
        for step in ap.steps:
            hostname = f" ({step.hostnames[0]})" if step.hostnames else ""
            cvss_color = "red" if step.max_cvss >= 9 else (
                "yellow" if step.max_cvss >= 7 else "white"
            )
            arrow = f" --[{step.edge_to_next}]-->" if step.edge_to_next else ""
            console.print(
                f"  [cyan]{step.ip}[/cyan]{hostname} "
                f"[{cvss_color}]CVSS:{step.max_cvss:.1f}[/{cvss_color}] "
                f"OS:{step.os_family}{arrow}"
            )
        console.print()


@cli.command()
@click.argument("target")
@click.option("--methods", default="ping,arp,tcp",
              help="Comma-separated methods: ping, arp, tcp, snmp  [default: ping,arp,tcp]")
@click.option("--community", default="public", show_default=True,
              help="SNMP community string (v1/v2c)")
@click.option("--snmp-port", default=161, type=int, show_default=True)
@click.option("--tcp-ports", default=None,
              help="Comma-separated port list for TCP scan (default: common ports)")
@click.option("--workers", default=64, type=int, show_default=True,
              help="Parallel worker threads")
@click.option("--no-follow-neighbors", is_flag=True, default=False,
              help="Skip ARP/CDP/LLDP neighbor walk on SNMP devices")
@click.pass_context
def discover(ctx, target, methods, community, snmp_port, tcp_ports,
             workers, no_follow_neighbors):
    """Discover hosts via ping sweep, ARP, TCP connect, and/or SNMP."""
    from gravwell.discovery.runner import discover as _discover, DiscoveryConfig

    method_list = [m.strip().lower() for m in methods.split(",") if m.strip()]
    port_list = None
    if tcp_ports:
        try:
            port_list = [int(p.strip()) for p in tcp_ports.split(",") if p.strip()]
        except ValueError as e:
            console.print(f"[red]Invalid --tcp-ports: {e}[/red]")
            return

    cfg = DiscoveryConfig(
        target=target,
        methods=method_list,
        snmp_community=community,
        snmp_port=snmp_port,
        tcp_ports=port_list,
        max_workers=workers,
        follow_snmp_neighbors=not no_follow_neighbors,
    )

    console.print(f"[bold]Discovering:[/bold] {target} "
                  f"(methods: {', '.join(method_list)})")
    try:
        result = _discover(cfg)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    if result.errors:
        for e in result.errors:
            console.print(f"[red]Error: {e}[/red]")
    if result.warnings:
        for w in result.warnings:
            console.print(f"[yellow]Warning: {w}[/yellow]")

    counts_str = "  ".join(f"{k}={v}" for k, v in result.method_counts.items())
    console.print(f"Found [green]{len(result.hosts)}[/green] hosts  ({counts_str})")

    if not result.hosts:
        return

    db_path = ctx.obj["db"]
    _unlock_db(db_path)
    pr = result.to_parse_result()
    with get_session(db_path) as session:
        h, v, already = ingest_parse_result(session, pr)

    if already:
        console.print("[dim]Already ingested (identical result)[/dim]")
    else:
        console.print(f"Ingested [cyan]{h}[/cyan] hosts, "
                      f"[cyan]{v}[/cyan] vulns into [dim]{db_path}[/dim]")

    table = Table(title=f"Discovered Hosts ({len(result.hosts)})")
    table.add_column("IP", style="cyan")
    table.add_column("Hostname")
    table.add_column("OS")
    table.add_column("Open Ports")
    table.add_column("Sources")
    for host in sorted(result.hosts, key=lambda h: h.ip):
        hn   = (host.hostnames[0] if host.hostnames else "")
        ports = ", ".join(str(s.port) for s in host.services
                          if s.state == "open")[:40]
        table.add_row(
            host.ip, hn,
            host.os_name or host.os_family or "",
            ports,
            ", ".join(host.source_files),
        )
    console.print(table)


@cli.command()
@click.option("--port", default=8888, type=int, show_default=True)
@click.option("--host", "host_addr", default="127.0.0.1", show_default=True)
@click.option("--debug", is_flag=True, default=False)
@click.pass_context
def serve(ctx, port, host_addr, debug):
    """Start the web UI."""
    import gravwell.keystore as ks_mod
    db_path = ctx.obj["db"]
    ks = ks_mod.load(db_path)
    if not ks["users"]:
        console.print("[red]No users configured. Create one first:[/red]")
        console.print("  gravwell user add admin --admin")
        raise SystemExit(1)
    _print_banner()
    console.print(f"[bold magenta]Starting[/bold magenta] on "
                  f"[cyan]http://{host_addr}:{port}[/cyan]")
    console.print(f"Database: [dim]{db_path}[/dim]")
    from gravwell.ui.app import create_app
    app = create_app(db_path)
    if debug:
        app.run(host=host_addr, port=port, debug=True)
    else:
        from waitress import serve as _serve
        _serve(app.server, host=host_addr, port=port, threads=8)


@cli.command("merge-macs")
@click.option("--dry-run", is_flag=True, default=False,
              help="Show what would be merged without making changes")
@click.pass_context
def merge_macs(ctx, dry_run):
    """Merge hosts that share a MAC address into one node.

    Useful after re-importing scan files or when the same device appears
    with multiple IPs across different scan sources (routers, firewalls,
    multi-NIC servers).  Services and vulnerabilities are re-assigned to
    the primary host (lowest ID); secondary hosts are removed.
    """
    from collections import defaultdict
    from sqlalchemy import text
    from gravwell.models.ingestion import _update_host_aggregates

    _INVALID_MACS = {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}
    db_path = ctx.obj["db"]
    _unlock_db(db_path)
    total_merged = 0

    with get_session(db_path) as session:
        all_hosts = (
            session.query(HostORM)
            .filter(HostORM.mac.isnot(None))
            .order_by(HostORM.id)
            .all()
        )

        mac_groups: dict[str, list] = defaultdict(list)
        for h in all_hosts:
            norm = (h.mac or "").upper().replace("-", ":")
            if norm and norm not in _INVALID_MACS:
                mac_groups[norm].append(h)

        dup_groups = {m: g for m, g in mac_groups.items() if len(g) > 1}
        if not dup_groups:
            console.print("[green]No duplicate MACs found.[/green]")
            return

        for mac, group in sorted(dup_groups.items()):
            primary = group[0]
            secondaries = group[1:]
            all_ips = "  ".join(h.ip for h in group)
            console.print(
                f"[cyan]{mac}[/cyan]  ({len(group)} nodes): {all_ips}\n"
                f"  primary=[green]{primary.ip}[/green]  "
                f"merging: {', '.join(h.ip for h in secondaries)}"
            )
            if dry_run:
                continue

            for sec in secondaries:
                # ── Merge metadata into primary ──────────────────────────
                all_known = set([primary.ip] + primary.additional_ips)
                to_add = [ip for ip in [sec.ip] + sec.additional_ips
                          if ip not in all_known]
                if to_add:
                    primary.additional_ips = primary.additional_ips + to_add

                primary.hostnames = list(dict.fromkeys(
                    primary.hostnames + sec.hostnames))
                primary.source_files = list(dict.fromkeys(
                    primary.source_files + sec.source_files))
                primary.tags = list(dict.fromkeys(primary.tags + sec.tags))
                if sec.notes and not primary.notes:
                    primary.notes = sec.notes
                if sec.os_name and not primary.os_name:
                    primary.os_name = sec.os_name
                    primary.os_family = sec.os_family

                # Flush ORM changes before raw SQL operations
                session.flush()

                # ── Reassign services ─────────────────────────────────────
                sec_svcs = session.execute(
                    text("SELECT id, port, protocol, product, version, "
                         "banner, service_name FROM services WHERE host_id = :hid"),
                    {"hid": sec.id},
                ).fetchall()

                for svc in sec_svcs:
                    conflict = session.execute(
                        text("SELECT id, product, version, banner, service_name "
                             "FROM services "
                             "WHERE host_id = :pid AND port = :port AND protocol = :proto"),
                        {"pid": primary.id, "port": svc.port, "proto": svc.protocol},
                    ).fetchone()

                    if not conflict:
                        session.execute(
                            text("UPDATE services SET host_id = :pid WHERE id = :sid"),
                            {"pid": primary.id, "sid": svc.id},
                        )
                    else:
                        # Merge richer metadata into the surviving service
                        updates: dict = {}
                        if svc.product and not conflict.product:
                            updates["product"] = svc.product
                        if svc.version and not conflict.version:
                            updates["version"] = svc.version
                        if svc.banner and not conflict.banner:
                            updates["banner"] = svc.banner
                        if svc.service_name and not conflict.service_name:
                            updates["service_name"] = svc.service_name
                        if updates:
                            set_clause = ", ".join(f"{k} = :{k}" for k in updates)
                            session.execute(
                                text(f"UPDATE services SET {set_clause} WHERE id = :id"),
                                {**updates, "id": conflict.id},
                            )
                        # Nullify FK before deleting the duplicate service
                        session.execute(
                            text("UPDATE vulnerabilities SET service_id = NULL "
                                 "WHERE service_id = :sid"),
                            {"sid": svc.id},
                        )
                        session.execute(
                            text("DELETE FROM services WHERE id = :sid"),
                            {"sid": svc.id},
                        )

                session.flush()

                # ── Reassign vulnerabilities ──────────────────────────────
                sec_vulns = session.execute(
                    text("SELECT id, plugin_id, port, name, cvss_score "
                         "FROM vulnerabilities WHERE host_id = :hid"),
                    {"hid": sec.id},
                ).fetchall()

                for vuln in sec_vulns:
                    plugin_key = vuln.plugin_id or f"name:{vuln.name[:64]}"
                    # NULL-safe port comparison
                    if vuln.port is None:
                        conflict = session.execute(
                            text("SELECT id, cvss_score FROM vulnerabilities "
                                 "WHERE host_id = :pid AND plugin_id = :pk "
                                 "AND port IS NULL"),
                            {"pid": primary.id, "pk": plugin_key},
                        ).fetchone()
                    else:
                        conflict = session.execute(
                            text("SELECT id, cvss_score FROM vulnerabilities "
                                 "WHERE host_id = :pid AND plugin_id = :pk "
                                 "AND port = :port"),
                            {"pid": primary.id, "pk": plugin_key, "port": vuln.port},
                        ).fetchone()

                    if not conflict:
                        session.execute(
                            text("UPDATE vulnerabilities SET host_id = :pid "
                                 "WHERE id = :vid"),
                            {"pid": primary.id, "vid": vuln.id},
                        )
                    else:
                        if (vuln.cvss_score or 0) > (conflict.cvss_score or 0):
                            session.execute(
                                text("UPDATE vulnerabilities SET cvss_score = :cvss "
                                     "WHERE id = :id"),
                                {"cvss": vuln.cvss_score, "id": conflict.id},
                            )
                        session.execute(
                            text("DELETE FROM cve_refs WHERE vuln_id = :vid"),
                            {"vid": vuln.id},
                        )
                        session.execute(
                            text("DELETE FROM vulnerabilities WHERE id = :vid"),
                            {"vid": vuln.id},
                        )

                session.flush()

                # ── Delete secondary host ─────────────────────────────────
                session.execute(
                    text("DELETE FROM hosts WHERE id = :hid"), {"hid": sec.id}
                )
                try:
                    session.expunge(sec)
                except Exception:
                    pass
                session.flush()
                total_merged += 1

            # Recalculate aggregate CVSS/counts for primary
            primary = session.query(HostORM).filter_by(id=primary.id).first()
            if primary:
                _update_host_aggregates(session, primary)

    action = "Would merge" if dry_run else "Merged"
    console.print(f"\n[bold]{action}[/bold] [green]{total_merged}[/green] duplicate host(s)")


# ── User management ──────────────────────────────────────────────────────────

@cli.group()
def user():
    """Manage GravWell user accounts."""


@user.command("add")
@click.argument("username")
@click.option("--admin", is_flag=True, default=False, help="Grant admin privileges.")
@click.pass_context
def user_add(ctx, username, admin):
    """Create a new user account."""
    import gravwell.keystore as ks_mod
    from gravwell.database import (set_cli_mek, init_db as _init_db,
                                   is_encrypted, migrate_to_encrypted, _get_mek)
    db_path = ctx.obj["db"]
    ks = ks_mod.load(db_path)

    if not ks["users"]:
        # First user — generate MEK and initialise the encrypted DB
        mek = ks_mod.generate_mek()
        if Path(db_path).exists() and not is_encrypted(db_path):
            console.print("[yellow]Encrypting existing database in-place...[/yellow]")
            migrate_to_encrypted(db_path, mek)
            console.print("[green]Encryption complete.[/green]")
        set_cli_mek(mek)
        _init_db(db_path)
    else:
        # Subsequent users — need MEK from an existing admin account
        console.print("Authorize with an existing account to add a new user.")
        _unlock_db(db_path)
        mek = _get_mek()

    pw  = getpass(f"Password for {username}: ")
    pw2 = getpass("Confirm password: ")
    if pw != pw2:
        console.print("[red]Passwords do not match.[/red]")
        raise SystemExit(1)
    if len(pw) < 8:
        console.print("[red]Password must be at least 8 characters.[/red]")
        raise SystemExit(1)
    try:
        ks_mod.add_user(db_path, username, pw, mek, is_admin=admin)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    console.print(f"[green]User '{username}' created.[/green]")


@user.command("delete")
@click.argument("username")
@click.option("--yes", is_flag=True, default=False, help="Skip confirmation.")
@click.pass_context
def user_delete(ctx, username, yes):
    """Delete a user account."""
    import gravwell.keystore as ks_mod
    db_path = ctx.obj["db"]
    if not yes:
        click.confirm(f"Delete user '{username}'?", abort=True)
    try:
        ks_mod.delete_user(db_path, username)
    except KeyError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    console.print(f"[yellow]User '{username}' deleted.[/yellow]")


@user.command("list")
@click.pass_context
def user_list(ctx):
    """List all user accounts."""
    import gravwell.keystore as ks_mod
    db_path = ctx.obj["db"]
    ks = ks_mod.load(db_path)
    users = ks["users"]
    if not users:
        console.print("[dim]No users configured.[/dim]")
        return
    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("Username")
    t.add_column("Admin")
    t.add_column("Created")
    t.add_column("Last Login")
    for u in users:
        t.add_row(
            u["username"],
            "yes" if u.get("is_admin") else "",
            str(u.get("created_at", ""))[:16],
            str(u.get("last_login") or "never")[:16],
        )
    console.print(t)


@cli.command("passwd")
@click.argument("username")
@click.pass_context
def passwd(ctx, username):
    """Change a user's password."""
    import gravwell.keystore as ks_mod
    from gravwell.database import _get_mek
    db_path = ctx.obj["db"]
    _unlock_db(db_path)   # need the MEK to re-encrypt the slot
    mek = _get_mek()
    pw  = getpass(f"New password for {username}: ")
    pw2 = getpass("Confirm: ")
    if pw != pw2:
        console.print("[red]Passwords do not match.[/red]")
        raise SystemExit(1)
    if len(pw) < 8:
        console.print("[red]Password must be at least 8 characters.[/red]")
        raise SystemExit(1)
    try:
        ks_mod.change_password(db_path, username, pw, mek)
    except KeyError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    console.print(f"[green]Password updated for '{username}'.[/green]")


@cli.command()
@click.option("--yes", is_flag=True, default=False, help="Skip confirmation")
@click.pass_context
def reset(ctx, yes):
    """Clear all data from the database."""
    db_path = ctx.obj["db"]
    if not yes:
        click.confirm(
            f"This will delete all data in {db_path}. Continue?", abort=True
        )
    _unlock_db(db_path)
    from gravwell.database import _get_engine
    from gravwell.models.orm import Base
    engine = _get_engine(db_path)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    console.print("[green]Database reset.[/green]")
