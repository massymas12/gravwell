# GravWell

Network mapping and attack path analysis tool for penetration testing.

GravWell ingests scan and assessment output from a wide range of tools, stores everything in an AES-256 encrypted SQLite database, and presents an interactive web UI for visualising the network graph, exploring vulnerabilities, and tracing attack paths between hosts.

---

## Features

- **Wide format support** — nmap, Nessus, Masscan, OpenVAS, Nuclei, enum4linux, CrowdStrike Falcon, Cisco IOS, Juniper JunOS, Fortinet FortiOS, Palo Alto PAN-OS (all auto-detected)
- **Encrypted database** — AES-256-GCM (SQLCipher 4) with per-user envelope encryption; stealing the `.db` file yields an unreadable blob without a valid GravWell password
- **Interactive network graph** — Dash + Cytoscape, automatic subnet grouping, drag-and-drop layout, multi-IP host support
- **Attack path analysis** — shortest path between hosts, Kerberoastable targets, lateral movement vectors, AD domain enumeration, admin interface exposure
- **CVE enrichment** — CISA KEV + FIRST.org EPSS exploit probability signals fetched on demand
- **RBAC multi-user** — granular per-user permissions (Edit, Import, Discover) and per-project access control; all managed from the web UI
- **Multi-project** — separate encrypted databases per engagement; create, rename, and delete from the sidebar
- **Active discovery** — ping sweep, ARP, TCP port scan, SNMP enumeration
- **CLI + Web UI** — full-featured CLI for scripted workflows, browser-based UI for analysis

---

## Supported Ingestion Formats

| Tool | Format | Notes |
|------|--------|-------|
| **nmap** | XML (`.xml`) | Hosts, ports, services, OS detection, scripts |
| **Nessus** | `.nessus` (XML) | Vulnerabilities, CVEs, CVSS scores, plugin output |
| **Masscan** | JSON / XML | Fast port scan results |
| **OpenVAS / Greenbone** | XML report | Vulnerabilities, NVT details, CVSS |
| **Nuclei** | JSON / JSONL | Template-based vulnerability findings |
| **enum4linux** | Text / JSON-NG | SMB shares, users, groups, password policy, domain info |
| **CrowdStrike Falcon** | JSON export | Asset inventory, Spotlight vulnerability data |
| **Cisco IOS** | `show` command output | Interfaces, routing, ARP table, version |
| **Juniper JunOS** | `show` command output | Interfaces, routes, version |
| **Fortinet FortiOS** | `show` / `get` output | Interfaces, routing, system info |
| **Palo Alto PAN-OS** | XML operational output | Interfaces, routing, system info |

All formats are auto-detected. You can also force a specific parser with `--format`.

---

## Requirements

- Python 3.11+
- On **Linux**: `libsqlcipher-dev` must be installed before `pip install`

```bash
# Debian / Ubuntu
sudo apt install libsqlcipher-dev

# Arch
sudo pacman -S sqlcipher
```

On **Windows x64** and **macOS** the `sqlcipher3` wheel bundles the native library — no extra steps needed.

---

## Installation

### With `uv` (recommended)

```bash
uv tool install git+https://github.com/massymas12/gravwell.git
```

### With `pip`

```bash
pip install git+https://github.com/massymas12/gravwell.git
```

### From source

```bash
git clone https://github.com/massymas12/gravwell.git
cd gravwell
pip install .
```

---

## Quick Start

### 1. Create the first user

The first user creation generates the database encryption key and encrypts the database.

```bash
gravwell user add admin --admin
# Enter and confirm a password when prompted
```

### 2. Start the web UI

```bash
gravwell serve --port 8050
```

Open `http://localhost:8050` and sign in.

### 3. Ingest scan data

Drag and drop scan files onto the web UI, or use the CLI:

```bash
gravwell ingest scan.xml
gravwell ingest results.nessus masscan_output.json
```

---

## CLI Reference

```
gravwell user add <username> [--admin]        Add a user
gravwell user delete <username>               Remove a user
gravwell user list                            List all users
gravwell passwd <username>                    Change a user's password

gravwell ingest <file> [<file>...]            Import scan files (auto-detected format)
gravwell ingest --format nmap <file>          Import with a forced parser

gravwell list hosts [--min-cvss N]            List discovered hosts
gravwell list hosts [--os Windows]            Filter by OS family
gravwell list hosts [--subnet 10.0.0.0/24]   Filter by subnet
gravwell list services [--ip IP] [--port N]   List open services
gravwell list vulns [--ip IP]                 List vulnerabilities

gravwell path <src-ip> <dst-ip>               Show attack path between two hosts

gravwell serve [--port PORT] [--host HOST]    Start the web server
gravwell reset                                Wipe all data in the current project
```

All data commands prompt for credentials to decrypt the database. Use `--db <path>` or set `GRAVWELL_DB` to target a specific project database:

```bash
gravwell --db ~/.gravwell/projects/client-acme.db ingest scan.xml
GRAVWELL_DB=~/.gravwell/projects/client-acme.db gravwell list hosts
```

---

## Projects

Projects are separate encrypted databases — one per engagement is recommended. Manage them from the sidebar in the web UI (New / Rename / Delete) or target them directly via the CLI.

Default database: `~/.gravwell/gravwell.db`
Project databases: `~/.gravwell/projects/<name>.db`

---

## User Management

### Adding users

Admin users can add new accounts from the web UI via the **☰ menu → Add User**, or from the CLI:

```bash
gravwell user add analyst
# Prompts for your credentials first, then the new user's password
```

Each user holds their own encrypted copy of the database key. All users within a project share the same scan data.

### Role-based access control (RBAC)

Every user has a **Role** and a set of **Permissions**, configured at creation time and editable via **☰ → Manage Users**.

| Role | Description |
|------|-------------|
| **Admin** | Full access — can manage users, create/delete projects, and perform all operations |
| **User** | Access limited to assigned permissions and projects |

| Permission | What it allows |
|------------|----------------|
| **Edit** | Modify host properties, tags, notes, and node layout |
| **Import** | Upload and ingest scan files |
| **Discover** | Run active network discovery (ping, ARP, TCP, SNMP) |

**Project access** can be set to *All projects* (including future ones) or restricted to a named list of specific projects. Non-admin users only see projects they are allowed to access in the sidebar dropdown.

### Manage Users screen

**☰ → Manage Users** (admin only) shows a live RBAC table with:

- **Role** badge (Admin / User)
- **Permissions** — all four permission types shown as green (granted) or greyed-out (denied) badges
- **Projects** — "All" badge or individual project names
- **Last Login** timestamp
- Per-row **delete** button (disabled for the currently signed-in account)

---

## Network Graph

The graph view visualises every discovered host as a node, grouped into coloured subnet boxes. Edges represent relationships between hosts.

### Edge types

| Edge | Style | Description |
|------|-------|-------------|
| **Intra-subnet** | Thin grey line, no arrows | Connects each host to its subnet's hub (gateway, router, or virtual switch) |
| **Inter-subnet** | Bold orange line, bidirectional arrows | Connects the hubs of adjacent subnets within the same /16 block |
| **Bridge** | Purple dashed, bidirectional arrows | Connects a multi-homed network device (router/firewall) to the hub of each subnet it spans |
| **Custom** | Green dashed, bidirectional arrows | Manually added by the user via the **+ Edge** button |

### How arrows are placed

Arrows are **not** derived from observed traffic — they are inferred from scan data using three rules:

1. **Subnet chaining** — subnets in the same /16 block are sorted by IP address and chained hub-to-hub: `10.1.1.0/24` ↔ `10.1.2.0/24` ↔ `10.1.3.0/24`. This produces O(n) inter-subnet edges rather than a full mesh. Pairs where both hubs are virtual switches (no real routing evidence) are skipped.

2. **Bridge detection** — hosts classified as routers or firewalls (via OS family, MAC vendor such as Cisco/Juniper/Fortinet, or router-specific ports like 161/SNMP, 179/BGP, 520/RIP) that have IPs in multiple subnets float outside the subnet boxes and get a bridge edge to each subnet's hub. The edge label shows the specific IP on that interface.

3. **Manual edges** — any edge added via **+ Edge** is stored in the database and rendered as a green dashed line between the two specified hosts.

### Hub selection

Each subnet's centre node (hub) is chosen in priority order:

1. A host classified as a **router** (network OS, network MAC vendor, or router ports)
2. A host classified as a **gateway** (last octet `.1` or `.254`)
3. A **virtual switch** node (synthesised automatically when no real gateway is found)

### Domain grouping

When hosts belong to an Active Directory domain, GravWell draws an outer **domain box** that wraps the relevant subnet boxes, giving you a three-level hierarchy: **domain → subnet → host**.

A subnet is assigned to a domain when at least 50% of its hosts carry a matching `domain:` tag. Subnets with no clear majority remain ungrouped.

**How domain tags are populated:**

| Source | How |
|--------|-----|
| **enum4linux** | Domain name read directly from LDAP (`ldap.domain`), SMB (`domain_name`), or NetBIOS workgroup — most authoritative |
| **FQDN inference** | Any hostname with 3+ labels (e.g. `pc01.corp.local`) automatically produces a `domain:CORP.LOCAL` tag at ingest time |
| **Manual** | Click any host node → **Edit** → fill in the **Domain** field |

Tags from all three sources are merged in the database, so re-ingesting a file or editing a node adds to existing domain information rather than replacing it.

### Multi-node selection

Hold **Shift** and drag on the empty canvas to draw a box selection over multiple nodes. Then drag any selected node to move the entire group together.

---

## Attack Path Analysis

The **Attack Paths** tab provides several automated analyses:

| Analysis | Description |
|----------|-------------|
| **Shortest Path** | Weighted shortest path between any two hosts using vulnerability severity as edge cost |
| **Path to HVT** | All attack paths to a designated high-value target |
| **Kerberoastable** | Windows hosts with registered SPNs likely vulnerable to Kerberoasting; uses multi-signal confidence scoring (OS, domain tag, open ports) |
| **SMB Lateral** | Hosts at risk of SMB credential relay or lateral movement |
| **Admin Interfaces** | Hosts with management interfaces exposed (RDP, SSH, WinRM, IPMI, etc.) |
| **AD Enum** | Domain enumeration findings from enum4linux: group names, password policy weaknesses, SMB signing status |

Clicking any IP or hostname in analysis results pans the graph to that node. Clicking a row in the Services or Vulnerabilities sub-tabs does the same.

---

## Security Notes

- The database is encrypted with AES-256-GCM (SQLCipher 4). The master encryption key (MEK) is derived from your password using PBKDF2-HMAC-SHA256 (480,000 iterations).
- The MEK lives in memory only while the server is running. Restarting the server clears the key and forces re-authentication — the database is locked at rest.
- Each user stores an independent AES-256-GCM encrypted copy of the MEK. Changing a user's password re-encrypts only their MEK slot; all other users and the database content are unaffected.
- User accounts (password hashes + encrypted MEK slots) are stored in `~/.gravwell/gravwell.keystore.json` — separate from the encrypted database to avoid a bootstrapping problem. This file contains no scan data.
- The Flask session secret is stored in `~/.gravwell/gravwell.key` (mode 0600).
- Never commit `.db`, `.keystore.json`, or `.key` files.
