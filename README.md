# GravWell

Network mapping and attack path analysis tool for penetration testing.

GravWell ingests scan and assessment output from a wide range of tools, stores everything in an AES-256 encrypted SQLite database, and presents an interactive web UI for visualising the network graph, exploring vulnerabilities, and tracing attack paths between hosts.

---

## Features

- **Wide format support** — nmap, Nessus, Masscan, OpenVAS, Nuclei, enum4linux, CrowdStrike Falcon, Cisco IOS, Juniper JunOS, Fortinet FortiOS, Palo Alto PAN-OS (all auto-detected)
- **Collection agent** — deploy a lightweight Python script (or compiled `.exe`) to a client machine; it discovers neighbours via ARP + ping sweep, port-scans them, and uploads the results directly to GravWell or saves a JSON file for manual import
- **Encrypted database** — AES-256-GCM (SQLCipher 4) with per-user envelope encryption; stealing the `.db` file yields an unreadable blob without a valid GravWell password
- **Interactive network graph** — Dash + Cytoscape, automatic subnet grouping, drag-and-drop layout, multi-IP host support
- **Attack path analysis** — shortest path between hosts, Kerberoastable targets, lateral movement vectors, AD domain enumeration, admin interface exposure
- **CVE enrichment** — CISA KEV + FIRST.org EPSS exploit probability signals fetched on demand
- **RBAC multi-user** — granular per-user permissions (Edit, Import, Discover) and per-project access control; all managed from the web UI
- **Multi-project** — separate encrypted databases per engagement; create, rename, and delete from the sidebar
- **Active discovery** — ping sweep, ARP, TCP port scan, UDP probes (DNS/NTP/SNMP), SNMP enumeration with neighbor walk (ARP cache, CDP, LLDP)
- **Passive discovery** — sniff a VPN or network interface to find hosts that won't respond to active probes; tags DNS resolver sources automatically
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
| **CrowdStrike Falcon** | JSON / CSV export | Asset inventory, Spotlight vulnerability data (see below) |
| **IPAM** | CSV / Excel (`.xlsx`) | Subnet definitions and names — used as grouping ground truth (see below) |
| **GravWell Agent** | JSON (`.json`) | Output from `collect.py` — own machine, ARP neighbours, port scan (see below) |
| **Cisco IOS** | `show` command output | Interfaces, routing, ARP table, version |
| **Juniper JunOS** | `show` command output | Interfaces, routes, version |
| **Fortinet FortiOS** | `show` / `get` output | Interfaces, routing, system info |
| **Palo Alto PAN-OS** | XML operational output | Interfaces, routing, system info |

All formats are auto-detected. You can also force a specific parser with `--format`.

### GravWell Collection Agent

The collection agent (`gravwell/agent/collect.py`) is a zero-dependency Python script you send to a client machine. It gathers:

| Stage | What it does |
|-------|-------------|
| **System info** | Hostname, OS, all interface IPs and MACs |
| **ARP table** | Passive read of the OS neighbour cache — no packets sent |
| **Ping sweep** | Active ICMP to all hosts on local /24 networks |
| **Port scan** | TCP connect on 31 common ports; uses nmap XML output when nmap is on PATH, otherwise raw socket scan |

**Delivery modes:**

| Mode | How |
|------|-----|
| **File + manual import** | Agent writes `gravwell_collect_<host>_<ts>.json`; customer shares it back; drag-and-drop onto the web UI like any other scan file |
| **Direct upload** | Agent POSTs to GravWell with `--server` and `--key`; data appears immediately in the active project |

**Running on the target:**

```bash
# Passive only (ARP + own info, no scan)
python collect.py --no-sweep --no-scan

# Full collection, save locally
python collect.py

# Full collection + upload to GravWell
python collect.py --server https://gravwell.corp.local --key YOUR_TOKEN

# Skip port scan (faster for large subnets)
python collect.py --no-scan --server https://gravwell.corp.local --key YOUR_TOKEN
```

`collect.py` requires Python 3.8+ and nothing else. Copy the single file to the target — no `pip install` needed.

**Building a standalone `.exe` for Windows targets (no Python required):**

```bash
python gravwell/agent/build.py
# outputs dist/gravwell-collect.exe
```

**API token:** On the first server startup after upgrade, GravWell prints a 64-character hex token to the console. This is the value to pass as `--key`. The token is stored in the encrypted database; additional tokens can be viewed at `GET /api/agent/tokens`.

---

### IPAM subnet import

Importing subnet definitions from your IPAM gives GravWell authoritative grouping data instead of statistical guessing.  Each imported subnet becomes a named compound group in the graph; any host whose IP falls inside a known subnet is placed there directly using **longest-prefix-match** (most specific subnet wins).  Hosts whose IPs don't match any imported subnet still fall back to the automatic heuristic, so rogue or unregistered machines are never silently dropped.

**Supported formats:** CSV (`.csv`) and Excel (`.xlsx`).

**Minimum required columns** (exact names or common aliases are accepted):

| Column | Accepted names | Example value |
|--------|---------------|---------------|
| Subnet CIDR | `Subnet`, `Network`, `CIDR`, `Prefix` | `10.3.10.0/24` |
| Label / name | `Description`, `Name`, `Label`, `Comment` | `ISM-Services-Prod-DMZ` |

> **phpIPAM users:** the "Available subnets" table exports with exactly `Subnet` and `Description` columns — copy those columns directly into Excel and save as `.xlsx` or CSV.  Leading `>` hierarchy markers in descriptions are stripped automatically.

**Import is non-destructive:** labels you have manually edited in the UI are never overwritten by a re-import.  Only subnets with no existing label are updated.

### CrowdStrike Falcon export guide

GravWell accepts **Discover asset exports** (JSON or CSV) and **Spotlight vulnerability exports** (JSON or CSV). Auto-detection works on any combination of the fields below — you do not need to include all of them, but the more you include the richer the graph nodes will be.

**Recommended fields to select when exporting from the Falcon console:**

| Field name in Falcon UI | JSON key | What GravWell uses it for |
|-------------------------|----------|--------------------------|
| Hostname | `hostname` | Node label |
| Sensor IP address | `local_ip` | **Primary IP — use this as the IP field** |
| IP address history | `ip_address_history` | Additional IPs on the same node |
| OS version | `os_version` | OS family colouring (Windows / Linux / macOS) |
| System manufacturer | `system_manufacturer` | MAC vendor enrichment |
| MAC address(es) | `mac_addresses` | MAC-based host deduplication |
| Device type | `device_type` | `device-type:laptop` / `server` tag |
| Machine domain | `machine_domain` | `domain:CORP.LOCAL` tag — feeds AD domain grouping |

> **Tip:** Use **Sensor IP address** (not "IP address history") as the IP column. The sensor IP is the current active address; history IPs are merged in automatically as secondary addresses when both fields are exported.

For Spotlight vulnerability exports GravWell recognises three export variants automatically:

| Variant | Key fields | Notes |
|---------|-----------|-------|
| **Spotlight API** (`/spotlight/entities/vulnerabilities/v2`) | `cve.id`, `host_info.local_ip` | Full CVSS scores included |
| **Flat vuln export** | `host_id`, `local_ip`, `cve_id` | One row per host+CVE pair |
| **Spotlight console UI export** | `hostname`, `vulnerability_id`, `exprt_rating` | No IP — hosts matched to existing inventory by hostname |

The console UI export (downloaded directly from the Falcon Spotlight page) contains no IP address. GravWell imports those records keyed by hostname and merges them into matching hosts from your device inventory import. Include at minimum `hostname`, `vulnerability_id`, `severity`, `exprt_rating`, `products`, and `recommended_remediations` for the richest output.

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

### Optional: passive discovery

Passive network capture requires [scapy](https://scapy.net/). Install it via the `discovery` extras:

```bash
pip install "gravwell[discovery]"
# or
uv tool install --with scapy git+https://github.com/massymas12/gravwell.git
```

**Linux** — run GravWell as root, or grant the raw-socket capability once to avoid needing root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

**Windows** — install [Npcap](https://npcap.com/) (free, replaces the deprecated WinPcap). The standard installer option "Install Npcap in WinPcap API-compatible mode" is sufficient.

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
| **Discover** | Run active and passive network discovery (ping, ARP, TCP, UDP, SNMP, passive listen) |

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

## Active & Passive Discovery

GravWell can discover hosts directly from the **Discover** section of the sidebar, without needing an external scanner.

### Active discovery

| Method | What it does |
|--------|-------------|
| **Ping** | ICMP echo sweep across the target CIDR |
| **ARP** | Reads the local ARP cache (finds hosts on directly connected subnets) |
| **TCP** | Parallel TCP connect scan on common ports (22, 80, 443, 445, 3389, …) |
| **UDP** | Application-level probes to DNS (53), NTP (123), and SNMP (161) — works without raw sockets |
| **SNMP** | SNMP v1/v2c poll for sysDescr, sysName, ifTable; walks the ARP cache, CDP, and LLDP neighbor tables on responsive devices |

Enter a target CIDR or single IP, tick the methods you want, and click **Start Discovery**. Discovered hosts are ingested immediately and appear on the graph.

### Passive discovery

Passive listen captures live traffic on any network interface (VPN tunnel, LAN adapter, Wi-Fi) to surface hosts that firewalls silently drop active probes for — the host only needs to *send* a single packet to be discovered.

**Requirements:** `pip install "gravwell[discovery]"` (installs scapy). See [Requirements](#requirements) for platform notes.

1. Enter the interface name in the **Passive Listen** section of the sidebar (e.g. `tun0`, `eth0`, `Ethernet 2`).
2. Set a capture duration (5–300 s; default 30 s).
3. Optionally enter a target CIDR in the **Discover** field above to filter results to that network.
4. Click **Start Passive Listen**. GravWell blocks for the capture duration, then ingests all observed unique unicast IPs.

Hosts discovered passively are tagged `dns-resolver` if they were observed sending DNS queries to port 53 — a useful pivot for internal DNS enumeration.

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
