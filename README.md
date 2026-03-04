# GravWell

Network mapping and attack path analysis tool for penetration testing.

GravWell ingests scan output from nmap, Nessus, Masscan, and OpenVAS, stores it in an encrypted SQLite database, and presents an interactive web UI for visualising the network graph, exploring vulnerabilities, and tracing attack paths.

---

## Features

- **Multi-format ingestion** — nmap XML, Nessus `.nessus`, Masscan JSON/XML, OpenVAS XML, enum4linux, Cisco (auto-detected)
- **Encrypted database** — AES-256 (SQLCipher) with per-user envelope encryption; stealing the `.db` file yields an unreadable blob
- **Interactive network graph** — Dash + Cytoscape, subnet grouping, drag-and-drop layout
- **Attack path analysis** — shortest path between any two hosts, KEV/EPSS enrichment for CVEs
- **Multi-user, multi-project** — named projects, Flask-Login authentication, admin/analyst roles
- **Active discovery** — ping sweep, ARP, TCP port scan, SNMP

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

The first user creation generates the database encryption key.

```bash
gravwell user add admin --admin
# Enter and confirm a password when prompted
```

### 2. Start the web UI

```bash
gravwell serve --port 8050
```

Open `http://localhost:8050` and sign in with the credentials you just created.

### 3. Ingest scan data

Drag and drop scan files onto the web UI, or use the CLI:

```bash
gravwell ingest scan.xml
gravwell ingest results.nessus target_masscan.json
```

---

## CLI Reference

```
gravwell user add <username> [--admin]   Add a user
gravwell user delete <username>          Remove a user
gravwell user list                       List all users
gravwell passwd <username>               Change a user's password

gravwell ingest <file> [<file>...]       Import scan files
gravwell list hosts [--min-cvss N]       List discovered hosts
gravwell list services [--ip IP]         List open services
gravwell list vulns [--ip IP]            List vulnerabilities
gravwell path <src-ip> <dst-ip>          Show attack path between two hosts

gravwell serve [--port PORT] [--host HOST]   Start the web server
gravwell reset                               Wipe all data in the current project
```

All data commands prompt for credentials to decrypt the database. Use `--db <path>` or the `GRAVWELL_DB` environment variable to target a specific project database.

---

## Projects

Projects are separate encrypted databases. Manage them from the sidebar in the web UI (New / Rename / Delete) or point the CLI at a specific file:

```bash
gravwell --db ~/.gravwell/projects/client-acme.db ingest scan.xml
```

---

## Adding More Users

Additional users can be added by an existing authenticated user:

```bash
gravwell user add analyst
# Prompts for your own credentials first, then the new user's password
```

Each user gets their own encrypted copy of the database key. All users share the same data within a project.

---

## Security Notes

- The database is encrypted with AES-256-GCM (SQLCipher 4). The encryption key is derived from your password using PBKDF2-HMAC-SHA256 (480,000 iterations).
- The master encryption key exists in memory only while the server is running. Restarting the server clears the key and forces re-authentication.
- User accounts are stored in `~/.gravwell/gravwell.keystore.json` (separate from the encrypted database to avoid a bootstrapping problem).
- The session secret is stored in `~/.gravwell/gravwell.key` (mode 0600).
