from dash import html, dcc


def create_sidebar() -> html.Div:
    return html.Div(
        id="sidebar",
        children=[
            # ── Projects ──────────────────────────────────────────────────
            html.H3("Projects", className="sidebar-section-title"),
            html.Div([
                dcc.Dropdown(
                    id="project-dropdown",
                    options=[],
                    value=None,
                    clearable=False,
                    className="filter-dropdown",
                    placeholder="Loading...",
                    style={"flex": "1"},
                ),
                html.Button("New", id="new-project-btn",
                            className="btn btn-sm btn-secondary",
                            style={"flexShrink": "0"}),
                html.Button("Ren", id="rename-project-btn",
                            className="btn btn-sm btn-secondary",
                            style={"flexShrink": "0"},
                            title="Rename current project"),
                html.Button("Del", id="delete-project-btn",
                            className="btn btn-sm btn-danger",
                            style={"flexShrink": "0"},
                            title="Delete current project"),
            ], className="project-row"),
            html.Div(
                id="new-project-row",
                children=[
                    dcc.Input(
                        id="new-project-name",
                        type="text",
                        placeholder="project-name",
                        className="project-input",
                        debounce=False,
                        n_submit=0,
                    ),
                    html.Button("Create", id="create-project-btn",
                                className="btn btn-sm btn-primary",
                                style={"flexShrink": "0"}),
                ],
                style={"display": "none"},
            ),
            html.Div(
                id="delete-project-row",
                children=[
                    html.Span("Delete this project?",
                              style={"fontSize": "11px", "color": "#E74C3C",
                                     "flex": "1"}),
                    html.Button("Yes", id="confirm-delete-project-btn",
                                className="btn btn-sm btn-danger",
                                style={"flexShrink": "0"}),
                    html.Button("No", id="cancel-delete-project-btn",
                                className="btn btn-sm btn-secondary",
                                style={"flexShrink": "0"}),
                ],
                style={"display": "none", "alignItems": "center",
                       "gap": "4px", "marginTop": "4px"},
            ),
            html.Div(
                id="rename-project-row",
                children=[
                    dcc.Input(
                        id="rename-project-name",
                        type="text",
                        placeholder="new-name",
                        className="project-input",
                        debounce=False,
                        n_submit=0,
                    ),
                    html.Button("Rename", id="confirm-rename-project-btn",
                                className="btn btn-sm btn-primary",
                                style={"flexShrink": "0"}),
                    html.Button("Cancel", id="cancel-rename-project-btn",
                                className="btn btn-sm btn-secondary",
                                style={"flexShrink": "0"}),
                ],
                style={"display": "none"},
            ),

            # ── Import ────────────────────────────────────────────────────
            html.H3("Import", className="sidebar-section-title"),
            dcc.Upload(
                id="file-upload",
                children=html.Div([
                    html.Span("Drag & drop"),
                    html.Br(),
                    html.Span("or "),
                    html.A("browse files"),
                ]),
                multiple=True,
                max_size=52_428_800,   # 50 MB — larger files rejected at JS level
                className="upload-area",
            ),
            html.Div(
                id="import-path-section",
                style={"display": "none"},
                children=[
                    html.Div([
                        dcc.Input(
                            id="import-path-input",
                            type="text",
                            placeholder="Full file path...",
                            debounce=False,
                            className="filter-input",
                            style={"flex": "1", "minWidth": "0",
                                   "marginTop": "6px"},
                        ),
                        html.Button(
                            "Browse",
                            id="open-browse-btn",
                            className="btn btn-sm btn-secondary",
                            n_clicks=0,
                            style={"marginTop": "6px", "flexShrink": "0"},
                        ),
                    ], style={"display": "flex", "gap": "4px",
                              "alignItems": "flex-end"}),
                    html.Button(
                        "Import from Path",
                        id="import-path-btn",
                        className="btn btn-secondary",
                        n_clicks=0,
                        style={"width": "100%", "marginTop": "4px",
                               "fontSize": "11px"},
                    ),
                ],
            ),
            # Progress bar — hidden until an import is running
            html.Div(id="ingest-progress-bar", style={"display": "none"}),
            html.Div(id="upload-status"),

            # ── Filters ───────────────────────────────────────────────────
            html.H3("Filters", className="sidebar-section-title"),
            html.Label("Hostname / IP"),
            dcc.Input(
                id="filter-hostname",
                type="text",
                placeholder="dc01, corp.*, 10.0.0.*",
                debounce=True,
                className="filter-input",
            ),
            html.Label("Subnet"),
            dcc.Input(
                id="filter-subnet",
                type="text",
                placeholder="192.168.0.0/16, 10.0.0.*, 10.0.0.5",
                debounce=True,
                className="filter-input",
            ),
            html.Label("OS Family"),
            dcc.Dropdown(
                id="filter-os",
                options=[
                    {"label": "Windows", "value": "Windows"},
                    {"label": "Linux", "value": "Linux"},
                    {"label": "Network", "value": "Network"},
                    {"label": "Unknown", "value": "Unknown"},
                ],
                multi=True,
                placeholder="All OS",
                className="filter-dropdown",
            ),
            html.Label("Min Severity"),
            dcc.Dropdown(
                id="filter-severity",
                options=[
                    {"label": "Critical (9+)", "value": "critical"},
                    {"label": "High (7+)", "value": "high"},
                    {"label": "Medium (4+)", "value": "medium"},
                    {"label": "Any vuln", "value": "info"},
                ],
                placeholder="Any",
                className="filter-dropdown",
            ),
            html.Label("Port / Service"),
            dcc.Input(
                id="filter-port-service",
                type="text",
                placeholder="80, http, *sql*",
                debounce=True,
                className="filter-input",
            ),
            html.Div([
                html.Button("Apply", id="apply-filters-btn",
                            className="btn btn-primary"),
                html.Button("Reset", id="reset-filters-btn",
                            className="btn btn-secondary"),
            ], className="filter-buttons"),

            # ── Active Discovery ──────────────────────────────────────────
            html.H3("Discover", className="sidebar-section-title"),
            dcc.Input(
                id="discover-target",
                type="text",
                placeholder="192.168.1.0/24  or  10.0.0.1",
                debounce=False,
                className="filter-input",
            ),
            html.Div([
                html.Label("Methods", style={"fontSize": "11px",
                                              "color": "#aaa", "marginRight": "4px"}),
                dcc.Checklist(
                    id="discover-methods",
                    options=[
                        {"label": " Ping",  "value": "ping"},
                        {"label": " ARP",   "value": "arp"},
                        {"label": " TCP",   "value": "tcp"},
                        {"label": " UDP",   "value": "udp"},
                        {"label": " SNMP",  "value": "snmp"},
                    ],
                    value=["ping", "arp", "tcp"],
                    inline=True,
                    style={"fontSize": "11px"},
                    labelStyle={"color": "#ccc", "cursor": "pointer",
                                "marginRight": "8px"},
                ),
            ], style={"marginTop": "4px"}),
            dcc.Input(
                id="discover-snmp-community",
                type="text",
                placeholder="SNMP community (default: public)",
                debounce=False,
                className="filter-input",
                style={"marginTop": "4px", "fontSize": "11px"},
            ),
            html.Div([
                html.Button("Start Discovery", id="discover-btn",
                            className="btn btn-primary",
                            style={"marginTop": "4px", "width": "100%"}),
            ]),
            html.Div(id="discover-status",
                     style={"fontSize": "11px", "marginTop": "4px",
                            "color": "#5DADE2"}),

            # ── Passive Listener ──────────────────────────────────────────
            html.H3("Passive Listen", className="sidebar-section-title"),
            html.Div(
                "Sniff VPN interface traffic to find hosts that don't respond "
                "to active probes. Requires scapy + Npcap (Windows).",
                style={"fontSize": "10px", "color": "#666", "marginBottom": "4px"},
            ),
            dcc.Input(
                id="passive-interface",
                type="text",
                placeholder="Interface (e.g. tun0, Ethernet 2)",
                debounce=False,
                className="filter-input",
                style={"fontSize": "11px"},
            ),
            html.Div([
                html.Label("Duration (s)",
                           style={"fontSize": "11px", "color": "#aaa",
                                  "marginRight": "6px", "whiteSpace": "nowrap"}),
                dcc.Input(
                    id="passive-duration",
                    type="number",
                    value=30,
                    min=5,
                    max=300,
                    step=5,
                    debounce=True,
                    className="filter-input",
                    style={"width": "70px", "fontSize": "11px"},
                ),
            ], style={"display": "flex", "alignItems": "center",
                      "gap": "4px", "marginTop": "4px"}),
            html.Button(
                "Start Passive Listen",
                id="passive-listen-btn",
                className="btn btn-secondary",
                style={"marginTop": "4px", "width": "100%", "fontSize": "11px"},
            ),
            html.Div(id="passive-listen-status",
                     style={"fontSize": "11px", "marginTop": "4px",
                            "color": "#5DADE2"}),

            # ── Scan Files ────────────────────────────────────────────────
            html.H3("Scan Files", className="sidebar-section-title"),
            html.Div(id="scan-file-list"),

            # ── CVE Enrichment ─────────────────────────────────────────
            html.H3("Enrichment", className="sidebar-section-title"),
            html.Button(
                "Enrich CVEs (KEV + EPSS)",
                id="enrich-btn",
                className="btn btn-secondary",
                n_clicks=0,
                style={"width": "100%", "fontSize": "11px"},
            ),
            html.Div(
                "Fetches CISA KEV + FIRST.org EPSS exploit signals for all CVEs.",
                style={"fontSize": "10px", "color": "#555", "marginTop": "3px"},
            ),
            html.Div(id="enrich-status",
                     style={"fontSize": "11px", "marginTop": "4px"}),
        ],
        className="sidebar",
    )
