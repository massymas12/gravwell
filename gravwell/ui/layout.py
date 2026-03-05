from dash import html, dcc
from gravwell.ui.components.sidebar import create_sidebar
from gravwell.ui.components.graph_panel import create_graph_panel
from gravwell.ui.components.detail_panel import create_detail_panel
from gravwell.ui.components.bottom_tabs import create_bottom_tabs


def _create_edit_modal() -> html.Div:
    """Modal overlay for editing node properties."""
    os_options = [
        {"label": "Windows", "value": "Windows"},
        {"label": "Linux",   "value": "Linux"},
        {"label": "Network", "value": "Network"},
        {"label": "Unknown", "value": "Unknown"},
    ]
    status_options = [
        {"label": "Up",      "value": "up"},
        {"label": "Down",    "value": "down"},
        {"label": "Unknown", "value": "unknown"},
    ]
    return html.Div(
        id="edit-modal-overlay",
        style={"display": "none"},
        children=[
            html.Div(
                id="edit-modal",
                className="edit-modal",
                children=[
                    # Header
                    html.Div([
                        html.H3(id="edit-modal-ip",
                                style={"margin": 0, "fontSize": "15px"}),
                        html.Button("×", id="edit-modal-close",
                                    className="modal-close-btn"),
                    ], className="modal-header"),
                    # Body — scrollable
                    html.Div([
                        html.Label("Hostnames (comma-separated)",
                                   className="edit-label"),
                        dcc.Input(id="edit-hostnames", type="text",
                                  className="edit-input"),
                        html.Label("Subnet Override (CIDR)", className="edit-label"),
                        dcc.Input(id="edit-subnet-override", type="text",
                                  placeholder="e.g. 192.168.1.0/24  (blank = auto)",
                                  className="edit-input"),
                        html.Label("OS Name", className="edit-label"),
                        dcc.Input(id="edit-os-name", type="text",
                                  className="edit-input"),
                        html.Label("OS Family", className="edit-label"),
                        dcc.Dropdown(id="edit-os-family", options=os_options,
                                     clearable=False, className="filter-dropdown"),
                        html.Label("Status", className="edit-label"),
                        dcc.Dropdown(id="edit-status", options=status_options,
                                     clearable=False, className="filter-dropdown"),
                        html.Label("MAC Address", className="edit-label"),
                        dcc.Input(id="edit-mac", type="text",
                                  className="edit-input"),
                        html.Label("MAC Vendor", className="edit-label"),
                        dcc.Input(id="edit-mac-vendor", type="text",
                                  className="edit-input"),
                        html.Label("Additional IPs (comma-separated)",
                                   className="edit-label"),
                        dcc.Input(id="edit-additional-ips", type="text",
                                  placeholder="e.g. 10.0.0.1, 172.16.0.1",
                                  className="edit-input"),
                        html.Label("Tags (comma-separated)",
                                   className="edit-label"),
                        dcc.Textarea(id="edit-tags", className="edit-textarea"),
                        html.Label("Key Terrain / Roles",
                                   className="edit-label"),
                        dcc.Checklist(
                            id="edit-roles",
                            options=[
                                {"label": " Domain Controller", "value": "dc"},
                                {"label": " Router / Switch",   "value": "router"},
                                {"label": " Web Server",        "value": "web"},
                                {"label": " Database Server",   "value": "db"},
                                {"label": " RDP Exposed",       "value": "rdp"},
                                {"label": " SMB Share",         "value": "smb"},
                                {"label": " Legacy / EOL OS",   "value": "legacy"},
                            ],
                            value=[],
                            style={"fontSize": "12px", "display": "flex",
                                   "flexWrap": "wrap", "gap": "4px 12px",
                                   "marginTop": "4px"},
                            labelStyle={"color": "#ccc", "cursor": "pointer"},
                            inputStyle={"marginRight": "4px",
                                        "accentColor": "#5DADE2"},
                        ),
                    ], className="modal-body",
                       style={"overflowY": "auto", "maxHeight": "70vh"}),
                    # Footer
                    html.Div([
                        html.Div(id="edit-save-status",
                                 style={"flex": "1", "fontSize": "11px",
                                        "color": "#5DADE2"}),
                        html.Button("Save Changes", id="save-edit-btn",
                                    className="btn btn-primary btn-sm"),
                        html.Button("Cancel", id="cancel-edit-btn",
                                    className="btn btn-secondary btn-sm"),
                    ], className="modal-footer"),
                ],
            ),
        ],
    )


def _create_add_node_modal() -> html.Div:
    """Modal for manually adding a host node via right-click on the canvas."""
    os_options = [
        {"label": "Windows", "value": "Windows"},
        {"label": "Linux",   "value": "Linux"},
        {"label": "Network", "value": "Network"},
        {"label": "Unknown", "value": "Unknown"},
    ]
    return html.Div(
        id="add-node-modal-overlay",
        style={"display": "none"},
        className="modal-overlay",
        children=[
            html.Div(
                className="edit-modal",
                style={"width": "380px"},
                children=[
                    html.Div([
                        html.H3("Add Node", style={"margin": 0, "fontSize": "15px",
                                                    "color": "#5DADE2"}),
                        html.Button("×", id="add-node-modal-close",
                                    className="modal-close-btn"),
                    ], className="modal-header"),
                    html.Div([
                        html.Label("IP Address *", className="edit-label"),
                        dcc.Input(id="add-node-ip", type="text",
                                  placeholder="192.168.1.100",
                                  className="edit-input", debounce=False),
                        html.Label("Hostname(s) (comma-separated)",
                                   className="edit-label"),
                        dcc.Input(id="add-node-hostnames", type="text",
                                  placeholder="server01, server01.corp.local",
                                  className="edit-input", debounce=False),
                        html.Label("OS Family", className="edit-label"),
                        dcc.Dropdown(id="add-node-os-family", options=os_options,
                                     value="Unknown", clearable=False,
                                     className="filter-dropdown"),
                        html.Label("Status", className="edit-label"),
                        dcc.Dropdown(
                            id="add-node-status",
                            options=[{"label": "Up",   "value": "up"},
                                     {"label": "Down", "value": "down"}],
                            value="up", clearable=False,
                            className="filter-dropdown",
                        ),
                        html.Label("Subnet (CIDR)", className="edit-label"),
                        dcc.Input(id="add-node-subnet", type="text",
                                  placeholder="192.168.1.0/24  (blank = auto-detect)",
                                  className="edit-input", debounce=False),
                        html.Div(id="add-node-error",
                                 style={"color": "#E74C3C", "fontSize": "11px",
                                        "marginTop": "6px"}),
                    ], className="modal-body"),
                    html.Div([
                        html.Button("Add Node", id="confirm-add-node-btn",
                                    className="btn btn-primary btn-sm"),
                        html.Button("Cancel", id="cancel-add-node-btn",
                                    className="btn btn-secondary btn-sm"),
                    ], className="modal-footer"),
                ],
            ),
        ],
    )


def _create_browse_modal() -> html.Div:
    """Server-side file browser modal."""
    return html.Div(
        id="browse-modal-overlay",
        style={"display": "none"},
        className="modal-overlay",
        children=[
            html.Div(
                className="edit-modal",
                style={"width": "520px"},
                children=[
                    html.Div([
                        html.H3("Browse Files", style={"margin": 0, "fontSize": "15px"}),
                        html.Button("×", id="browse-modal-close",
                                    className="modal-close-btn"),
                    ], className="modal-header"),
                    html.Div([
                        # Current path breadcrumb
                        html.Div(id="browse-current-path",
                                 style={"fontSize": "11px", "color": "#5DADE2",
                                        "marginBottom": "6px", "wordBreak": "break-all"}),
                        # File listing
                        html.Div(
                            id="browse-file-list",
                            style={"maxHeight": "380px", "overflowY": "auto",
                                   "border": "1px solid #333", "borderRadius": "3px",
                                   "backgroundColor": "#161616"},
                        ),
                    ], className="modal-body"),
                ],
            ),
        ],
    )


def _create_add_user_modal() -> html.Div:
    """Modal for creating a new user (admin only)."""
    _cl = {"color": "#ccc", "cursor": "pointer"}
    _ci = {"marginRight": "6px", "accentColor": "#5DADE2"}
    return html.Div(
        id="add-user-modal-overlay",
        style={"display": "none"},
        className="modal-overlay",
        children=[
            html.Div(
                className="edit-modal",
                style={"width": "400px"},
                children=[
                    html.Div([
                        html.H3("Add User", style={"margin": 0, "fontSize": "15px",
                                                   "color": "#5DADE2"}),
                        html.Button("×", id="add-user-modal-close",
                                    className="modal-close-btn"),
                    ], className="modal-header"),
                    html.Div([
                        # ── Credentials ───────────────────────────────────
                        html.Label("Username", className="edit-label"),
                        dcc.Input(id="add-user-username-input", type="text",
                                  placeholder="username",
                                  className="edit-input", debounce=False),
                        html.Label("Password", className="edit-label"),
                        dcc.Input(id="add-user-password-input", type="password",
                                  placeholder="password",
                                  className="edit-input", debounce=False),

                        # ── Role ──────────────────────────────────────────
                        html.Label("Role", className="edit-label"),
                        dcc.Checklist(
                            id="add-user-is-admin",
                            options=[{"label": " Admin — can manage users and has all permissions",
                                      "value": "admin"}],
                            value=[],
                            style={"fontSize": "12px", "marginBottom": "4px"},
                            labelStyle=_cl, inputStyle=_ci,
                        ),

                        # ── Permissions ───────────────────────────────────
                        html.Label("Permissions", className="edit-label"),
                        html.Div(
                            "(Inherited automatically when Admin is checked)",
                            id="add-user-perms-note",
                            style={"fontSize": "10px", "color": "#555",
                                   "marginBottom": "4px", "display": "none"},
                        ),
                        dcc.Checklist(
                            id="add-user-permissions",
                            options=[
                                {"label": " Edit node data",       "value": "edit"},
                                {"label": " Import scan files",    "value": "import"},
                                {"label": " Run active discovery", "value": "discover"},
                                {"label": " Export data",          "value": "export"},
                            ],
                            value=["edit", "import"],
                            style={"fontSize": "12px", "display": "flex",
                                   "flexWrap": "wrap", "gap": "2px 16px",
                                   "marginBottom": "6px"},
                            labelStyle=_cl, inputStyle=_ci,
                        ),

                        # ── Project access ────────────────────────────────
                        html.Label("Project Access", className="edit-label"),
                        dcc.RadioItems(
                            id="add-user-project-access",
                            options=[
                                {"label": " All projects (current and future)",
                                 "value": "all"},
                                {"label": " Specific projects only:",
                                 "value": "specific"},
                            ],
                            value="all",
                            style={"fontSize": "12px", "marginBottom": "4px"},
                            labelStyle={**_cl, "display": "block",
                                        "marginBottom": "3px"},
                            inputStyle=_ci,
                        ),
                        html.Div(
                            id="add-user-project-list-wrap",
                            style={"display": "none", "marginLeft": "18px",
                                   "marginBottom": "6px",
                                   "padding": "6px 8px",
                                   "background": "#161616",
                                   "borderRadius": "3px",
                                   "border": "1px solid #333"},
                            children=[
                                dcc.Checklist(
                                    id="add-user-project-list",
                                    options=[],
                                    value=[],
                                    style={"fontSize": "12px",
                                           "display": "flex",
                                           "flexDirection": "column",
                                           "gap": "4px"},
                                    labelStyle=_cl, inputStyle=_ci,
                                ),
                            ],
                        ),

                        html.Div(id="add-user-status",
                                 style={"fontSize": "11px", "color": "#E74C3C",
                                        "marginTop": "6px", "minHeight": "14px"}),
                    ], className="modal-body",
                       style={"overflowY": "auto", "maxHeight": "65vh"}),
                    html.Div([
                        html.Button("Create User", id="confirm-add-user-btn",
                                    className="btn btn-primary btn-sm"),
                        html.Button("Cancel", id="cancel-add-user-btn",
                                    className="btn btn-secondary btn-sm"),
                    ], className="modal-footer"),
                ],
            ),
        ],
    )


def _create_manage_users_modal() -> html.Div:
    """Full-screen-ish modal showing all users with RBAC details (admin only)."""
    return html.Div(
        id="manage-users-modal-overlay",
        style={"display": "none"},
        className="modal-overlay",
        children=[
            html.Div(
                className="edit-modal",
                style={"width": "760px", "maxWidth": "95vw"},
                children=[
                    html.Div([
                        html.H3("Manage Users",
                                style={"margin": 0, "fontSize": "15px",
                                       "color": "#5DADE2"}),
                        html.Button("×", id="manage-users-modal-close",
                                    className="modal-close-btn"),
                    ], className="modal-header"),
                    html.Div(
                        id="manage-users-content",
                        className="modal-body",
                        style={"overflowY": "auto", "maxHeight": "70vh",
                               "padding": "12px 16px"},
                    ),
                    html.Div([
                        html.Div(id="manage-users-status",
                                 style={"flex": "1", "fontSize": "11px",
                                        "color": "#5DADE2"}),
                        html.Button("Close", id="manage-users-close-btn",
                                    className="btn btn-secondary btn-sm"),
                    ], className="modal-footer"),
                ],
            ),
        ],
    )


def create_layout() -> html.Div:
    return html.Div(
        id="app-root",
        children=[
            # Hidden stores
            dcc.Store(id="graph-data-store"),
            dcc.Store(id="selected-node-store"),
            dcc.Store(id="selected-edge-store"),
            dcc.Store(id="selected-subnet-store"),
            dcc.Store(id="edge-add-mode", data={"active": False, "source_ip": None}),
            dcc.Store(id="path-results-store"),
            dcc.Store(id="project-switch-trigger", data=0),
            dcc.Store(id="node-focus-store"),
            dcc.Store(id="browse-dir-store", data=""),
            dcc.Store(id="node-positions-store"),
            dcc.Store(id="add-node-position-store"),
            dcc.Store(id="current-user-store"),
            dcc.Download(id="export-download"),
            dcc.Store(id="export-png-dummy"),
            # Hidden text input: JS writes graph coords here to trigger the Add Node modal.
            # Must be type="text" (not "hidden") so React attaches its onChange handler
            # and the programmatic value-setter + dispatchEvent trick works.
            dcc.Input(id="_add-node-js-trigger", type="text", value="",
                      debounce=False, style={"display": "none"}),
            dcc.Input(id="_delete-node-js-trigger", type="text", value="",
                      debounce=False, style={"display": "none"}),
            dcc.Input(id="_path-host-focus-trigger", type="text", value="",
                      debounce=False, style={"display": "none"}),
            dcc.Input(id="_autosave-positions-trigger", type="text", value="",
                      debounce=False, style={"display": "none"}),
            # Edit modal (always in DOM so callback IDs are static)
            _create_edit_modal(),
            # Add Node modal
            _create_add_node_modal(),
            # File browser modal
            _create_browse_modal(),
            # Add User modal (settings)
            _create_add_user_modal(),
            # Manage Users modal (settings)
            _create_manage_users_modal(),
            # Polling interval: refresh every 60s
            dcc.Interval(id="refresh-interval", interval=60_000, n_intervals=0),
            # Fast interval used only while a file import is running
            dcc.Interval(id="ingest-progress-interval", interval=250,
                         n_intervals=0, disabled=True),

            # Top bar
            html.Div(
                id="topbar",
                children=[
                    html.Span("GravWell", id="topbar-logo"),
                    html.Span(id="topbar-stats", className="topbar-stats"),
                    # Hamburger menu (settings)
                    html.Div([
                        html.Button("☰", id="hamburger-btn",
                                    className="hamburger-btn", n_clicks=0),
                        html.Div(
                            id="hamburger-menu",
                            className="hamburger-menu",
                            style={"display": "none"},
                            children=[
                                html.Div(id="hamburger-username",
                                         className="hamburger-username"),
                                html.Div("Add User", id="add-user-menu-item",
                                         className="hamburger-item",
                                         n_clicks=0,
                                         style={"display": "none"}),
                                html.Div("Manage Users", id="manage-users-menu-item",
                                         className="hamburger-item",
                                         n_clicks=0,
                                         style={"display": "none"}),
                                html.Hr(className="hamburger-sep"),
                                html.Div("Export Hosts & Vulns (CSV)",
                                         id="export-csv-menu-item",
                                         className="hamburger-item",
                                         n_clicks=0,
                                         style={"display": "none"}),
                                html.Div("Export Hosts & Vulns (XLSX)",
                                         id="export-xlsx-menu-item",
                                         className="hamburger-item",
                                         n_clicks=0,
                                         style={"display": "none"}),
                                html.Div("Export Graph (PNG)",
                                         id="export-png-menu-item",
                                         className="hamburger-item",
                                         n_clicks=0,
                                         style={"display": "none"}),
                                html.Hr(className="hamburger-sep"),
                                html.A("Logout", href="/logout",
                                       className="hamburger-item hamburger-item-danger"),
                            ],
                        ),
                    ], className="hamburger-wrap"),
                    # Invisible backdrop — clicking outside closes the menu
                    html.Div(id="hamburger-backdrop",
                             style={"display": "none", "position": "fixed",
                                    "top": 0, "left": 0, "width": "100%",
                                    "height": "100%", "zIndex": 999},
                             n_clicks=0),
                ],
                className="topbar",
            ),

            # Main 3-column area
            html.Div(
                id="main-area",
                children=[
                    create_sidebar(),
                    create_graph_panel(),
                    html.Div(id="vertical-resize-handle",
                             className="resize-handle-v"),
                    create_detail_panel(),
                ],
                className="main-area",
            ),

            # Horizontal drag handle between main area and bottom panel
            html.Div(id="horizontal-resize-handle",
                     className="resize-handle-h"),

            # Bottom panel
            create_bottom_tabs(),
        ],
        className="app-root",
    )
