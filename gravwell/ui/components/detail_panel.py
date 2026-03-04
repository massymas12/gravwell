from dash import html, dcc


def create_detail_panel() -> html.Div:
    return html.Div(
        id="right-panel",
        children=[
            # Subnet selection panel — shown when a subnet compound node is tapped
            html.Div(
                id="subnet-selected-panel",
                style={"display": "none"},
                children=[
                    html.Div(id="subnet-selected-info",
                             style={"fontSize": "11px", "color": "#888",
                                    "marginBottom": "4px"}),
                    html.Div([
                        dcc.Input(
                            id="subnet-label-input",
                            type="text",
                            placeholder="Label (e.g. DMZ)...",
                            className="edit-input",
                            style={"flex": "1", "minWidth": "0"},
                            debounce=False,
                        ),
                        html.Button("Save", id="save-subnet-label-btn",
                                    className="btn btn-sm btn-primary"),
                    ], style={"display": "flex", "gap": "6px"}),
                    # Box size (padding) slider
                    html.Div([
                        html.Label("Box padding",
                                   style={"fontSize": "10px", "color": "#888",
                                          "textTransform": "uppercase",
                                          "letterSpacing": "0.5px",
                                          "marginRight": "6px", "flexShrink": "0"}),
                        dcc.Slider(
                            id="subnet-padding-slider",
                            min=10, max=300, step=10, value=30,
                            marks={10: "10", 100: "100", 200: "200", 300: "300"},
                            tooltip={"always_visible": False,
                                     "placement": "bottom"},
                            className="subnet-padding-slider",
                        ),
                    ], style={"display": "flex", "alignItems": "center",
                               "marginTop": "6px", "gap": "4px"}),
                ],
                className="subnet-selected-panel",
            ),
            # Edge selection panel — shown when an edge is tapped
            html.Div(
                id="edge-selected-panel",
                style={"display": "none"},
                children=[
                    html.Div(id="edge-selected-info",
                             style={"fontSize": "12px", "color": "#ccc",
                                    "marginBottom": "4px"}),
                    html.Div([
                        html.Button("Delete / Hide", id="delete-edge-btn",
                                    className="btn btn-sm btn-danger"),
                        html.Button("Restore All Hidden", id="restore-edges-btn",
                                    className="btn btn-sm btn-secondary"),
                    ], style={"display": "flex", "gap": "6px"}),
                ],
                className="edge-selected-panel",
            ),
            html.Div(
                [
                    html.H3("Node Details", className="panel-header"),
                    # Always in the DOM; shown/hidden by callback
                    html.Button(
                        "Edit Node",
                        id="edit-btn",
                        className="btn btn-sm btn-secondary",
                        style={"display": "none"},
                    ),
                ],
                style={"display": "flex", "alignItems": "center",
                       "justifyContent": "space-between", "marginBottom": "4px"},
            ),
            # Config attachment panel — shown when a host node is selected
            html.Div(
                id="config-attach-panel",
                style={"display": "none"},
                children=[
                    html.Div(id="config-current-file",
                             style={"fontSize": "11px", "color": "#5DADE2",
                                    "marginBottom": "3px"}),
                    dcc.Upload(
                        id="attach-config-upload",
                        children=html.Span(
                            id="attach-config-label",
                            children="Drop / click to attach device config",
                            style={"fontSize": "10px"},
                        ),
                        className="upload-area",
                        style={"padding": "4px 6px"},
                    ),
                    html.Div(id="attach-config-status",
                             style={"fontSize": "11px", "color": "#5DADE2",
                                    "marginTop": "2px"}),
                ],
                className="config-attach-panel",
            ),
            html.Div(
                id="detail-panel",
                children=html.Div(
                    "Click a node in the graph to view details.",
                    className="detail-placeholder",
                ),
                className="detail-content",
            ),
            # Analyst notes — hidden until a host node is selected
            html.Div(
                id="node-notes-section",
                style={"display": "none"},
                children=[
                    html.H4("Analyst Notes",
                            style={"marginBottom": "4px", "marginTop": "10px",
                                   "fontSize": "13px"}),
                    dcc.Textarea(
                        id="node-notes-textarea",
                        placeholder="Add analyst notes for this host...",
                        style={
                            "width": "100%", "height": "80px",
                            "resize": "vertical",
                            "backgroundColor": "#1e1e1e", "color": "#ccc",
                            "border": "1px solid #444", "borderRadius": "3px",
                            "fontSize": "11px", "padding": "4px",
                            "fontFamily": "monospace", "boxSizing": "border-box",
                        },
                    ),
                    html.Div([
                        html.Button(
                            "Save Note",
                            id="save-note-btn",
                            className="btn btn-sm btn-primary",
                            n_clicks=0,
                            style={"fontSize": "11px"},
                        ),
                        html.Span(
                            id="save-note-status",
                            style={"fontSize": "10px", "marginLeft": "8px",
                                   "color": "#27AE60"},
                        ),
                    ], style={"marginTop": "4px", "display": "flex",
                              "alignItems": "center"}),
                ],
            ),
            # Delete node — shown when a host node is selected
            html.Div(
                id="delete-node-section",
                style={"display": "none", "marginTop": "10px",
                       "borderTop": "1px solid #333", "paddingTop": "8px"},
                children=[
                    html.Button(
                        "Delete Node",
                        id="delete-node-btn",
                        className="btn btn-sm btn-danger",
                        n_clicks=0,
                        style={"width": "100%", "fontSize": "11px"},
                    ),
                    html.Div(
                        id="delete-node-confirm-row",
                        style={"display": "none", "marginTop": "4px",
                               "gap": "4px"},
                        children=[
                            html.Span(
                                "Delete this host and all its data?",
                                style={"fontSize": "11px", "color": "#E74C3C",
                                       "flex": "1"},
                            ),
                            html.Button(
                                "Yes",
                                id="confirm-delete-node-btn",
                                className="btn btn-sm btn-danger",
                                n_clicks=0,
                                style={"flexShrink": "0"},
                            ),
                            html.Button(
                                "No",
                                id="cancel-delete-node-btn",
                                className="btn btn-sm btn-secondary",
                                n_clicks=0,
                                style={"flexShrink": "0"},
                            ),
                        ],
                    ),
                ],
            ),
        ],
        className="right-panel",
    )
