from dash import html, dcc, dash_table


def create_bottom_tabs() -> html.Div:
    return html.Div(
        id="bottom-panel",
        children=[
            dcc.Tabs(
                id="bottom-tabs",
                value="tab-hosts",
                children=[
                    dcc.Tab(label="Hosts", value="tab-hosts"),
                    dcc.Tab(label="Services", value="tab-services"),
                    dcc.Tab(label="Vulnerabilities", value="tab-vulns"),
                    dcc.Tab(label="Attack Paths", value="tab-paths"),
                ],
                className="bottom-tabs",
            ),
            html.Div(id="bottom-tab-content", className="bottom-tab-content"),
        ],
        className="bottom-panel",
    )
