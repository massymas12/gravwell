from dash import html, dcc
import dash_cytoscape as cyto
from gravwell.ui.styles import CYTOSCAPE_STYLESHEET

# Load extra layouts (cola, cose-bilkent)
cyto.load_extra_layouts()

_LEGEND_SHAPES = [
    ("●", "#7F8C8D", "Host"),
    ("⬡", "#F39C12", "Gateway"),
    ("⬠", "#F39C12", "Router"),
    ("◆", "#B7950B", "Enterprise IoT"),
    ("★", "#D7BDE2", "Domain Controller"),
    ("▬", "#5DADE2", "Virtual Switch"),
]

_LEGEND_OS = [
    ("#2471A3", "Windows"),
    ("#1E8449", "Linux"),
    ("#1ABC9C", "macOS / iOS"),
    ("#616A6B", "Unknown"),
]

_LEGEND_SEVERITY = [
    ("#E74C3C", "Critical (≥9.0)"),
    ("#E67E22", "High (≥7.0)"),
    ("#F1C40F", "Medium (≥4.0)"),
]


def _shape_row(symbol, color, label):
    return html.Div([
        html.Span(symbol, className="legend-icon", style={"color": color}),
        html.Span(label, className="legend-label"),
    ], className="legend-row")


def _dot_row(color, label):
    return html.Div([
        html.Div(className="legend-dot", style={"background": color}),
        html.Span(label, className="legend-label"),
    ], className="legend-row")


def _border_row(color, label):
    return html.Div([
        html.Div(className="legend-border-sample",
                 style={"border": f"2.5px solid {color}"}),
        html.Span(label, className="legend-label"),
    ], className="legend-row")


def _create_legend():
    return html.Div(
        id="graph-legend",
        children=[
            html.Div("Legend", className="legend-title"),
            html.Span("Shapes", className="legend-section"),
            *[_shape_row(s, c, l) for s, c, l in _LEGEND_SHAPES],
            html.Span("OS / Type", className="legend-section"),
            *[_dot_row(c, l) for c, l in _LEGEND_OS],
            html.Span("Vuln Severity", className="legend-section"),
            *[_border_row(c, l) for c, l in _LEGEND_SEVERITY],
        ],
        className="graph-legend",
    )


def create_graph_panel() -> html.Div:
    return html.Div(
        id="graph-panel",
        children=[
            html.Div(
                id="graph-toolbar",
                children=[
                    html.Span("Layout: "),
                    dcc.Dropdown(
                        id="layout-selector",
                        options=[
                            {"label": "Preset (static, default)", "value": "preset"},
                            {"label": "Cose-Bilkent (spring)", "value": "cose-bilkent"},
                            {"label": "Cose-Bilkent Spread", "value": "cose-bilkent-spread"},
                            {"label": "Force (Cola)", "value": "cola"},
                            {"label": "Breadth-first", "value": "breadthfirst"},
                            {"label": "Concentric", "value": "concentric"},
                            {"label": "Grid", "value": "grid"},
                            {"label": "Circle", "value": "circle"},
                        ],
                        value="preset",
                        clearable=False,
                        className="layout-dropdown",
                    ),
                    html.Button("Fit", id="fit-graph-btn", className="btn btn-sm"),
                    html.Button("Save Layout", id="save-layout-btn",
                                className="btn btn-sm",
                                title="Persist current node positions to DB"),
                    html.Button("Reset Layout", id="reset-layout-btn",
                                className="btn btn-sm btn-danger",
                                title="Clear all saved positions and recompute from scratch"),
                    html.Span(id="save-layout-status",
                              style={"fontSize": "11px", "color": "#27AE60",
                                     "fontStyle": "italic"}),
                    html.Button("+ Edge", id="add-edge-btn",
                                className="btn btn-sm btn-primary"),
                    html.Button("Cancel", id="cancel-add-edge-btn",
                                className="btn btn-sm btn-secondary",
                                style={"display": "none"}),
                    html.Span(id="edge-add-status",
                              style={"fontSize": "11px", "color": "#27AE60",
                                     "fontStyle": "italic"}),
                    html.Span("Edges:", style={
                        "marginLeft": "12px", "marginRight": "4px",
                        "fontSize": "11px", "color": "#aaa", "whiteSpace": "nowrap",
                    }),
                    dcc.Checklist(
                        id="edge-type-visibility",
                        options=[
                            {"label": "Routes",      "value": "inter-subnet"},
                            {"label": "Bridges",     "value": "multi-ip-link"},
                            {"label": "Spokes",      "value": "intra-subnet"},
                            {"label": "Manual",      "value": "custom-edge"},
                            {"label": "LLDP/CDP",    "value": "lldp-edge"},
                            {"label": "Inter-VLAN",  "value": "inter-vlan-edge"},
                        ],
                        value=["inter-subnet", "multi-ip-link",
                               "intra-subnet", "custom-edge", "lldp-edge",
                               "inter-vlan-edge"],
                        inline=True,
                        className="edge-visibility-checklist",
                    ),
                    html.Span(id="graph-host-count", className="graph-stat"),
                    html.Span(" hosts | "),
                    html.Span(id="graph-edge-count", className="graph-stat"),
                    html.Span(" edges"),
                ],
                className="graph-toolbar",
            ),
            cyto.Cytoscape(
                id="network-graph",
                elements=[],
                stylesheet=CYTOSCAPE_STYLESHEET,
                layout={"name": "preset", "animate": False,
                        "fit": True, "padding": 60},
                style={"width": "100%", "height": "100%"},
                userZoomingEnabled=True,
                userPanningEnabled=True,
                boxSelectionEnabled=True,
                responsive=True,
                autoRefreshLayout=False,
                minZoom=0.05,
                maxZoom=6,
                # Performance hints for large maps (9k+ nodes):
                # textureOnViewport — render to a flat texture while panning/
                #   zooming instead of re-drawing every node; makes pan smooth.
                # hideEdgesOnViewport — skip edge drawing during pan/zoom;
                #   edges are redrawn once the viewport stops moving.
                # pixelRatio — force 1:1 pixel ratio; HiDPI screens otherwise
                #   render at 2-4× the pixel count for no visible benefit at
                #   the zoom levels used for large network maps.
                textureOnViewport=True,
                hideEdgesOnViewport=True,
                pixelRatio=1,
            ),
            _create_legend(),
        ],
        className="graph-panel",
    )
