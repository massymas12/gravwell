"""Cytoscape stylesheet for the network graph."""
import base64

# Small notepad SVG used as a badge on nodes with analyst notes.
# Base64-encoded to avoid URL-encoding issues with Cytoscape.js.
_NOTE_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13">'
    b'<rect x="0.5" y="0.5" width="12" height="12" rx="2" fill="#F1C40F"/>'
    b'<line x1="3" y1="4.5" x2="10" y2="4.5" stroke="#444"'
    b' stroke-width="1.3" stroke-linecap="round"/>'
    b'<line x1="3" y1="6.8" x2="10" y2="6.8" stroke="#444"'
    b' stroke-width="1.3" stroke-linecap="round"/>'
    b'<line x1="3" y1="9.1" x2="7" y2="9.1" stroke="#444"'
    b' stroke-width="1.3" stroke-linecap="round"/>'
    b'</svg>'
)
_NOTE_URI = "data:image/svg+xml;base64," + base64.b64encode(_NOTE_SVG).decode()

CYTOSCAPE_STYLESHEET = [
    # -------------------------------------------------------------------------
    # Domain compound group nodes (wrap subnet boxes)
    # -------------------------------------------------------------------------
    {
        "selector": ".domain-group",
        "style": {
            "label": "data(label)",
            "text-valign": "top",
            "text-halign": "center",
            "font-size": "15px",
            "font-weight": "bold",
            "color": "#FFFFFF",
            "text-outline-color": "#000000",
            "text-outline-width": "2px",
            "background-color": "data(bg_color)",
            "background-opacity": 0.2,
            "border-color": "data(border_color)",
            "border-width": "2.5px",
            "border-style": "dashed",
            "border-opacity": 0.8,
            "padding": "50px",
            "shape": "roundrectangle",
        },
    },

    # -------------------------------------------------------------------------
    # Subnet compound group nodes
    # -------------------------------------------------------------------------
    {
        "selector": ".subnet-group",
        "style": {
            "label": "data(label)",
            "text-valign": "top",
            "text-halign": "center",
            "font-size": "13px",
            "font-weight": "bold",
            "color": "#FFFFFF",
            "text-outline-color": "#000000",
            "text-outline-width": "2px",
            "background-color": "data(bg_color)",
            "background-opacity": 0.4,
            "border-color": "data(border_color)",
            "border-width": "2px",
            "border-opacity": 0.9,
            "padding": "data(box_padding)",
            "shape": "roundrectangle",
        },
    },

    # -------------------------------------------------------------------------
    # Default host node
    # -------------------------------------------------------------------------
    {
        "selector": "node.host",
        "style": {
            "label": "data(label)",
            "text-wrap": "wrap",
            "text-max-width": "90px",
            "font-size": "10px",
            "font-weight": "bold",
            "color": "#FFFFFF",
            "text-outline-color": "#000000",
            "text-outline-width": "2px",
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": "3px",
            "background-color": "#7F8C8D",
            "width": "32px",
            "height": "32px",
            "border-width": "1.5px",
            "border-color": "#333",
            "shape": "ellipse",
        },
    },

    # -------------------------------------------------------------------------
    # OS families
    # -------------------------------------------------------------------------
    {
        "selector": ".os-windows",
        "style": {"background-color": "#2471A3"},  # steel blue
    },
    {
        "selector": ".os-linux",
        "style": {"background-color": "#1E8449"},  # forest green
    },
    {
        "selector": ".os-network",
        "style": {
            "background-color": "#B7950B",          # gold
            "shape": "diamond",
            "width": "36px",
            "height": "36px",
        },
    },
    {
        "selector": ".os-unknown",
        "style": {"background-color": "#616A6B"},
    },

    # -------------------------------------------------------------------------
    # Gateway nodes — hexagon, brighter, slightly larger
    # -------------------------------------------------------------------------
    {
        "selector": ".gateway",
        "style": {
            "shape": "hexagon",
            "width": "40px",
            "height": "40px",
            "border-width": "2.5px",
            "border-color": "#F39C12",
            "background-color": "#154360",  # deep blue (overwrites os colour)
        },
    },
    # gateway + os class wins, so reset bg for Windows/Linux gateways too
    {
        "selector": ".gateway.os-windows",
        "style": {"background-color": "#1A5276"},
    },
    {
        "selector": ".gateway.os-linux",
        "style": {"background-color": "#145A32"},
    },

    # -------------------------------------------------------------------------
    # Router nodes — pentagon, gold border
    # -------------------------------------------------------------------------
    {
        "selector": ".router",
        "style": {
            "shape": "pentagon",
            "width": "44px",
            "height": "44px",
            "border-width": "3px",
            "border-color": "#F39C12",
            "background-color": "#784212",
        },
    },
    {
        "selector": ".router.os-network",
        "style": {
            "background-color": "#7D6608",
            "shape": "pentagon",
        },
    },

    # -------------------------------------------------------------------------
    # Domain Controller — star shape, deep purple (overrides router/gateway)
    # -------------------------------------------------------------------------
    {
        "selector": ".domain-controller",
        "style": {
            "shape": "star",
            "width": "48px",
            "height": "48px",
            "background-color": "#6C3483",
            "border-color": "#D7BDE2",
            "border-width": "3px",
        },
    },
    {
        "selector": ".domain-controller.severity-critical",
        "style": {
            "border-color": "#E74C3C",
            "border-width": "4px",
        },
    },

    # -------------------------------------------------------------------------
    # Legacy / EOL OS — dashed amber border
    # -------------------------------------------------------------------------
    {
        "selector": ".legacy-os",
        "style": {
            "border-color": "#D4AC0D",
            "border-width": "3px",
            "border-style": "dashed",
        },
    },

    # -------------------------------------------------------------------------
    # Virtual switch node (synthetic, not from scan data)
    # -------------------------------------------------------------------------
    {
        "selector": ".virtual-switch",
        "style": {
            "label": "SW",
            "shape": "rectangle",
            "width": "36px",
            "height": "20px",
            "background-color": "#1C2833",
            "border-color": "data(border_color)",
            "border-width": "2px",
            "font-size": "9px",
            "font-weight": "bold",
            "color": "#FFFFFF",
            "text-outline-color": "#000",
            "text-outline-width": "1px",
            "text-valign": "center",
        },
    },

    # -------------------------------------------------------------------------
    # Severity borders (applied on top of OS colour)
    # -------------------------------------------------------------------------
    {
        "selector": ".severity-critical",
        "style": {
            "border-color": "#E74C3C",
            "border-width": "3.5px",
            "width": "48px",
            "height": "48px",
        },
    },
    {
        "selector": ".severity-high",
        "style": {
            "border-color": "#E67E22",
            "border-width": "3px",
            "width": "40px",
            "height": "40px",
        },
    },
    {
        "selector": ".severity-medium",
        "style": {
            "border-color": "#F1C40F",
            "border-width": "2px",
        },
    },

    # -------------------------------------------------------------------------
    # Nodes with analyst notes — small yellow dot in top-right corner
    # -------------------------------------------------------------------------
    {
        "selector": ".has-note",
        "style": {
            "background-image": f"url('{_NOTE_URI}')",
            "background-width": "13px",
            "background-height": "13px",
            "background-position-x": "88%",
            "background-position-y": "12%",
            "background-clip": "none",
        },
    },

    # -------------------------------------------------------------------------
    # Selected / highlighted
    # -------------------------------------------------------------------------
    {
        "selector": ":selected",
        "style": {
            "border-color": "#FFFFFF",
            "border-width": "3px",
            "overlay-color": "#FFFFFF",
            "overlay-opacity": 0.1,
        },
    },
    {
        "selector": ".highlighted",
        "style": {
            "background-color": "#F1C40F",
            "border-color": "#FFFFFF",
            "border-width": "3px",
            "z-index": 999,
        },
    },

    # -------------------------------------------------------------------------
    # Edges
    # -------------------------------------------------------------------------
    {
        "selector": "edge",
        "style": {
            "width": "1px",
            "line-color": "#444",
            "curve-style": "bezier",
            "opacity": 0.5,
        },
    },
    # Intra-subnet spoke: thin grey
    {
        "selector": ".intra-subnet",
        "style": {
            "line-color": "#566573",
            "line-style": "solid",
            "width": "1px",
            "opacity": 0.6,
        },
    },
    # Inter-subnet link between hubs: bold, coloured, with arrow
    {
        "selector": ".inter-subnet",
        "style": {
            "line-color": "#F39C12",
            "line-style": "solid",
            "width": "2.5px",
            "opacity": 0.9,
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#F39C12",
            "source-arrow-shape": "triangle",
            "source-arrow-color": "#F39C12",
            "curve-style": "bezier",
        },
    },
    # Legacy edge classes (kept for attack path highlighting)
    {
        "selector": ".subnet",
        "style": {
            "line-color": "#566573",
            "line-style": "solid",
            "width": "1px",
        },
    },
    {
        "selector": ".shared_service",
        "style": {
            "line-color": "#5DADE2",
            "line-style": "dashed",
            "width": "1.5px",
        },
    },
    {
        "selector": ".highlighted-edge",
        "style": {
            "line-color": "#F1C40F",
            "width": "3px",
            "opacity": 1,
        },
    },
    # Multi-IP bridge edges: floating multi-homed node → subnet hub (purple dashed)
    # Each edge is labelled with the specific IP on that interface.
    {
        "selector": ".multi-ip-link",
        "style": {
            "line-color": "#A78BFA",
            "line-style": "dashed",
            "width": "2px",
            "opacity": 0.85,
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#A78BFA",
            "source-arrow-shape": "triangle",
            "source-arrow-color": "#A78BFA",
            "curve-style": "bezier",
            "label": "data(label)",
            "font-size": "9px",
            "color": "#C4B5FD",
            "text-background-color": "#0f0f1a",
            "text-background-opacity": 0.85,
            "text-background-padding": "2px",
        },
    },
    # Custom manually-added edges: bright green dashed, bidirectional arrows
    {
        "selector": ".custom-edge",
        "style": {
            "line-color": "#27AE60",
            "line-style": "dashed",
            "width": "2px",
            "opacity": 0.9,
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#27AE60",
            "source-arrow-shape": "triangle",
            "source-arrow-color": "#27AE60",
            "curve-style": "bezier",
        },
    },

    # -------------------------------------------------------------------------
    # Dense-subnet node scaling
    #
    # Hub-and-spoke topology: all N hosts connect to the hub at the same
    # ideal edge distance r.  The ring circumference 2πr must fit N nodes
    # of width w without overlap: r ≥ (N × w) / (2π).
    #
    # At nestingFactor=0.6, idealEdge=120 → r=72 px.
    #   N=14, w=32 → need r≥71 px  ✓  (fits just barely)
    #   N=20, w=32 → need r≥102 px ✗  shrink to 20 px → need r≥64 px  ✓
    #   N=30, w=20 → need r≥96 px  ✗  shrink to 12 px → need r≥57 px  ✓
    # -------------------------------------------------------------------------
    {
        "selector": "node.host.dense-subnet",
        "style": {
            "width": "20px",
            "height": "20px",
            "font-size": "8px",
            "text-max-width": "55px",
            "border-width": "1.5px",
        },
    },
    {
        "selector": "node.host.very-dense-subnet",
        "style": {
            "width": "12px",
            "height": "12px",
            # Labels hidden — too many to read; hover tooltip still works
            "label": "",
            "border-width": "1.5px",
        },
    },
    # Severity border overrides for dense/very-dense must keep reduced size
    {
        "selector": "node.host.dense-subnet.severity-critical",
        "style": {"width": "22px", "height": "22px"},
    },
    {
        "selector": "node.host.very-dense-subnet.severity-critical",
        "style": {"width": "16px", "height": "16px", "label": "data(label)"},
    },
    {
        "selector": "node.host.dense-subnet.severity-high",
        "style": {"width": "21px", "height": "21px"},
    },
    # Spoke edges inside dense subnets: very faint so they don't dominate visually
    {
        "selector": ".intra-subnet.dense-intra",
        "style": {
            "opacity": 0.25,
            "width": "0.5px",
        },
    },
]
