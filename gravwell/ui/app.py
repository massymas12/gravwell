from __future__ import annotations
import base64
import dash
from gravwell.ui.layout import create_layout
from gravwell.ui.callbacks import (
    graph_callbacks,
    import_callbacks,
    path_callbacks,
    filter_callbacks,
    project_callbacks,
    edit_callbacks,
    discovery_callbacks,
    edge_callbacks,
    subnet_callbacks,
    config_callbacks,
    enrich_callbacks,
    browse_callbacks,
    add_node_callbacks,
    settings_callbacks,
    export_callbacks,
)

_FAVICON_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    b'<rect width="32" height="32" rx="6" fill="#1a1a2e"/>'
    # edges
    b'<line x1="16" y1="16" x2="7"  y2="9"  stroke="#5DADE2" stroke-width="1.5" stroke-linecap="round"/>'
    b'<line x1="16" y1="16" x2="25" y2="9"  stroke="#5DADE2" stroke-width="1.5" stroke-linecap="round"/>'
    b'<line x1="16" y1="16" x2="7"  y2="23" stroke="#5DADE2" stroke-width="1.5" stroke-linecap="round"/>'
    b'<line x1="16" y1="16" x2="25" y2="23" stroke="#5DADE2" stroke-width="1.5" stroke-linecap="round"/>'
    # satellite nodes
    b'<circle cx="7"  cy="9"  r="3.5" fill="#5DADE2"/>'
    b'<circle cx="25" cy="9"  r="3.5" fill="#5DADE2"/>'
    b'<circle cx="7"  cy="23" r="3.5" fill="#5DADE2"/>'
    b'<circle cx="25" cy="23" r="3.5" fill="#5DADE2"/>'
    # central node
    b'<circle cx="16" cy="16" r="5.5" fill="#A78BFA"/>'
    b'</svg>'
)
_FAVICON_URI = "data:image/svg+xml;base64," + base64.b64encode(_FAVICON_SVG).decode()

_APP_CSS = """
body, html { margin: 0; padding: 0; background: #121212; color: #ccc;
             font-family: 'Segoe UI', monospace; height: 100%; }
.app-root { display: flex; flex-direction: column; height: 100vh; overflow: hidden; }

/* Topbar */
.topbar { display: flex; align-items: center; background: #1a1a2e;
          padding: 6px 16px; height: 36px; flex-shrink: 0;
          border-bottom: 1px solid #333; }
#topbar-logo { font-size: 20px; font-weight: 700; color: #A78BFA;
               margin-right: 14px; letter-spacing: 1px; }
.topbar-stats { font-size: 12px; color: #888; }

/* Main 3-column */
.main-area { display: flex; flex: 1; overflow: hidden; min-height: 0; }

/* Sidebar */
.sidebar { width: 220px; flex-shrink: 0; overflow-y: auto; background: #1a1a1a;
           padding: 8px; border-right: 1px solid #333; }
.sidebar-section-title { font-size: 12px; text-transform: uppercase; color: #5DADE2;
                          margin: 12px 0 4px; }
.filter-input { width: 100%; background: #2d2d2d; border: 1px solid #444; color: #ccc;
                padding: 4px; font-size: 12px; box-sizing: border-box; }
.filter-dropdown .Select-control { background: #2d2d2d !important; border-color: #444 !important; }
.filter-buttons { display: flex; gap: 6px; margin-top: 8px; }

/* Buttons */
.btn { padding: 4px 10px; font-size: 12px; border: none; cursor: pointer;
       border-radius: 3px; transition: background 0.12s, transform 0.08s, box-shadow 0.08s;
       user-select: none; }
.btn:active { transform: scale(0.93); box-shadow: inset 0 2px 4px rgba(0,0,0,0.4); }
.btn-primary { background: #2980B9; color: #fff; }
.btn-primary:hover { background: #3498DB; }
.btn-primary:active { background: #1a6fa8; }
.btn-secondary { background: #555; color: #fff; }
.btn-secondary:hover { background: #666; }
.btn-secondary:active { background: #3d3d3d; }
.btn-danger { background: #922B21; color: #fff; }
.btn-danger:hover { background: #E74C3C; }
.btn-danger:active { background: #6b1f17; }
.btn-warning { background: #7D6608; color: #fff; }
.btn-warning:hover { background: #D4AC0D; }
.btn-warning:active { background: #5a4a05; }
.btn-sm { padding: 2px 8px; font-size: 11px; }

/* Save layout status flash */
@keyframes status-flash {
  0%   { opacity: 0; transform: translateY(-4px); }
  15%  { opacity: 1; transform: translateY(0); }
  75%  { opacity: 1; }
  100% { opacity: 0; }
}
#save-layout-status:not(:empty) { animation: status-flash 2.5s ease forwards; }

/* Projects row */
.project-row { display: flex; gap: 4px; align-items: center; margin-bottom: 4px; }
.project-input { flex: 1; background: #2d2d2d; border: 1px solid #444; color: #ccc;
                 padding: 3px 6px; font-size: 12px; }

/* Upload area */
.upload-area { border: 2px dashed #444; padding: 10px; text-align: center;
               cursor: pointer; font-size: 11px; color: #888; margin-bottom: 6px; }
.upload-area:hover { border-color: #5DADE2; color: #5DADE2; }

/* Ingest progress bar */
#ingest-progress-bar { margin-bottom: 4px; }

/* Graph panel */
.graph-panel { flex: 1; display: flex; flex-direction: column; overflow: hidden;
               background: #161616; position: relative; }
.graph-toolbar { display: flex; align-items: center; gap: 8px; padding: 4px 8px;
                 background: #1e1e1e; border-bottom: 1px solid #333; flex-shrink: 0;
                 font-size: 12px; }
.layout-dropdown { width: 160px; }
.graph-stat { color: #5DADE2; font-weight: bold; }
.edge-visibility-checklist { display: flex; align-items: center; gap: 6px; }
.edge-visibility-checklist label { font-size: 11px; color: #ccc; display: flex;
  align-items: center; gap: 3px; cursor: pointer; white-space: nowrap; }
.edge-visibility-checklist input[type=checkbox] { margin: 0; cursor: pointer; }
#network-graph { flex: 1; will-change: transform; transform: translateZ(0); }
#network-graph canvas { will-change: transform; transform: translateZ(0); image-rendering: auto; }

/* Right panel */
.right-panel { width: 280px; flex-shrink: 0; overflow-y: auto; background: #1a1a1a;
               padding: 8px; border-left: 1px solid #333; }
.panel-header { font-size: 13px; color: #5DADE2; margin: 0 0 8px; }
.detail-placeholder { color: #555; font-size: 12px; margin-top: 20px;
                       text-align: center; }
.detail-content { font-size: 12px; }

/* Bottom panel */
.bottom-panel { height: 280px; flex-shrink: 0; border-top: 1px solid #333;
                background: #1a1a1a; display: flex; flex-direction: column; }
.bottom-tab-content { flex: 1; overflow: auto; padding: 4px; }

/* Path inputs */
.path-input { background: #2d2d2d; border: 1px solid #444; color: #ccc;
              padding: 4px 8px; font-size: 12px; border-radius: 3px; width: 120px; }

/* Query toolbar (Attack Paths tab) */
.query-toolbar { display: flex; flex-wrap: wrap; gap: 6px; padding: 5px 8px;
                 background: #1a1a1a; border-bottom: 1px solid #333;
                 flex-shrink: 0; align-items: flex-start; }
.query-group { display: flex; flex-wrap: wrap; gap: 4px; align-items: center;
               border-right: 1px solid #333; padding-right: 8px; }
.query-group:last-child { border-right: none; }
.qg-label { font-size: 9px; color: #555; text-transform: uppercase;
            letter-spacing: 0.5px; width: 100%; margin-bottom: 2px; }
.query-results { flex: 1; overflow-y: auto; padding: 6px 8px; font-size: 12px; }

/* Graph legend overlay */
.graph-legend { position: absolute; bottom: 12px; left: 12px; z-index: 100;
                background: rgba(15, 15, 25, 0.88); border: 1px solid #444;
                border-radius: 6px; padding: 8px 12px; min-width: 170px;
                pointer-events: none; }
.legend-title { font-size: 11px; font-weight: bold; color: #5DADE2;
                text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }
.legend-section { display: block; font-size: 9px; color: #666;
                  text-transform: uppercase; letter-spacing: 0.5px;
                  border-top: 1px solid #333; margin-top: 5px;
                  padding-top: 4px; margin-bottom: 3px; }
.legend-row { display: flex; align-items: center; gap: 6px;
              margin-bottom: 2px; color: #bbb; font-size: 11px; }
.legend-icon { width: 16px; text-align: center; font-size: 13px; line-height: 1; }
.legend-label { font-size: 11px; }
.legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.legend-border-sample { width: 20px; height: 10px; border-radius: 3px;
                         flex-shrink: 0; background: transparent; }

/* Edit modal overlay */
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                 background: rgba(0,0,0,0.75); z-index: 1000;
                 display: flex; align-items: center; justify-content: center; }
.edit-modal { background: #1e1e1e; border: 1px solid #555; border-radius: 6px;
              width: 420px; max-height: 85vh; overflow-y: auto;
              box-shadow: 0 8px 32px rgba(0,0,0,0.6); }
.modal-header { display: flex; align-items: center; padding: 12px 16px;
                border-bottom: 1px solid #333; }
.modal-header h3 { flex: 1; color: #5DADE2; font-size: 14px; }
.modal-close-btn { background: none; border: none; color: #777; font-size: 22px;
                   cursor: pointer; padding: 0 4px; line-height: 1; }
.modal-close-btn:hover { color: #fff; }
.modal-body { padding: 12px 16px; }
.modal-footer { display: flex; align-items: center; gap: 8px; padding: 10px 16px;
                border-top: 1px solid #333; }

/* Node edit form */
.edit-form { font-size: 12px; }
.edit-label { display: block; color: #888; font-size: 11px;
              margin: 6px 0 2px; text-transform: uppercase; letter-spacing: 0.5px; }
.edit-input { width: 100%; background: #2d2d2d; border: 1px solid #555; color: #ccc;
              padding: 4px 6px; font-size: 12px; box-sizing: border-box;
              border-radius: 2px; margin-bottom: 2px; }
.edit-input:focus { border-color: #5DADE2; outline: none; }
.edit-textarea { width: 100%; background: #2d2d2d; border: 1px solid #555; color: #ccc;
                 padding: 4px 6px; font-size: 12px; box-sizing: border-box;
                 border-radius: 2px; min-height: 60px; resize: vertical; }
.edit-textarea:focus { border-color: #5DADE2; outline: none; }

/* Subnet / edge / config panels */
.subnet-selected-panel { margin-bottom: 6px; }
.edge-selected-panel { margin-bottom: 6px; }
.config-attach-panel { margin-bottom: 6px; }

/* Subnet padding slider — dark theme overrides for rc-slider */
.subnet-padding-slider { flex: 1; }
.subnet-padding-slider .rc-slider-rail { background: #444; }
.subnet-padding-slider .rc-slider-track { background: #5DADE2; }
.subnet-padding-slider .rc-slider-handle { border-color: #5DADE2; background: #2d2d2d; }
.subnet-padding-slider .rc-slider-handle:hover { border-color: #85C1E9; }
.subnet-padding-slider .rc-slider-mark-text { color: #666; font-size: 9px; }

/* Resize handles */
.resize-handle-v { width: 5px; cursor: ew-resize; flex-shrink: 0;
                   background: #222; transition: background 0.15s; }
.resize-handle-v:hover, .resize-handle-v.dragging { background: #5DADE2; }
.resize-handle-h { height: 5px; cursor: ns-resize; flex-shrink: 0;
                   background: #222; transition: background 0.15s; }
.resize-handle-h:hover, .resize-handle-h.dragging { background: #5DADE2; }

/* Tables */
table { width: 100%; }
th { background: #2d2d2d; color: #aaa; padding: 4px 8px;
     text-align: left; font-size: 11px; }
td { padding: 3px 8px; font-size: 11px; border-bottom: 1px solid #2d2d2d; }

/* Clickable host cells — children are transparent to pointer events so the
   click always lands on the g-host-link element itself (e.target), avoiding
   the need to walk up the DOM tree and making focus reliable. */
.g-host-link { cursor: pointer; }
.g-host-link * { pointer-events: none; }

/* Hamburger menu */
.hamburger-wrap { position: relative; margin-left: auto; }
.hamburger-btn { background: none; border: 1px solid #444; color: #aaa;
                 font-size: 15px; cursor: pointer; padding: 1px 8px;
                 border-radius: 3px; line-height: 1.4; }
.hamburger-btn:hover { border-color: #5DADE2; color: #5DADE2; }
.hamburger-menu { position: absolute; top: calc(100% + 4px); right: 0;
                  background: #1e1e1e; border: 1px solid #555; border-radius: 4px;
                  min-width: 190px; z-index: 1000;
                  box-shadow: 0 4px 14px rgba(0,0,0,0.6); padding: 4px 0; }
.hamburger-username { padding: 7px 14px; font-size: 11px; color: #666;
                      border-bottom: 1px solid #333; }
.hamburger-item { display: block; padding: 7px 14px; font-size: 12px;
                  cursor: pointer; color: #ccc; text-decoration: none;
                  background: none; border: none; width: 100%; text-align: left; }
.hamburger-item:hover { background: #2d2d2d; color: #fff; }
.hamburger-item-danger { color: #E74C3C; }
.hamburger-item-danger:hover { color: #ff6b6b; }
.hamburger-sep { border: none; border-top: 1px solid #333; margin: 4px 0; }
"""


_LARGE_FILE_JS = """
(function () {
  var LARGE_BYTES = 50 * 1024 * 1024; // 50 MB

  function showPathSection(filename, sizeMb) {
    var section = document.getElementById('import-path-section');
    if (section) {
      section.style.display    = 'block';
      section.style.marginTop  = '4px';
    }
    // Pre-fill the path input via React's synthetic event system
    var input = document.getElementById('import-path-input');
    if (input && filename) {
      var setter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value'
      );
      if (setter && setter.set) {
        setter.set.call(input, filename);
        input.dispatchEvent(new Event('input', { bubbles: true }));
      }
    }
    // Show a status message
    var status = document.getElementById('upload-status');
    if (status) {
      var mb = sizeMb > 0 ? ' (~' + sizeMb + ' MB)' : '';
      status.innerHTML =
        '<div style="color:#E67E22;font-size:12px;font-weight:bold;">' +
        '\u2018' + (filename || 'file') + '\u2019 is too large for browser upload' + mb + '.</div>' +
        '<div style="color:#aaa;font-size:11px;margin-top:2px;">' +
        'Enter the full server path above and click Import.</div>';
    }
  }

  // ── Drag-and-drop interception ─────────────────────────────────────────────
  // Listen in the capture phase so we see the event before react-dropzone.
  // We only read File.size — no file content is ever loaded.
  document.addEventListener('drop', function (e) {
    var uploadEl = document.getElementById('file-upload');
    if (!uploadEl || !uploadEl.contains(e.target)) return;
    var files = e.dataTransfer && e.dataTransfer.files;
    if (!files || !files.length) return;
    for (var i = 0; i < files.length; i++) {
      if (files[i].size > LARGE_BYTES) {
        showPathSection(files[i].name, Math.round(files[i].size / (1024 * 1024)));
        e.stopImmediatePropagation();
        e.preventDefault();
        return;
      }
    }
  }, true); // capture phase

  // ── Browse-dialog interception ─────────────────────────────────────────────
  // dcc.Upload hides a real <input type="file"> inside the dropzone div.
  // When the user clicks "browse files" and picks a file, the browser has a
  // File reference (with .size) but has NOT yet called FileReader.readAsDataURL.
  // Intercept the change event in capture phase — BEFORE react-dropzone's
  // handler — check the size, and cancel the event if the file is too large.
  function interceptBrowseInput() {
    var uploadEl = document.getElementById('file-upload');
    if (!uploadEl) return false;
    var input = uploadEl.querySelector('input[type="file"]');
    if (!input || input._gw_intercepted) return false;
    input._gw_intercepted = true;
    input.addEventListener('change', function (e) {
      var files = e.target.files;
      if (!files || !files.length) return;
      for (var i = 0; i < files.length; i++) {
        if (files[i].size > LARGE_BYTES) {
          var name = files[i].name;
          var mb   = Math.round(files[i].size / (1024 * 1024));
          // Clear the input BEFORE stopping propagation so react-dropzone
          // doesn't receive stale file references on the next open.
          e.target.value = '';
          e.stopImmediatePropagation();
          showPathSection(name, mb);
          return;
        }
      }
    }, true); // capture phase — runs before react-dropzone's listener
    return true;
  }

  // Try immediately, then retry after React mounts the component.
  if (!interceptBrowseInput()) {
    var _retries = 0;
    var _iv = setInterval(function () {
      if (interceptBrowseInput() || ++_retries > 20) clearInterval(_iv);
    }, 300);
  }
})();
"""

_CYTO_PERF_JS = """
(function () {
  /* LOD collapses subnets to hub-only at low zoom.
     cy.remove() is used (not display:none) so Cytoscape stops
     hit-testing hidden elements on every mousemove event. */
  var LOD_THRESHOLD   = 0.25;  // zoom below which subnets collapse
  var MAX_PIXEL_RATIO = 1.5;
  var POLL_MS         = 300;

  var _cy           = null;
  var _lodActive    = false;
  var _fullSnapshot = null;   // sorted parent-first jsons for restore
  var _preLodPan    = null;   // viewport pan before LOD (to restore on exit)
  var _preLodZoom   = null;

  /* Sort jsons so every compound parent appears before its children.
     Edges come last.  Required for cy.add() to rebuild compounds. */
  function _sortForAdd(jsons) {
    var nodes = jsons.filter(function(e){ return e.group === 'nodes'; });
    var edges = jsons.filter(function(e){ return e.group === 'edges'; });
    var byId  = {};
    nodes.forEach(function(n){ byId[n.data.id] = n; });
    var sorted = [], seen = {};
    function visit(n) {
      if (seen[n.data.id]) return;
      if (n.data.parent && byId[n.data.parent]) visit(byId[n.data.parent]);
      sorted.push(n); seen[n.data.id] = true;
    }
    nodes.forEach(visit);
    return sorted.concat(edges);
  }

  function enterLOD(cy) {
    if (_lodActive) return;

    /* Bail if subnet-hub class not yet applied (graph not fully initialised) */
    var hubIds = {};
    cy.nodes('.subnet-hub, .bridge-node').forEach(function(n){ hubIds[n.id()] = true; });
    if (Object.keys(hubIds).length === 0) return;

    _lodActive    = true;
    _fullSnapshot = _sortForAdd(cy.elements().jsons());
    _preLodPan    = Object.assign({}, cy.pan());
    _preLodZoom   = cy.zoom();

    /* Collapsed view: keep domain boxes, subnet boxes, and one hub per subnet.
       Subnet/domain compound nodes stay so the layout remains structured —
       each box just shrinks to contain only its hub node.
       Hub nodes keep their parent reference so they sit inside their box.
       Bridge nodes (multi-homed, no parent) are kept as-is.
       Only inter-hub / bridge edges are kept. */
    var collapsed = [];
    cy.nodes('.domain-group').forEach(function(n) { collapsed.push(n.json()); });
    cy.nodes('.subnet-group').forEach(function(n) { collapsed.push(n.json()); });
    cy.nodes('.subnet-hub, .bridge-node').forEach(function(n) { collapsed.push(n.json()); });
    cy.edges().forEach(function(e) {
      if (hubIds[e.data('source')] && hubIds[e.data('target')]) collapsed.push(e.json());
    });

    cy.batch(function() {
      cy.elements().remove();
      cy.add(collapsed);
    });
  }

  function exitLOD(cy) {
    if (!_lodActive || !_fullSnapshot) return;
    _lodActive = false;
    var snap = _fullSnapshot; _fullSnapshot = null;
    cy.batch(function() {
      cy.elements().remove();
      cy.add(snap);
    });
  }

  function _checkLOD() {
    if (!_cy) return;
    var z = _cy.zoom();
    if (z < LOD_THRESHOLD && !_lodActive) enterLOD(_cy);
    else if (z >= LOD_THRESHOLD && _lodActive) exitLOD(_cy);
  }

  function _applyRenderer(cy) {
    var r = cy.renderer && cy.renderer();
    if (!r || !r.options) return;
    r.options.textureOnViewport   = true;
    r.options.hideEdgesOnViewport = true;
    r.options.motionBlur          = true;
    r.options.motionBlurOpacity   = 0.15;
    if ((window.devicePixelRatio || 1) > MAX_PIXEL_RATIO) {
      r.options.pixelRatio = MAX_PIXEL_RATIO;
      try { cy.resize(); } catch(_) {}
    }
  }

  /* Poll for _gravwell_cy (set by _CY_GLOBAL_JS ~1500ms after mount). */
  setInterval(function() {
    var cy = window._gravwell_cy;
    if (!cy || cy === _cy) return;
    _cy = cy; _lodActive = false; _fullSnapshot = null;
    _applyRenderer(cy);
    cy.on('zoom', _checkLOD);
    _checkLOD();
  }, 500);

  setInterval(_checkLOD, POLL_MS);
})();
"""

_CY_GLOBAL_JS = """
(function () {
  /* dash-cytoscape v1 stores the cy instance as this._cy (NOT this.cy).
     Walk the React fiber tree upward from the #network-graph container div
     until we find the component whose stateNode has ._cy, then cache it
     globally so the Save Layout callback can read positions reliably. */
  function findCy() {
    var el = document.getElementById('network-graph');
    if (!el) return null;
    var keys = Object.keys(el);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      if (k.startsWith('__reactFiber') || k.startsWith('__reactInternalInstance')) {
        var fiber = el[k];
        var depth = 0;
        while (fiber && depth < 30) {
          if (fiber.stateNode && fiber.stateNode._cy) return fiber.stateNode._cy;
          fiber = fiber.return;
          depth++;
        }
        break;
      }
    }
    return null;
  }

  /* ── Add-node context menu (canvas right-click) ── */
  var _ctxMenu = null;
  var _lastCy  = null;

  function showContextMenu(clientX, clientY) {
    if (!_ctxMenu) {
      _ctxMenu = document.createElement('div');
      _ctxMenu.style.cssText =
        'position:fixed;background:#1e1e1e;border:1px solid #555;border-radius:4px;' +
        'padding:4px 0;z-index:9999;display:none;min-width:155px;' +
        'box-shadow:0 4px 14px rgba(0,0,0,0.6);font-family:Segoe UI,monospace;';
      var item = document.createElement('div');
      item.textContent = '+ Add Node Here';
      item.style.cssText =
        'padding:7px 14px;font-size:12px;cursor:pointer;color:#ccc;';
      item.onmouseover = function() { item.style.background = '#2d2d2d'; };
      item.onmouseout  = function() { item.style.background = ''; };
      item.onclick = function() {
        _ctxMenu.style.display = 'none';
        var inp = document.getElementById('_add-node-js-trigger');
        if (inp && window._gravwell_add_pos) {
          var setter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype, 'value');
          if (setter && setter.set) {
            var payload = Object.assign({}, window._gravwell_add_pos,
                                        { _t: Date.now() });
            setter.set.call(inp, JSON.stringify(payload));
            inp.dispatchEvent(new Event('input', { bubbles: true }));
          }
        }
      };
      _ctxMenu.appendChild(item);
      document.body.appendChild(_ctxMenu);
    }
    _ctxMenu.style.display = 'block';
    var mw = 160, mh = 36;
    _ctxMenu.style.left = Math.min(clientX, window.innerWidth  - mw) + 'px';
    _ctxMenu.style.top  = Math.min(clientY, window.innerHeight - mh) + 'px';
  }

  /* ── Delete-node context menu (host node right-click) ── */
  var _delMenu = null;

  function _fireInput(id, value) {
    var inp = document.getElementById(id);
    if (!inp) return;
    var setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value');
    if (setter && setter.set) {
      setter.set.call(inp, value);
      inp.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  function showDeleteMenu(clientX, clientY, rightClickedIp) {
    if (!_delMenu) {
      _delMenu = document.createElement('div');
      _delMenu.style.cssText =
        'position:fixed;background:#1e1e1e;border:1px solid #555;border-radius:4px;' +
        'padding:4px 0;z-index:9999;display:none;min-width:175px;' +
        'box-shadow:0 4px 14px rgba(0,0,0,0.6);font-family:Segoe UI,monospace;';
      document.body.appendChild(_delMenu);
    }
    _delMenu.innerHTML = '';

    /* Collect all selected host IPs — if none are selected just use the
       right-clicked node.  This means a right-click on an unselected node
       still works as a single-node delete without forcing a selection first. */
    var cy = window._gravwell_cy;
    var selectedIps = [];
    if (cy) {
      cy.nodes(':selected').forEach(function(n) {
        if (n.data('node_type') === 'host' && n.data('ip'))
          selectedIps.push(n.data('ip'));
      });
    }
    /* If the right-clicked node isn't in the selection (or nothing selected),
       treat this as a single-node operation on just that IP. */
    if (selectedIps.indexOf(rightClickedIp) === -1) {
      selectedIps = [rightClickedIp];
    }

    var isBulk = selectedIps.length > 1;
    var label  = isBulk
      ? 'Delete ' + selectedIps.length + ' selected hosts'
      : 'Delete ' + rightClickedIp;
    var confirmMsg = isBulk
      ? 'Delete ' + selectedIps.length + ' hosts and all their data?\\n\\nThis cannot be undone.'
      : 'Delete host ' + rightClickedIp + ' and all its data?\\n\\nThis cannot be undone.';

    var item = document.createElement('div');
    item.style.cssText = 'padding:7px 14px;font-size:12px;cursor:pointer;color:#E74C3C;';
    item.textContent = label;
    item.onmouseover = function() { item.style.background = '#2d2d2d'; };
    item.onmouseout  = function() { item.style.background = ''; };
    item.onclick = function() {
      _delMenu.style.display = 'none';
      if (!confirm(confirmMsg)) return;
      if (isBulk) {
        _fireInput('_delete-nodes-bulk-trigger',
                   JSON.stringify({ ips: selectedIps, _t: Date.now() }));
      } else {
        _fireInput('_delete-node-js-trigger',
                   JSON.stringify({ ip: rightClickedIp, _t: Date.now() }));
      }
    };
    _delMenu.appendChild(item);
    _delMenu.style.display = 'block';
    var mw = 180, mh = 36;
    _delMenu.style.left = Math.min(clientX, window.innerWidth  - mw) + 'px';
    _delMenu.style.top  = Math.min(clientY, window.innerHeight - mh) + 'px';
  }

  document.addEventListener('click', function() {
    if (_ctxMenu)  _ctxMenu.style.display  = 'none';
    if (_delMenu)  _delMenu.style.display   = 'none';
  }, false);

  /* ── Path-table host cell click → focus graph node ──
     CSS rule ".g-host-link * { pointer-events: none }" ensures e.target IS
     the g-host-link element, so the walk is just a safety fallback. */
  document.addEventListener('click', function(e) {
    var el = e.target;
    for (var i = 0; i < 5 && el && el.tagName !== 'BODY'; i++) {
      if (el.classList && el.classList.contains('g-host-link') && el.title) {
        var inp = document.getElementById('_path-host-focus-trigger');
        if (inp) {
          var setter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype, 'value');
          if (setter && setter.set) {
            setter.set.call(inp, JSON.stringify({ip: el.title, _t: Date.now()}));
            inp.dispatchEvent(new Event('input', {bubbles: true}));
          }
        }
        return;
      }
      el = el.parentElement;
    }
  }, false);

  document.addEventListener('keydown', function(e) {
    if (e.key !== 'Escape') return;
    if (_ctxMenu) _ctxMenu.style.display = 'none';
    if (_delMenu) _delMenu.style.display  = 'none';
  }, false);

  setInterval(function () {
    var cy = findCy();
    if (cy) {
      if (cy !== _lastCy) {
        _lastCy = cy;
        /* ── Auto-save positions 800 ms after a node drag ends ── */
        var _dragTimer = null;
        cy.on('dragfree', function(evt) {
          if (!evt.target.isNode || !evt.target.isNode()) return;
          if (evt.target.data('node_type') !== 'host') return;
          clearTimeout(_dragTimer);
          _dragTimer = setTimeout(function() {
            var inp = document.getElementById('_autosave-positions-trigger');
            if (inp) {
              var setter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value');
              if (setter && setter.set) {
                setter.set.call(inp, 'drag_' + Date.now());
                inp.dispatchEvent(new Event('input', {bubbles: true}));
              }
            }
          }, 800);
        });

        cy.on('cxttap', function(evt) {
          if (evt.target === cy) {
            /* Empty canvas right-click → Add Node */
            window._gravwell_add_pos = {
              x: Math.round(evt.position.x),
              y: Math.round(evt.position.y),
            };
            showContextMenu(
              evt.originalEvent.clientX,
              evt.originalEvent.clientY
            );
          } else if (evt.target !== cy && evt.target.isNode &&
                     evt.target.isNode() &&
                     evt.target.data('node_type') === 'host') {
            /* Host node right-click → Delete Node */
            if (_ctxMenu) _ctxMenu.style.display = 'none';
            showDeleteMenu(
              evt.originalEvent.clientX,
              evt.originalEvent.clientY,
              evt.target.data('ip')
            );
          }
        });
      }
      window._gravwell_cy = cy;
    }
  }, 1500);

  /* Reset the save-layout-status animation each time its text changes
     so the flash plays on every save, not just the first one. */
  function attachStatusObserver() {
    var el = document.getElementById('save-layout-status');
    if (!el) { setTimeout(attachStatusObserver, 500); return; }
    new MutationObserver(function () {
      el.style.animation = 'none';
      void el.offsetHeight; // force reflow
      el.style.animation = '';
    }).observe(el, { childList: true, subtree: true, characterData: true });
  }
  attachStatusObserver();
})();
"""

_RESIZE_JS = """
(function () {
  /* Use event delegation on document so this works even though
     Dash/React renders elements after DOMContentLoaded fires. */
  var activeHandle = null;
  var startCoord = 0;
  var startSize  = 0;

  document.addEventListener('mousedown', function (e) {
    var id = e.target && e.target.id;
    if (id === 'vertical-resize-handle') {
      e.preventDefault();
      var target = document.getElementById('right-panel');
      if (!target) return;
      activeHandle = 'v';
      startCoord   = e.clientX;
      startSize    = target.offsetWidth;
      e.target.classList.add('dragging');
      document.body.style.cursor    = 'ew-resize';
      document.body.style.userSelect = 'none';
    } else if (id === 'horizontal-resize-handle') {
      e.preventDefault();
      var target = document.getElementById('bottom-panel');
      if (!target) return;
      activeHandle = 'h';
      startCoord   = e.clientY;
      startSize    = target.offsetHeight;
      e.target.classList.add('dragging');
      document.body.style.cursor    = 'ns-resize';
      document.body.style.userSelect = 'none';
    }
  });

  document.addEventListener('mousemove', function (e) {
    if (!activeHandle) return;
    if (activeHandle === 'v') {
      var target = document.getElementById('right-panel');
      if (!target) return;
      var w = Math.max(150, startSize - (e.clientX - startCoord));
      target.style.width = w + 'px';
      target.style.flex  = 'none';
    } else {
      var target = document.getElementById('bottom-panel');
      if (!target) return;
      var h = Math.max(60, startSize - (e.clientY - startCoord));
      target.style.height = h + 'px';
      target.style.flex   = 'none';
    }
  });

  document.addEventListener('mouseup', function () {
    if (!activeHandle) return;
    var hid = activeHandle === 'v' ? 'vertical-resize-handle'
                                   : 'horizontal-resize-handle';
    var handle = document.getElementById(hid);
    if (handle) handle.classList.remove('dragging');
    activeHandle = null;
    document.body.style.cursor     = '';
    document.body.style.userSelect = '';
  });
})();
"""


def create_app(db_path: str) -> dash.Dash:
    app = dash.Dash(
        __name__,
        title="GravWell",
        update_title=None,
        suppress_callback_exceptions=True,
    )

    app.server.config["GRAVWELL_DB_PATH"] = db_path

    from gravwell.auth import init_auth
    init_auth(app.server, db_path)

    # Pre-load MEK from the server key file so agent submissions work
    # immediately after a restart, without requiring a browser login first.
    from gravwell.keystore import load_server_mek
    _startup_mek = load_server_mek(db_path)
    if _startup_mek is not None:
        app.server.config["GRAVWELL_MEK"] = _startup_mek

    # Register agent API routes
    from gravwell.ui.api import api_bp
    app.server.register_blueprint(api_bp)

    # Generate agent API token on first run and print it to the console
    from gravwell.database import ensure_agent_token
    new_token = ensure_agent_token(db_path)
    if new_token:
        print("\n" + "=" * 60)
        print("  GravWell Agent API Token (shown once — store it safely)")
        print(f"  {new_token}")
        print("  Use with: python collect.py --server <URL> --key <TOKEN>")
        print("=" * 60 + "\n")

    # Allow large scan file uploads (Nessus/CrowdStrike exports can be 100MB+).
    # dcc.Upload base64-encodes files in the browser (~33% overhead), so a
    # 750 MB original file becomes ~1 GB on the wire.
    app.server.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GB

    # Return a proper JSON 413 so the browser doesn't just see a closed connection
    from flask import jsonify

    @app.server.errorhandler(413)
    def _too_large(_e):
        return jsonify(error="File too large — maximum upload is ~750 MB"), 413

    app.layout = create_layout()
    app.index_string = app.index_string.replace(
        "</head>",
        f'<link rel="icon" type="image/svg+xml" href="{_FAVICON_URI}"><style>{_APP_CSS}</style></head>',
    ).replace(
        "</body>",
        f"<script>{_RESIZE_JS}</script><script>{_LARGE_FILE_JS}</script><script>{_CY_GLOBAL_JS}</script><script>{_CYTO_PERF_JS}</script></body>",
    )

    # Register all callbacks
    graph_callbacks.register(app)
    import_callbacks.register(app)
    path_callbacks.register(app)
    filter_callbacks.register(app)
    project_callbacks.register(app)
    edit_callbacks.register(app)
    discovery_callbacks.register(app)
    edge_callbacks.register(app)
    subnet_callbacks.register(app)
    config_callbacks.register(app)
    enrich_callbacks.register(app)
    browse_callbacks.register(app)
    add_node_callbacks.register(app)
    settings_callbacks.register(app)
    export_callbacks.register(app)

    # Clientside callback: watch export-png-dummy store and trigger PNG download
    app.clientside_callback(
        """function(store_data) {
            if (!store_data) return window.dash_clientside.no_update;
            var cy = window._gravwell_cy;
            if (!cy) return window.dash_clientside.no_update;
            try {
                // Export full graph at natural scale so text is sharp.
                // Cap scale so canvas stays under ~200 MP (Chrome limit ~268 MP).
                var bb = cy.elements().boundingBox();
                var area = (bb.w || 1) * (bb.h || 1);
                var scale = Math.min(1, Math.sqrt(200 * 1024 * 1024 / area));
                function doExport(s) {
                    cy.png({output: 'blob-promise', scale: s, full: true, bg: '#121212'})
                      .then(function(blob) {
                        if (!blob || blob.size === 0) {
                            // Canvas too large even at this scale — halve and retry once
                            if (s > 0.1) { doExport(s / 2); }
                            else { console.error('PNG export: canvas too large to export'); }
                            return;
                        }
                        var blobUrl = URL.createObjectURL(blob);
                        var a = document.createElement('a');
                        a.href = blobUrl;
                        var ts = new Date().toISOString().replace(/[-:T]/g,'').slice(0,15);
                        a.download = 'network-map_' + ts + '.png';
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        setTimeout(function(){ URL.revokeObjectURL(blobUrl); }, 2000);
                      })
                      .catch(function(e) { console.error('PNG export failed:', e); });
                }
                doExport(scale);
            } catch(e) { console.error('PNG export failed:', e); }
            return window.dash_clientside.no_update;
        }""",
        dash.Output("export-png-dummy", "data", allow_duplicate=True),
        dash.Input("export-png-dummy", "data"),
        prevent_initial_call=True,
    )

    return app
