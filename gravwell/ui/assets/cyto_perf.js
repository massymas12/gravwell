/**
 * Runtime performance patches for the Cytoscape graph.
 *
 * textureOnViewport  — pan/zoom renders to a cached bitmap.
 * hideEdgesOnViewport — suppresses edge rendering during pan/zoom.
 * motionBlur         — subtle trail masking lower effective framerates.
 * GPU compositing    — translateZ(0) promotes canvases to GPU layers.
 * pixelRatio clamp   — 1.5× cap on HiDPI screens (~44 % less GPU fill).
 *
 * LOD collapsing     — below LOD_THRESHOLD zoom, non-hub host nodes and
 *                      intra-subnet edges are hidden by adding the
 *                      .lod-hidden class (which maps to display:none in the
 *                      Python stylesheet).  Using addClass/removeClass rather
 *                      than direct style() calls means the state survives
 *                      Dash element prop updates.
 */
(function () {
    'use strict';

    var CONTAINER_ID    = 'network-graph';
    var MAX_PIXEL_RATIO = 1.5;
    var LOD_THRESHOLD   = 0.6;
    var POLL_MS         = 300;

    var _cy        = null;
    var _lodActive = false;

    function gpuPromote(el) {
        el.style.willChange = 'transform';
        el.style.transform  = 'translateZ(0)';
    }

    // ── LOD ───────────────────────────────────────────────────────────────────
    // .lod-hidden { display: none } is declared in the Python stylesheet so
    // Cytoscape owns the rule.  We only add/remove the class here.

    function enterLOD(cy) {
        if (_lodActive) return;
        _lodActive = true;
        cy.batch(function () {
            // Regular hosts that are not hubs or bridge nodes
            cy.nodes('.host:not(.subnet-hub):not(.bridge-node)').addClass('lod-hidden');
            // Intra-subnet spoke edges
            cy.edges('.intra-subnet').addClass('lod-hidden');
            // Compound box outlines (hiding parent does NOT cascade to children
            // in Cytoscape, so hub nodes stay visible)
            cy.nodes('.subnet-group, .domain-group').addClass('lod-hidden');
        });
    }

    function exitLOD(cy) {
        if (!_lodActive) return;
        _lodActive = false;
        cy.batch(function () {
            cy.elements().removeClass('lod-hidden');
        });
    }

    function _checkLOD() {
        if (!_cy) return;
        var zoom = _cy.zoom();
        if (zoom < LOD_THRESHOLD && !_lodActive) {
            enterLOD(_cy);
        } else if (zoom >= LOD_THRESHOLD && _lodActive) {
            exitLOD(_cy);
        }
    }

    // ── Renderer perf options ─────────────────────────────────────────────────

    function _applyRendererOptions(cy) {
        var r = cy.renderer && cy.renderer();
        if (!r || !r.options) return;
        r.options.textureOnViewport   = true;
        r.options.hideEdgesOnViewport = true;
        r.options.motionBlur          = true;
        r.options.motionBlurOpacity   = 0.15;

        var deviceRatio = window.devicePixelRatio || 1;
        if (deviceRatio > MAX_PIXEL_RATIO) {
            r.options.pixelRatio = MAX_PIXEL_RATIO;
            try { cy.resize(); } catch (_) {}
        }
    }

    // ── Main patch ────────────────────────────────────────────────────────────

    function patch() {
        var container = document.getElementById(CONTAINER_ID);
        if (!container) return false;

        gpuPromote(container);

        var cyreg = container._cyreg;
        if (!cyreg || !cyreg.cy) return false;

        var cy = cyreg.cy;

        _applyRendererOptions(cy);
        container.querySelectorAll('canvas').forEach(gpuPromote);

        if (_cy !== cy) {
            if (_cy) _cy.off('zoom', _checkLOD);
            _cy        = cy;
            _lodActive = false;
            cy.on('zoom', _checkLOD);
            // Run an immediate check in case we're already zoomed out
            _checkLOD();
        }

        return true;
    }

    // Startup poll — waits for Cytoscape to mount
    var attempts = 0;
    var initTimer = setInterval(function () {
        if (patch() || attempts++ > 80) clearInterval(initTimer);
    }, 75);

    // Ongoing zoom poll — fallback in case the zoom event misses a change
    setInterval(_checkLOD, POLL_MS);

    // Only re-patch when the graph container itself is (re)mounted, not on
    // every Dash DOM update.  This prevents _lodActive being reset on each
    // callback response.
    var observer = new MutationObserver(function (mutations) {
        for (var i = 0; i < mutations.length; i++) {
            var added = mutations[i].addedNodes;
            for (var j = 0; j < added.length; j++) {
                var n = added[j];
                if (n.nodeType !== 1) continue;
                if (n.id === CONTAINER_ID ||
                    (n.querySelector && n.querySelector('#' + CONTAINER_ID))) {
                    _lodActive = false;
                    patch();
                    return;
                }
            }
        }
    });
    observer.observe(document.body, { childList: true, subtree: true });
})();
