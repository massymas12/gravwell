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
 *                      intra-subnet edges are removed from the render pass
 *                      (display:none) and subnet/domain compound boxes are
 *                      hidden, leaving only hub nodes + inter-hub edges.
 */
(function () {
    'use strict';

    var CONTAINER_ID    = 'network-graph';
    var MAX_PIXEL_RATIO = 1.5;
    var LOD_THRESHOLD   = 0.6;
    var POLL_MS         = 300;  // zoom-poll interval (fallback + primary driver)

    var _cy        = null;
    var _lodActive = false;

    function gpuPromote(el) {
        el.style.willChange = 'transform';
        el.style.transform  = 'translateZ(0)';
    }

    // ── LOD ───────────────────────────────────────────────────────────────────
    // Use display:'none' / display:'element' rather than hide()/show().
    // display:none removes elements from the Cytoscape render pass entirely;
    // hide() only sets visibility:hidden which still draws to the canvas.

    function enterLOD(cy) {
        if (_lodActive) return;
        _lodActive = true;
        cy.batch(function () {
            cy.nodes('.host:not(.subnet-hub):not(.bridge-node)').style('display', 'none');
            cy.edges('.intra-subnet').style('display', 'none');
            // Hiding the compound shells does not cascade to children in Cytoscape,
            // so hub nodes stay visible while the box outlines vanish.
            cy.nodes('.subnet-group, .domain-group').style('display', 'none');
        });
    }

    function exitLOD(cy) {
        if (!_lodActive) return;
        _lodActive = false;
        cy.batch(function () {
            cy.elements().style('display', 'element');
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

    // ── Renderer perf options (best-effort) ──────────────────────────────────

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
            if (_cy) {
                _cy.off('zoom', _checkLOD);
                _lodActive = false;
            }
            _cy = cy;
            // Event listener for responsiveness + polling interval as fallback
            cy.on('zoom', _checkLOD);
        }

        return true;
    }

    // Startup poll — waits for Cytoscape to mount
    var attempts = 0;
    var initTimer = setInterval(function () {
        if (patch() || attempts++ > 80) clearInterval(initTimer);
    }, 75);

    // Ongoing poll — catches zoom changes even if the event doesn't fire
    setInterval(_checkLOD, POLL_MS);

    // Re-patch on Dash remounts
    var observer = new MutationObserver(function (mutations) {
        for (var i = 0; i < mutations.length; i++) {
            if (mutations[i].addedNodes.length) {
                _lodActive = false;
                patch();
                break;
            }
        }
    });
    observer.observe(document.body, { childList: true, subtree: true });
})();
