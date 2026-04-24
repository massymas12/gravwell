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
 *                      intra-subnet edges are hidden; subnet/domain compound
 *                      boxes are also hidden so only hub nodes remain,
 *                      connected by inter-hub edges.
 */
(function () {
    'use strict';

    var CONTAINER_ID    = 'network-graph';
    var MAX_PIXEL_RATIO = 1.5;
    var LOD_THRESHOLD   = 0.6;   // zoom level below which subnets collapse
    var LOD_DEBOUNCE_MS = 150;

    var _cy        = null;
    var _lodActive = false;
    var _lodTimer  = null;

    function gpuPromote(el) {
        el.style.willChange = 'transform';
        el.style.transform  = 'translateZ(0)';
    }

    // ── LOD ───────────────────────────────────────────────────────────────────

    function enterLOD(cy) {
        if (_lodActive) return;
        _lodActive = true;
        cy.batch(function () {
            cy.nodes('.host:not(.subnet-hub):not(.bridge-node)').hide();
            cy.edges('.intra-subnet').hide();
            // Hiding compound parents does NOT cascade to children in Cytoscape,
            // so hub nodes stay visible while the box outlines disappear.
            cy.nodes('.subnet-group, .domain-group').hide();
        });
    }

    function exitLOD(cy) {
        if (!_lodActive) return;
        _lodActive = false;
        cy.batch(function () {
            cy.elements().show();
        });
    }

    function _onZoom() {
        if (!_cy) return;
        clearTimeout(_lodTimer);
        var zoom = _cy.zoom();
        _lodTimer = setTimeout(function () {
            if (zoom < LOD_THRESHOLD) {
                enterLOD(_cy);
            } else {
                exitLOD(_cy);
            }
        }, LOD_DEBOUNCE_MS);
    }

    // ── Renderer perf options (best-effort — missing renderer is non-fatal) ──

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

        // Renderer options are best-effort; failure must not block LOD setup.
        _applyRendererOptions(cy);

        container.querySelectorAll('canvas').forEach(gpuPromote);

        // Register zoom listener once per cy instance.
        if (_cy !== cy) {
            if (_cy) {
                _cy.off('zoom', _onZoom);
                _lodActive = false;
                clearTimeout(_lodTimer);
            }
            _cy = cy;
            cy.on('zoom', _onZoom);
        }

        return true;
    }

    var attempts = 0;
    var timer = setInterval(function () {
        if (patch() || attempts++ > 80) clearInterval(timer);
    }, 75);

    var observer = new MutationObserver(function (mutations) {
        for (var i = 0; i < mutations.length; i++) {
            if (mutations[i].addedNodes.length) {
                _lodActive = false;
                clearTimeout(_lodTimer);
                patch();
                break;
            }
        }
    });
    observer.observe(document.body, { childList: true, subtree: true });
})();
