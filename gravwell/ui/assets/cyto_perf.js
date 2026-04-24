/**
 * Runtime performance patches for the Cytoscape graph.
 *
 * dash-cytoscape 1.0.2 does not expose Cytoscape.js renderer options as React
 * props, so we set them directly on the renderer object after mount.
 *
 * textureOnViewport  — pan/zoom renders to a cached bitmap; only redraws from
 *                      scratch when motion stops.  Biggest single win for lag.
 *
 * hideEdgesOnViewport — suppresses edge rendering entirely during pan/zoom.
 *                       Cuts per-frame work roughly in half on edge-heavy maps.
 *
 * motionBlur         — subtle trail that masks lower effective framerates.
 *
 * GPU compositing    — translateZ(0) on each canvas element promotes it to a
 *                      dedicated GPU layer so the compositor can blit without
 *                      CPU rasterisation every frame.
 *
 * pixelRatio clamp   — on HiDPI / Retina screens Cytoscape renders at 2× by
 *                      default (4× the pixels).  Clamping to 1.5 cuts GPU
 *                      fill cost by ~44 % with minimal visible quality loss.
 */
(function () {
    'use strict';

    var CONTAINER_ID  = 'network-graph';
    var MAX_PIXEL_RATIO = 1.5;   // clamp; raise to 2 if you want full retina

    function gpuPromote(el) {
        el.style.willChange = 'transform';
        el.style.transform  = 'translateZ(0)';
    }

    function patch() {
        var container = document.getElementById(CONTAINER_ID);
        if (!container) return false;

        // Promote container itself immediately — canvases may not exist yet
        gpuPromote(container);

        // Cytoscape stores the instance in _cyreg on the container element
        var cyreg = container._cyreg;
        if (!cyreg || !cyreg.cy) return false;

        var cy = cyreg.cy;
        var r  = cy.renderer && cy.renderer();
        if (!r || !r.options) return false;

        // ── Renderer options ─────────────────────────────────────────────
        r.options.textureOnViewport   = true;
        r.options.hideEdgesOnViewport = true;
        r.options.motionBlur          = true;
        r.options.motionBlurOpacity   = 0.15;

        // ── Pixel-ratio clamp ────────────────────────────────────────────
        // Cytoscape reads pixelRatio from r.options at canvas resize time.
        // Calling cy.resize() after setting it re-initialises the canvases.
        var deviceRatio = window.devicePixelRatio || 1;
        if (deviceRatio > MAX_PIXEL_RATIO) {
            r.options.pixelRatio = MAX_PIXEL_RATIO;
            try { cy.resize(); } catch (_) {}
        }

        // ── GPU-promote every canvas layer ───────────────────────────────
        // Cytoscape creates 3-4 <canvas> elements (edges, nodes, drag, select).
        // Each gets its own compositor layer so pan/zoom is pure GPU blitting.
        container.querySelectorAll('canvas').forEach(gpuPromote);

        return true;
    }

    // Poll until the Cytoscape instance is ready (React mounts async)
    var attempts = 0;
    var timer = setInterval(function () {
        if (patch() || attempts++ > 80) clearInterval(timer);
    }, 75);

    // Re-apply if Dash ever remounts the component (e.g. layout switch)
    var observer = new MutationObserver(function (mutations) {
        for (var i = 0; i < mutations.length; i++) {
            if (mutations[i].addedNodes.length) { patch(); break; }
        }
    });
    observer.observe(document.body, { childList: true, subtree: true });
})();
