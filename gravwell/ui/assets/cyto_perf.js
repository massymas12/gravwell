/**
 * Patches the Cytoscape renderer after it mounts to enable viewport-level
 * performance options that dash-cytoscape 1.0.2 doesn't expose as props.
 *
 * textureOnViewport  — during pan/zoom, render the graph to a bitmap and
 *                      just move/scale the texture.  Redraws from scratch only
 *                      after movement stops.  Eliminates the per-frame element
 *                      re-render that causes drag/pan lag on large graphs.
 *
 * hideEdgesOnViewport — hide all edges during pan/zoom (only nodes move).
 *                       Cuts render work roughly in half on edge-heavy graphs.
 *
 * motionBlur         — subtle trailing effect that makes motion feel smooth
 *                      even at lower effective framerates.
 */
(function () {
    var CONTAINER_ID = 'network-graph';

    function patch() {
        var el = document.getElementById(CONTAINER_ID);
        if (!el) return false;

        // Cytoscape.js stores the cy instance in _cyreg on the container element.
        var cyreg = el._cyreg;
        if (!cyreg || !cyreg.cy) return false;

        var cy = cyreg.cy;
        var r  = cy.renderer && cy.renderer();
        if (!r || !r.options) return false;

        r.options.textureOnViewport   = true;
        r.options.hideEdgesOnViewport = true;
        r.options.motionBlur          = true;
        r.options.motionBlurOpacity   = 0.15;

        return true;
    }

    // Cytoscape is mounted asynchronously by React/Dash.
    // Poll briefly until the instance is available, then stop.
    var attempts = 0;
    var timer = setInterval(function () {
        if (patch() || attempts++ > 60) {   // give up after ~6 s
            clearInterval(timer);
        }
    }, 100);

    // Re-apply whenever Dash replaces the element subtree (e.g. layout switch).
    // Using MutationObserver is cheap — no polling overhead after initial setup.
    var observer = new MutationObserver(function () {
        patch();
    });
    document.addEventListener('DOMContentLoaded', function () {
        var root = document.getElementById('network-graph') || document.body;
        observer.observe(root.parentNode || document.body,
                         { childList: true, subtree: false });
    });
})();
