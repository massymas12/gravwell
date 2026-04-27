/* cyto_perf.js — loaded */
console.log('[cyto_perf] script loaded');

(function () {
    'use strict';

    var CONTAINER_ID    = 'network-graph';
    var MAX_PIXEL_RATIO = 1.5;
    var LOD_THRESHOLD   = 0.6;
    var POLL_MS         = 300;

    var _cy           = null;
    var _lodActive    = false;
    var _fullSnapshot = null;
    var _diagnosed    = false;

    function gpuPromote(el) {
        el.style.willChange = 'transform';
        el.style.transform  = 'translateZ(0)';
    }

    // ── Find Cytoscape instance ───────────────────────────────────────────────
    // Method 1: internal _cyreg (Cytoscape <= 3.x standard).
    // Method 2: walk the React fiber tree to find dash-cytoscape's stateNode.cy
    function _findCy(container) {
        if (container._cyreg && container._cyreg.cy) return container._cyreg.cy;

        var fiberKey = Object.keys(container).find(function (k) {
            return k.startsWith('__reactFiber') || k.startsWith('__reactInternalInstance');
        });
        if (!fiberKey) return null;

        var node = container[fiberKey];
        while (node) {
            if (node.stateNode &&
                typeof node.stateNode === 'object' &&
                node.stateNode.cy &&
                typeof node.stateNode.cy.zoom === 'function') {
                return node.stateNode.cy;
            }
            node = node.return || null;
        }
        return null;
    }

    // ── Snapshot helpers ──────────────────────────────────────────────────────
    function _sortForAdd(jsons) {
        var nodes = jsons.filter(function (e) { return e.group === 'nodes'; });
        var edges = jsons.filter(function (e) { return e.group === 'edges'; });
        var byId  = {};
        nodes.forEach(function (n) { byId[n.data.id] = n; });
        var sorted = [];
        var seen   = {};
        function visit(n) {
            if (seen[n.data.id]) return;
            if (n.data.parent && byId[n.data.parent]) visit(byId[n.data.parent]);
            sorted.push(n);
            seen[n.data.id] = true;
        }
        nodes.forEach(visit);
        return sorted.concat(edges);
    }

    // ── LOD ───────────────────────────────────────────────────────────────────
    function enterLOD(cy) {
        if (_lodActive) return;
        _lodActive    = true;
        _fullSnapshot = _sortForAdd(cy.elements().jsons());

        var hubIds = {};
        cy.nodes('.subnet-hub, .bridge-node').forEach(function (n) { hubIds[n.id()] = true; });

        var collapsed = [];
        cy.nodes('.subnet-hub, .bridge-node').forEach(function (n) {
            var j = n.json();
            var d = Object.assign({}, j.data);
            delete d.parent;
            collapsed.push({ group: 'nodes', data: d, classes: j.classes, position: j.position });
        });
        cy.edges().forEach(function (e) {
            if (hubIds[e.data('source')] && hubIds[e.data('target')]) {
                collapsed.push(e.json());
            }
        });

        console.log('[cyto_perf] LOD enter — zoom:', cy.zoom().toFixed(3),
                    '| full:', _fullSnapshot.length,
                    '| collapsed:', collapsed.length,
                    '| hubs:', Object.keys(hubIds).length);

        cy.batch(function () {
            cy.elements().remove();
            if (collapsed.length) cy.add(collapsed);
        });
    }

    function exitLOD(cy) {
        if (!_lodActive || !_fullSnapshot) return;
        console.log('[cyto_perf] LOD exit — zoom:', cy.zoom().toFixed(3));
        _lodActive    = false;
        var snap      = _fullSnapshot;
        _fullSnapshot = null;
        cy.batch(function () {
            cy.elements().remove();
            cy.add(snap);
        });
    }

    function _checkLOD() {
        if (!_cy) return;
        var zoom = _cy.zoom();
        if (zoom < LOD_THRESHOLD && !_lodActive) enterLOD(_cy);
        else if (zoom >= LOD_THRESHOLD && _lodActive) exitLOD(_cy);
    }

    // ── Renderer options ──────────────────────────────────────────────────────
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

        var cy = _findCy(container);

        if (!cy) {
            if (!_diagnosed) {
                _diagnosed = true;
                var keys = Object.keys(container).filter(function (k) {
                    return k.startsWith('_') || k.startsWith('__react');
                });
                console.log('[cyto_perf] container found but cy not resolved.',
                            'Container keys:', keys.join(', ') || '(none)');
            }
            return false;
        }

        if (!_diagnosed) {
            _diagnosed = true;
            console.log('[cyto_perf] cy found via', container._cyreg ? '_cyreg' : 'React fiber',
                        '| zoom:', cy.zoom().toFixed(3),
                        '| elements:', cy.elements().length,
                        '| .subnet-hub nodes:', cy.nodes('.subnet-hub').length);
        }

        _applyRendererOptions(cy);
        container.querySelectorAll('canvas').forEach(gpuPromote);

        if (_cy !== cy) {
            if (_cy) _cy.off('zoom', _checkLOD);
            _cy           = cy;
            _lodActive    = false;
            _fullSnapshot = null;
            cy.on('zoom', _checkLOD);
            _checkLOD();
        }

        return true;
    }

    var attempts = 0;
    var initTimer = setInterval(function () {
        if (patch() || attempts++ > 80) {
            if (attempts > 80 && !_cy) console.log('[cyto_perf] gave up — cy never found after 80 attempts');
            clearInterval(initTimer);
        }
    }, 75);

    setInterval(_checkLOD, POLL_MS);

    var observer = new MutationObserver(function (mutations) {
        for (var i = 0; i < mutations.length; i++) {
            var added = mutations[i].addedNodes;
            for (var j = 0; j < added.length; j++) {
                var n = added[j];
                if (n.nodeType !== 1) continue;
                if (n.id === CONTAINER_ID ||
                    (n.querySelector && n.querySelector('#' + CONTAINER_ID))) {
                    _lodActive    = false;
                    _fullSnapshot = null;
                    _diagnosed    = false;
                    patch();
                    return;
                }
            }
        }
    });
    observer.observe(document.body, { childList: true, subtree: true });
})();
