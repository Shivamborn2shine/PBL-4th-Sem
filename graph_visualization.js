/**
 * Observe4U – Graph Visualization Module
 *
 * D3.js force-directed graph for visualizing threat intelligence relationships.
 * Nodes: USER (cyan), DOMAIN (red), IP (amber), EMAIL (purple)
 * Edges: scanned, resolves_to, associated_with
 */

// ═══════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════

const GRAPH_CONFIG = {
    colors: {
        USER: '#06b6d4',
        DOMAIN: '#ef4444',
        IP: '#f59e0b',
        EMAIL: '#8b5cf6',
    },
    nodeSize: {
        USER: 18,
        DOMAIN: 22,
        IP: 16,
        EMAIL: 16,
    },
    shapes: {
        USER: 'circle',
        DOMAIN: 'square',
        IP: 'diamond',
        EMAIL: 'triangle',
    },
    linkColors: {
        scanned: 'rgba(6, 182, 212, 0.4)',
        resolves_to: 'rgba(245, 158, 11, 0.4)',
        associated_with: 'rgba(139, 92, 246, 0.4)',
    },
    icons: {
        USER: '👤',
        DOMAIN: '🌐',
        IP: '📡',
        EMAIL: '📧',
    },
};

// ═══════════════════════════════════════════════════════════════════
// Graph Rendering
// ═══════════════════════════════════════════════════════════════════

function renderGraph(graphData) {
    const container = document.getElementById('graph-viz');
    if (!container) return;

    // Clear existing
    container.innerHTML = '';

    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
        container.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: center; height: 100%;
                        color: #64748b; font-size: 0.9rem; flex-direction: column; gap: 0.8rem;">
                <span style="font-size: 3rem; opacity: 0.4;">🕸️</span>
                <span>Graph will populate as you scan URLs and emails</span>
            </div>
        `;
        return;
    }

    const width = container.clientWidth;
    const height = container.clientHeight || 450;

    // ── Create SVG ───────────────────────────────────────────────
    const svg = d3.select('#graph-viz')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .style('border-radius', '10px');

    // Gradient definitions
    const defs = svg.append('defs');

    // Glow filter
    const glowFilter = defs.append('filter')
        .attr('id', 'glow')
        .attr('x', '-50%').attr('y', '-50%')
        .attr('width', '200%').attr('height', '200%');
    glowFilter.append('feGaussianBlur')
        .attr('stdDeviation', '3')
        .attr('result', 'coloredBlur');
    const feMerge = glowFilter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // ── Zoom behavior ────────────────────────────────────────────
    const graphGroup = svg.append('g');

    const zoom = d3.zoom()
        .scaleExtent([0.3, 4])
        .on('zoom', (event) => {
            graphGroup.attr('transform', event.transform);
        });

    svg.call(zoom);

    // ── Prepare data ─────────────────────────────────────────────
    const nodes = graphData.nodes.map(n => ({ ...n }));
    const edges = graphData.edges.map(e => ({
        source: typeof e.source === 'object' ? e.source.id : e.source,
        target: typeof e.target === 'object' ? e.target.id : e.target,
        relation: e.relation,
    }));

    // Filter edges to only include existing nodes
    const nodeIds = new Set(nodes.map(n => n.id));
    const validEdges = edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));

    // ── Force simulation ─────────────────────────────────────────
    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(validEdges).id(d => d.id).distance(120))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(40));

    // ── Draw edges ───────────────────────────────────────────────
    const linkGroup = graphGroup.append('g').attr('class', 'links');

    const link = linkGroup.selectAll('line')
        .data(validEdges)
        .enter()
        .append('line')
        .attr('stroke', d => GRAPH_CONFIG.linkColors[d.relation] || 'rgba(148, 163, 184, 0.2)')
        .attr('stroke-width', 2)
        .attr('stroke-dasharray', d => d.relation === 'resolves_to' ? '6,3' : 'none');

    // Edge labels
    const linkLabel = linkGroup.selectAll('text')
        .data(validEdges)
        .enter()
        .append('text')
        .text(d => d.relation)
        .attr('font-size', '9px')
        .attr('font-family', "'JetBrains Mono', monospace")
        .attr('fill', 'rgba(148, 163, 184, 0.5)')
        .attr('text-anchor', 'middle')
        .attr('dy', -6);

    // ── Draw nodes ───────────────────────────────────────────────
    const nodeGroup = graphGroup.append('g').attr('class', 'nodes');

    const node = nodeGroup.selectAll('g')
        .data(nodes)
        .enter()
        .append('g')
        .attr('cursor', 'pointer')
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded)
        );

    // Node circles/shapes
    node.each(function (d) {
        const group = d3.select(this);
        const color = GRAPH_CONFIG.colors[d.type] || '#64748b';
        const size = GRAPH_CONFIG.nodeSize[d.type] || 16;

        // Outer glow
        group.append('circle')
            .attr('r', size + 4)
            .attr('fill', color)
            .attr('opacity', 0.15)
            .attr('filter', 'url(#glow)');

        // Main node
        group.append('circle')
            .attr('r', size)
            .attr('fill', `${color}33`)
            .attr('stroke', color)
            .attr('stroke-width', 2);

        // Icon
        group.append('text')
            .text(GRAPH_CONFIG.icons[d.type] || '●')
            .attr('text-anchor', 'middle')
            .attr('dy', 5)
            .attr('font-size', `${size * 0.7}px`);
    });

    // Node labels
    node.append('text')
        .text(d => {
            const label = d.label || d.id;
            return label.length > 20 ? label.substring(0, 18) + '..' : label;
        })
        .attr('dy', d => (GRAPH_CONFIG.nodeSize[d.type] || 16) + 16)
        .attr('text-anchor', 'middle')
        .attr('font-size', '10px')
        .attr('font-family', "'JetBrains Mono', monospace")
        .attr('fill', '#94a3b8')
        .attr('font-weight', '500');

    // ── Tooltip on hover ─────────────────────────────────────────
    node.on('mouseover', function (event, d) {
        d3.select(this).select('circle:nth-child(2)')
            .transition().duration(200)
            .attr('stroke-width', 3)
            .attr('r', (GRAPH_CONFIG.nodeSize[d.type] || 16) + 3);
    })
        .on('mouseout', function (event, d) {
            d3.select(this).select('circle:nth-child(2)')
                .transition().duration(200)
                .attr('stroke-width', 2)
                .attr('r', GRAPH_CONFIG.nodeSize[d.type] || 16);
        });

    // ── Simulation tick ──────────────────────────────────────────
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        linkLabel
            .attr('x', d => (d.source.x + d.target.x) / 2)
            .attr('y', d => (d.source.y + d.target.y) / 2);

        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // ── Drag handlers ────────────────────────────────────────────
    function dragStarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragEnded(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
}
