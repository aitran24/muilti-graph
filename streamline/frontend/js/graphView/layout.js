(() => {
window.Streamline = window.Streamline || {};
const internals = window.Streamline.GraphViewInternals || {};
window.Streamline.GraphViewInternals = internals;

function reserveTierRange(tierRanges, tier, desiredStart, rowWidth, padding, minGap) {
  if (!tierRanges.has(tier)) {
    tierRanges.set(tier, []);
  }

  const ranges = tierRanges.get(tier);
  let start = Number.isFinite(desiredStart) ? desiredStart : 0;
  const width = Number.isFinite(rowWidth) ? Math.max(0, rowWidth) : 0;
  let guard = 0;

  while (true) {
    guard += 1;
    if (guard > 10000) {
      return start;
    }

    const min = start - padding;
    const max = start + width + padding;
    let shifted = false;

    for (const range of ranges) {
      const overlaps = !(max + minGap <= range.min || min - minGap >= range.max);
      if (!overlaps) {
        continue;
      }

      const delta = range.max + minGap - min;
      start += Math.max(1, delta);
      shifted = true;
      break;
    }

    if (!shifted) {
      ranges.push({ min, max });
      ranges.sort((a, b) => a.min - b.min);
      return start;
    }
  }
}

function layoutSubtreeWithDepthWrap(rootId, childrenMap, maxWidth) {
  const nodeSpacingX = 180;
  const tierUnitY = 100;
  const baseLevelStep = 2;
  const overflowStep = 2;
  const padding = 44;
  const minGap = 8;
  const maxCols = Math.max(2, Math.floor(maxWidth / nodeSpacingX));

  const queue = [{ nodeId: rootId, tier: 0, x: 0 }];
  const queued = new Set([rootId]);
  const positions = {};
  const maxIterations = 50000;
  let iterations = 0;

  while (queue.length) {
    iterations += 1;
    if (iterations > maxIterations) {
      break;
    }

    const current = queue.shift();
    queued.delete(current.nodeId);
    if (positions[current.nodeId]) {
      continue;
    }

    positions[current.nodeId] = {
      x: current.x,
      y: current.tier * tierUnitY,
    };

    const seenChildren = new Set();
    const orderedChildren = [];
    (childrenMap.get(current.nodeId) || []).forEach((childId) => {
      if (
        childId === current.nodeId ||
        seenChildren.has(childId) ||
        positions[childId] ||
        queued.has(childId)
      ) {
        return;
      }
      seenChildren.add(childId);
      orderedChildren.push(childId);
    });

    if (!orderedChildren.length) {
      continue;
    }

    const rowCount = Math.ceil(orderedChildren.length / maxCols);
    for (let row = 0; row < rowCount; row += 1) {
      const start = row * maxCols;
      const rowNodes = orderedChildren.slice(start, start + maxCols);
      const rowWidth = (rowNodes.length - 1) * nodeSpacingX;
      const desiredStartX = current.x - rowWidth / 2;
      const rowTier = current.tier + baseLevelStep + row * overflowStep;
      const adjustedStartX = desiredStartX;

      rowNodes.forEach((childId, colIndex) => {
        queued.add(childId);
        queue.push({
          nodeId: childId,
          tier: rowTier,
          x: adjustedStartX + colIndex * nodeSpacingX,
        });
      });
    }
  }

  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  Object.values(positions).forEach((pos) => {
    minX = Math.min(minX, pos.x - padding);
    minY = Math.min(minY, pos.y - padding);
    maxX = Math.max(maxX, pos.x + padding);
    maxY = Math.max(maxY, pos.y + padding);
  });

  if (!Number.isFinite(minX)) {
    minX = -padding;
    minY = -padding;
    maxX = padding;
    maxY = padding;
  }

  return {
    positions,
    nodes: new Set(Object.keys(positions)),
    width: Math.max(140, maxX - minX),
    height: Math.max(140, maxY - minY),
    minX,
    minY,
  };
}

function buildFallbackGridLayout(graph, canvasWidth) {
  const nodes = (graph && graph.nodes) || [];
  const positions = {};
  if (!nodes.length) {
    return positions;
  }

  const spacingX = 190;
  const spacingY = 140;
  const maxCols = Math.max(2, Math.floor(canvasWidth / spacingX));

  nodes.forEach((node, index) => {
    const row = Math.floor(index / maxCols);
    const col = index % maxCols;
    positions[node.id] = {
      x: col * spacingX,
      y: row * spacingY,
    };
  });

  return positions;
}

function buildWrappedDepthLayout(graph, canvasWidth) {
  const nodes = (graph && graph.nodes) || [];
  const edges = (graph && graph.edges) || [];
  if (!nodes.length) {
    return {};
  }

  const { children, indegree } = internals.buildChildrenMap(edges);
  const nodeIds = nodes.map((node) => node.id);
  const allNodeSet = new Set(nodeIds);

  let roots = nodes
    .filter((node) => String(node.type || "").toLowerCase() === "technique")
    .map((node) => node.id);

  if (!roots.length) {
    roots = nodeIds.filter((nodeId) => (indegree.get(nodeId) || 0) === 0);
  }

  if (!roots.length) {
    roots = [nodeIds[0]];
  }

  const components = [];
  const usedNodes = new Set();
  const subtreeWidthLimit = Math.max(1080, Math.floor(canvasWidth * 1.1));

  roots.forEach((rootId) => {
    if (!allNodeSet.has(rootId) || usedNodes.has(rootId)) {
      return;
    }

    const subtree = layoutSubtreeWithDepthWrap(rootId, children, subtreeWidthLimit);
    subtree.nodes.forEach((nodeId) => usedNodes.add(nodeId));
    components.push(subtree);
  });

  nodeIds.forEach((nodeId) => {
    if (usedNodes.has(nodeId)) {
      return;
    }

    components.push({
      positions: {
        [nodeId]: { x: 0, y: 0 },
      },
      nodes: new Set([nodeId]),
      width: 120,
      height: 120,
      minX: 0,
      minY: 0,
    });
    usedNodes.add(nodeId);
  });

  const packed = {};
  const componentGapX = 120;
  const componentGapY = 160;
  let cursorX = 0;
  let cursorY = 0;
  let rowHeight = 0;

  components.forEach((component) => {
    const wrap = cursorX > 0 && cursorX + component.width > canvasWidth;
    if (wrap) {
      cursorX = 0;
      cursorY += rowHeight + componentGapY;
      rowHeight = 0;
    }

    const shiftX = cursorX - component.minX;
    const shiftY = cursorY - component.minY;
    Object.entries(component.positions).forEach(([nodeId, pos]) => {
      packed[nodeId] = {
        x: pos.x + shiftX,
        y: pos.y + shiftY,
      };
    });

    cursorX += component.width + componentGapX;
    rowHeight = Math.max(rowHeight, component.height);
  });

  return packed;
}

function recenterTechniqueRoots(view, graph) {
  const nodes = (graph && graph.nodes) || [];
  const edges = (graph && graph.edges) || [];
  if (!nodes.length || !edges.length) {
    return;
  }

  const techniqueIds = nodes
    .filter((node) => String((node && (node.type || node.group)) || "").trim().toLowerCase() === "technique")
    .map((node) => String((node && node.id) || "").trim())
    .filter(Boolean);

  techniqueIds.forEach((techniqueId) => {
    if (!view.basePositions.has(techniqueId)) {
      return;
    }

    const childPositions = [];
    edges.forEach((edge) => {
      const source = String((edge && (edge.source || edge.from)) || "").trim();
      const target = String((edge && (edge.target || edge.to)) || "").trim();
      if (!source || !target || source !== techniqueId || !view.basePositions.has(target)) {
        return;
      }
      childPositions.push(view.basePositions.get(target));
    });

    if (!childPositions.length) {
      return;
    }

    const centerX = childPositions.reduce((sum, pos) => sum + pos.x, 0) / childPositions.length;
    const minChildY = childPositions.reduce((minY, pos) => Math.min(minY, pos.y), Number.POSITIVE_INFINITY);
    const nextY = Number.isFinite(minChildY) ? minChildY - 120 : 0;

    view.basePositions.set(techniqueId, {
      x: centerX,
      y: nextY,
    });
  });
}

function recomputeBaseLayout(view, graph, preserveExisting = false) {
  const currentGraph = graph || { nodes: [], edges: [] };

  if (!currentGraph.nodes.length) {
    view.basePositions = new Map();
    return;
  }

  const canvasWidth = Math.max(620, Math.floor((view.canvasElement.clientWidth || 0) * 0.92));
  let packed = {};

  try {
    packed = buildWrappedDepthLayout(currentGraph, canvasWidth);
  } catch (error) {
    packed = {};
  }

  const expectedCount = currentGraph.nodes.length;
  const actualCount = Object.keys(packed).length;
  if (!expectedCount || actualCount < Math.max(1, Math.floor(expectedCount * 0.6))) {
    packed = buildFallbackGridLayout(currentGraph, canvasWidth);
  }

  if (!preserveExisting) {
    view.basePositions = new Map(
      Object.entries(packed).map(([nodeId, pos]) => [nodeId, { x: pos.x, y: pos.y }])
    );
  } else {
    const next = new Map();
    const nodeIds = new Set(currentGraph.nodes.map((node) => node.id));

    nodeIds.forEach((nodeId) => {
      const existing = view.basePositions.get(nodeId);
      if (existing && Number.isFinite(existing.x) && Number.isFinite(existing.y)) {
        next.set(nodeId, { x: existing.x, y: existing.y });
        return;
      }

      const layoutPos = packed[nodeId];
      if (layoutPos && Number.isFinite(layoutPos.x) && Number.isFinite(layoutPos.y)) {
        next.set(nodeId, { x: layoutPos.x, y: layoutPos.y });
      }
    });

    view.basePositions = next;
  }

  const missingNodes = currentGraph.nodes.filter((node) => !view.basePositions.has(node.id));
  if (missingNodes.length) {
    const fallbackForMissing = buildFallbackGridLayout({ nodes: missingNodes, edges: [] }, canvasWidth);
    missingNodes.forEach((node) => {
      const pos = fallbackForMissing[node.id] || { x: 0, y: 0 };
      view.basePositions.set(node.id, { x: pos.x, y: pos.y });
    });
  }

  recenterTechniqueRoots(view, currentGraph);
}

internals.layout = {
  recomputeBaseLayout,
};
})();
