const state = {
  techniques: [],
  techniqueIndex: -1,
  activeTechnique: "",
  datasetFolder: "",
  patterns: [],
  fullGraph: null,
  filteredGraph: null,
  filteredNodeMap: new Map(),
  basePositions: new Map(),
  nodeDataSet: null,
  edgeDataSet: null,
  network: null,
};

const FREE_LAYOUT = {
  improvedLayout: true,
  hierarchical: {
    enabled: false,
  },
};

const el = {
  techniqueSelect: document.getElementById("technique-select"),
  prevBtn: document.getElementById("prev-technique"),
  nextBtn: document.getElementById("next-technique"),
  graphStats: document.getElementById("graph-stats"),
  status: document.getElementById("status-message"),
  graphCanvas: document.getElementById("graph-canvas"),
  patternInput: document.getElementById("pattern-input"),
  addPatternBtn: document.getElementById("add-pattern"),
  patternList: document.getElementById("pattern-list"),
  completeBtn: document.getElementById("complete-btn"),
  inspectBox: document.getElementById("node-inspect"),
};

function setStatus(message, isError = false) {
  el.status.textContent = message;
  el.status.classList.toggle("error", isError);
}

async function apiGet(url) {
  const response = await fetch(url);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Request failed");
  }
  return payload;
}

async function apiPost(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Request failed");
  }
  return payload;
}

function updateTechniqueControls() {
  const hasTechniques = state.techniques.length > 0;
  el.prevBtn.disabled = !hasTechniques || state.techniqueIndex <= 0;
  el.nextBtn.disabled = !hasTechniques || state.techniqueIndex >= state.techniques.length - 1;
  el.techniqueSelect.disabled = !hasTechniques;
}

function renderTechniqueOptions() {
  el.techniqueSelect.innerHTML = "";
  state.techniques.forEach((technique) => {
    const option = document.createElement("option");
    option.value = technique;
    option.textContent = technique;
    el.techniqueSelect.appendChild(option);
  });

  if (state.techniqueIndex >= 0) {
    el.techniqueSelect.value = state.techniques[state.techniqueIndex];
  }

  updateTechniqueControls();
}

function renderPatternList() {
  el.patternList.innerHTML = "";

  if (!state.patterns.length) {
    const empty = document.createElement("li");
    empty.className = "pattern-item";
    empty.textContent = "No pattern yet.";
    el.patternList.appendChild(empty);
    return;
  }

  state.patterns.forEach((pattern, index) => {
    const row = document.createElement("li");
    row.className = "pattern-item";

    const code = document.createElement("code");
    code.textContent = pattern;

    const removeButton = document.createElement("button");
    removeButton.type = "button";
    removeButton.className = "remove-pattern";
    removeButton.textContent = "Remove";
    removeButton.dataset.index = String(index);

    row.appendChild(code);
    row.appendChild(removeButton);
    el.patternList.appendChild(row);
  });
}

function normalizePatterns(patterns) {
  const seen = new Set();
  const normalized = [];

  (patterns || []).forEach((raw) => {
    const value = String(raw || "").trim();
    if (!value || seen.has(value)) {
      return;
    }
    seen.add(value);
    normalized.push(value);
  });

  return normalized;
}

function buildChildrenMap(edges) {
  const children = new Map();
  const indegree = new Map();

  edges.forEach((edge) => {
    const source = edge.source || edge.from;
    const target = edge.target || edge.to;
    if (!source || !target) {
      return;
    }

    if (!children.has(source)) {
      children.set(source, []);
    }
    children.get(source).push(target);

    indegree.set(target, (indegree.get(target) || 0) + 1);
    if (!indegree.has(source)) {
      indegree.set(source, indegree.get(source) || 0);
    }
  });

  return { children, indegree };
}

function nodeMatchesPatterns(node, lowerPatterns) {
  if (!lowerPatterns.length) {
    return false;
  }
  const searchable = JSON.stringify(node).toLowerCase();
  return lowerPatterns.some((pattern) => searchable.includes(pattern));
}

function markSubtree(startId, childrenMap, removeSet) {
  const stack = [startId];
  while (stack.length) {
    const current = stack.pop();
    if (removeSet.has(current)) {
      continue;
    }
    removeSet.add(current);

    const children = childrenMap.get(current) || [];
    for (const childId of children) {
      stack.push(childId);
    }
  }
}

function filterGraphClientSide(fullGraph, patterns) {
  if (!fullGraph) {
    return { nodes: [], edges: [] };
  }

  const nodes = Array.isArray(fullGraph.nodes) ? fullGraph.nodes : [];
  const edges = Array.isArray(fullGraph.edges) ? fullGraph.edges : [];

  const normalizedPatterns = normalizePatterns(patterns);
  const lowerPatterns = normalizedPatterns.map((p) => p.toLowerCase());
  if (!lowerPatterns.length) {
    return {
      ...fullGraph,
      nodes: nodes.map((n) => ({ ...n })),
      edges: edges.map((e) => ({ ...e })),
    };
  }

  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const { children, indegree } = buildChildrenMap(edges);

  let roots = nodes
    .filter((node) => String(node.type || "").toLowerCase() === "technique")
    .map((node) => node.id);

  if (!roots.length) {
    roots = nodes
      .filter((node) => (indegree.get(node.id) || 0) === 0)
      .map((node) => node.id);
  }

  const removeSet = new Set();

  for (const rootId of roots) {
    const stack = [rootId];
    const visited = new Set();

    while (stack.length) {
      const nodeId = stack.pop();
      if (visited.has(nodeId) || removeSet.has(nodeId)) {
        continue;
      }
      visited.add(nodeId);

      const node = nodeMap.get(nodeId);
      if (!node) {
        continue;
      }

      if (nodeMatchesPatterns(node, lowerPatterns)) {
        markSubtree(nodeId, children, removeSet);
        continue;
      }

      const childIds = children.get(nodeId) || [];
      for (const childId of childIds) {
        if (!visited.has(childId)) {
          stack.push(childId);
        }
      }
    }
  }

  const keptNodes = nodes.filter((node) => !removeSet.has(node.id));
  const keptNodeIds = new Set(keptNodes.map((node) => node.id));

  const keptEdges = edges.filter((edge) => {
    const source = edge.source || edge.from;
    const target = edge.target || edge.to;
    return keptNodeIds.has(source) && keptNodeIds.has(target);
  });

  return {
    ...fullGraph,
    nodes: keptNodes,
    edges: keptEdges,
  };
}

function colorForGroup(group) {
  const palette = {
    Technique: "#0f766e",
    Process: "#3f3f46",
    File: "#1d4ed8",
    Network: "#b45309",
    Registry: "#6d28d9",
    User: "#065f46",
    Wmi: "#7c2d12",
    UnknownEntity: "#475569",
  };
  return palette[group] || "#334155";
}

function ensureNetwork() {
  if (state.network) {
    return;
  }

  const options = {
    layout: FREE_LAYOUT,
    interaction: {
      dragNodes: true,
      dragView: true,
      hover: true,
      navigationButtons: true,
      keyboard: true,
      zoomView: true,
    },
    nodes: {
      shape: "dot",
      size: 13,
      font: {
        face: "Space Grotesk",
        size: 13,
      },
      borderWidth: 1,
    },
    edges: {
      arrows: "to",
      smooth: {
        enabled: true,
        type: "cubicBezier",
        forceDirection: "vertical",
        roundness: 0.42,
      },
      width: 1.1,
      color: {
        color: "#8c8b87",
        highlight: "#0f766e",
      },
      font: {
        face: "IBM Plex Mono",
        size: 10,
        align: "horizontal",
      },
    },
    physics: {
      enabled: false,
    },
  };

  state.nodeDataSet = new vis.DataSet([]);
  state.edgeDataSet = new vis.DataSet([]);
  state.network = new vis.Network(
    el.graphCanvas,
    { nodes: state.nodeDataSet, edges: state.edgeDataSet },
    options,
  );

  state.network.on("click", (params) => {
    if (!params.nodes.length) {
      el.inspectBox.textContent = "Click a node to inspect properties.";
      return;
    }

    const nodeId = params.nodes[0];
    const node = state.filteredNodeMap.get(nodeId);
    if (!node) {
      el.inspectBox.textContent = "Node data not found.";
      return;
    }

    el.inspectBox.textContent = JSON.stringify(node.properties || node, null, 2);
  });

  state.network.on("dragEnd", (params) => {
    if (!params.nodes || !params.nodes.length) {
      return;
    }

    const draggedIds = params.nodes;
    const latestPositions = state.network.getPositions(draggedIds);
    draggedIds.forEach((nodeId) => {
      const pos = latestPositions[nodeId];
      if (pos) {
        state.basePositions.set(nodeId, { x: pos.x, y: pos.y });
      }
    });
  });
}

function getConnectedComponents(nodeIds, edges) {
  const nodeSet = new Set(nodeIds);
  const adjacency = new Map();

  nodeIds.forEach((id) => adjacency.set(id, new Set()));
  (edges || []).forEach((edge) => {
    const source = edge.source || edge.from;
    const target = edge.target || edge.to;
    if (!nodeSet.has(source) || !nodeSet.has(target)) {
      return;
    }

    adjacency.get(source).add(target);
    adjacency.get(target).add(source);
  });

  const visited = new Set();
  const components = [];

  nodeIds.forEach((start) => {
    if (visited.has(start)) {
      return;
    }
    const stack = [start];
    const component = [];
    visited.add(start);

    while (stack.length) {
      const current = stack.pop();
      component.push(current);
      (adjacency.get(current) || []).forEach((neighbor) => {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          stack.push(neighbor);
        }
      });
    }

    components.push(component);
  });

  return components;
}

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
  const nodeSpacingX = 175;
  const tierUnitY = 92;
  const baseLevelStep = 2;
  const overflowStep = 1;
  const padding = 84;
  const minGap = 18;
  const maxCols = Math.max(2, Math.floor(maxWidth / nodeSpacingX));

  const queue = [{ nodeId: rootId, tier: 0, x: 0 }];
  const queued = new Set([rootId]);
  const positions = {};
  const tierRanges = new Map();
  const maxIterations = 50000;
  let iterations = 0;

  reserveTierRange(tierRanges, 0, 0, 0, padding, minGap);

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
      const adjustedStartX = reserveTierRange(
        tierRanges,
        rowTier,
        desiredStartX,
        rowWidth,
        padding,
        minGap,
      );

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

  const { children, indegree } = buildChildrenMap(edges);
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
  const subtreeWidthLimit = Math.max(420, Math.floor(canvasWidth * 0.58));

  roots.forEach((rootId) => {
    if (!allNodeSet.has(rootId) || usedNodes.has(rootId)) {
      return;
    }

    const subtree = layoutSubtreeWithDepthWrap(rootId, children, subtreeWidthLimit);
    subtree.nodes.forEach((nodeId) => usedNodes.add(nodeId));
    components.push(subtree);
  });

  // Keep orphan or cyclic leftovers visible.
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
  const componentGapX = 130;
  const componentGapY = 210;
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

function toVisGraph(graph, keepOriginalLayout = false) {
  const visNodes = (graph.nodes || []).map((node) => {
    const color = colorForGroup(node.group);
    const basePosition = state.basePositions.get(node.id);
    const withPosition =
      keepOriginalLayout && basePosition
        ? {
            x: basePosition.x,
            y: basePosition.y,
          }
        : {};

    return {
      id: node.id,
      label: node.label || node.id,
      group: node.group,
      title: `${node.group}: ${node.label || node.id}`,
      color: {
        border: color,
        background: `${color}22`,
        highlight: {
          border: color,
          background: `${color}44`,
        },
      },
      ...withPosition,
    };
  });

  const visEdges = (graph.edges || []).map((edge) => ({
    id: edge.id,
    from: edge.source || edge.from,
    to: edge.target || edge.to,
    label: edge.label || edge.type || "",
  }));

  return { visNodes, visEdges };
}

function updateDataSet(dataSet, nextItems) {
  const currentIds = new Set(dataSet.getIds());
  const nextIds = new Set(nextItems.map((item) => item.id));

  const toRemove = [];
  currentIds.forEach((id) => {
    if (!nextIds.has(id)) {
      toRemove.push(id);
    }
  });

  if (toRemove.length) {
    dataSet.remove(toRemove);
  }

  dataSet.update(nextItems);
}

function renderGraph(graph, keepOriginalLayout = false) {
  ensureNetwork();

  const { visNodes, visEdges } = toVisGraph(graph, keepOriginalLayout);

  state.filteredNodeMap = new Map((graph.nodes || []).map((node) => [node.id, node]));
  updateDataSet(state.nodeDataSet, visNodes);
  updateDataSet(state.edgeDataSet, visEdges);

  const nodeCount = visNodes.length;
  const edgeCount = visEdges.length;
  el.graphStats.textContent = `${nodeCount} nodes | ${edgeCount} edges`;
}

function applyFilterAndRender() {
  state.patterns = normalizePatterns(state.patterns);
  state.filteredGraph = filterGraphClientSide(state.fullGraph, state.patterns);
  renderGraph(state.filteredGraph, true);
}

function captureBasePositions() {
  if (!state.network || !state.fullGraph) {
    return;
  }

  const allNodeIds = (state.fullGraph.nodes || []).map((node) => node.id);
  const positions = state.network.getPositions(allNodeIds);
  state.basePositions = new Map(
    Object.entries(positions).map(([nodeId, position]) => [nodeId, position]),
  );
}

async function buildPackedBaseLayout() {
  const canvasWidth = Math.max(620, Math.floor(el.graphCanvas.clientWidth * 0.92));
  let packed = {};

  try {
    packed = buildWrappedDepthLayout(state.fullGraph, canvasWidth);
  } catch (error) {
    packed = {};
  }

  const expectedCount = ((state.fullGraph && state.fullGraph.nodes) || []).length;
  const actualCount = Object.keys(packed).length;
  if (!expectedCount || actualCount < Math.max(1, Math.floor(expectedCount * 0.6))) {
    packed = buildFallbackGridLayout(state.fullGraph, canvasWidth);
  }

  state.basePositions = new Map(Object.entries(packed));

  renderGraph(state.fullGraph, true);
}

async function loadTechnique(technique) {
  if (!technique) {
    return;
  }

  try {
    setStatus(`Loading graph for ${technique}...`);
    const [graphPayload, patternPayload] = await Promise.all([
      apiGet(`/api/graph?technique=${encodeURIComponent(technique)}`),
      apiGet(`/api/patterns?technique=${encodeURIComponent(technique)}`),
    ]);

    state.activeTechnique = technique;
    state.fullGraph = graphPayload;
    state.patterns = normalizePatterns(patternPayload.patterns || []);
    state.basePositions = new Map();

    renderGraph(state.fullGraph, false);
    await buildPackedBaseLayout();
    renderPatternList();
    applyFilterAndRender();

    if (state.network) {
      state.network.fit({ animation: false });
    }

    const sourceFile = graphPayload.source_file || "unknown";
    setStatus(`Loaded ${technique} from ${sourceFile}`);
  } catch (error) {
    state.fullGraph = { nodes: [], edges: [] };
    state.filteredGraph = { nodes: [], edges: [] };
    state.basePositions = new Map();
    renderPatternList();
    renderGraph(state.filteredGraph, false);
    setStatus(error.message, true);
  }
}

async function loadTechniques() {
  try {
    setStatus("Loading technique list...");
    const payload = await apiGet("/api/techniques");
    state.techniques = Array.isArray(payload.techniques) ? payload.techniques : [];
    state.datasetFolder = String(payload.dataset_folder || "");

    if (!state.techniques.length) {
      state.techniqueIndex = -1;
      renderTechniqueOptions();
      const locationText = state.datasetFolder || "configured dataset folder";
      setStatus(`No Sysmon logs found in ${locationText}.`, true);
      return;
    }

    state.techniqueIndex = 0;
    renderTechniqueOptions();
    await loadTechnique(state.techniques[0]);
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function addPattern() {
  const value = (el.patternInput.value || "").trim();
  if (!value || !state.activeTechnique) {
    return;
  }

  try {
    const payload = await apiPost("/api/patterns/append", {
      technique: state.activeTechnique,
      new_pattern: value,
    });

    state.patterns = normalizePatterns(payload.patterns || []);
    el.patternInput.value = "";
    renderPatternList();
    applyFilterAndRender();
    setStatus(`Pattern '${value}' saved and applied.`);
  } catch (error) {
    setStatus(error.message, true);
  }
}

function removePatternByIndex(index) {
  if (index < 0 || index >= state.patterns.length) {
    return;
  }

  const removed = state.patterns[index];
  state.patterns.splice(index, 1);
  state.patterns = normalizePatterns(state.patterns);
  renderPatternList();
  applyFilterAndRender();
  setStatus(`Removed pattern '${removed}' locally. Press Complete to persist.`);
}

async function savePatterns() {
  if (!state.activeTechnique) {
    return;
  }

  try {
    const payload = await apiPost("/api/patterns", {
      technique: state.activeTechnique,
      patterns: state.patterns,
    });

    state.patterns = normalizePatterns(payload.patterns || []);
    renderPatternList();
    applyFilterAndRender();
    setStatus(`Patterns saved for ${state.activeTechnique}.`);
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function selectTechniqueAt(index) {
  if (index < 0 || index >= state.techniques.length) {
    return;
  }

  state.techniqueIndex = index;
  renderTechniqueOptions();
  await loadTechnique(state.techniques[index]);
}

function bindEvents() {
  el.prevBtn.addEventListener("click", async () => {
    await selectTechniqueAt(state.techniqueIndex - 1);
  });

  el.nextBtn.addEventListener("click", async () => {
    await selectTechniqueAt(state.techniqueIndex + 1);
  });

  el.techniqueSelect.addEventListener("change", async (event) => {
    const technique = event.target.value;
    const index = state.techniques.indexOf(technique);
    await selectTechniqueAt(index);
  });

  el.addPatternBtn.addEventListener("click", addPattern);

  el.patternInput.addEventListener("keydown", async (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      await addPattern();
    }
  });

  el.patternList.addEventListener("click", (event) => {
    const button = event.target.closest("button.remove-pattern");
    if (!button) {
      return;
    }

    const idx = Number(button.dataset.index || "-1");
    removePatternByIndex(idx);
  });

  el.completeBtn.addEventListener("click", savePatterns);
}

async function init() {
  bindEvents();
  await loadTechniques();
}

init().catch((error) => {
  const message = error && error.message ? error.message : "Unexpected initialization error";
  setStatus(message, true);
});
