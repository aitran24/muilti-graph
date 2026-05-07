const state = {
  cy: null,
  graphPayload: null,
  graphTechnique: null,
  hiddenNodeCount: 0,
  matchResult: null,
  activeAlgorithm: null,
  activeTechnique: null,
};

const targetSelect = document.getElementById("targetSelect");
const algoSelect = document.getElementById("algoSelect");
const runBtn = document.getElementById("runBtn");
const statusEl = document.getElementById("status");
const summaryEl = document.getElementById("summary");
const tabsEl = document.getElementById("resultTabs");
const resultListEl = document.getElementById("resultList");

const LARGE_GRAPH_NODE_THRESHOLD = 200;
const MAX_CHILDREN_PER_PARENT = 15;

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.className = isError ? "status error" : "status";
}

function selectedAlgorithms() {
  return Array.from(algoSelect.options)
    .filter((option) => option.selected)
    .map((option) => option.value);
}

async function loadTargets() {
  const response = await fetch("/api/targets");
  const payload = await response.json();

  targetSelect.innerHTML = "";
  (payload.targets || []).forEach((techniqueName) => {
    const option = document.createElement("option");
    option.value = techniqueName;
    option.textContent = techniqueName;
    targetSelect.appendChild(option);
  });
}

async function loadGraph(techniqueName) {
  const response = await fetch(`/api/graph?technique=${encodeURIComponent(techniqueName)}`);
  if (!response.ok) {
    const payload = await response.json();
    throw new Error(payload.error || "Failed to load graph.");
  }
  state.graphPayload = await response.json();
  state.graphTechnique = techniqueName;
  renderGraph(state.graphPayload);
}

function toElements(graphPayload) {
  const nodes = (graphPayload.nodes || []).map((node) => ({
    data: {
      id: node.id,
      label: node.label || node.id,
      nodeType: node.type || "unknown",
      group: node.group || "Unknown",
    },
  }));

  const edges = (graphPayload.edges || []).map((edge) => ({
    data: {
      id: edge.id,
      source: edge.source || edge.from,
      target: edge.target || edge.to,
      label: edge.label || edge.type || "REL",
      edgeType: edge.type || "REL",
    },
  }));

  return [...nodes, ...edges];
}

function buildRenderableGraph(graphPayload) {
  const nodes = graphPayload.nodes || [];
  const edges = graphPayload.edges || [];

  if (nodes.length <= LARGE_GRAPH_NODE_THRESHOLD) {
    state.hiddenNodeCount = 0;
    return graphPayload;
  }

  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const techniqueIds = nodes
    .filter((node) => String(node.group || "").toLowerCase() === "technique")
    .map((node) => node.id);
  const outgoingChildrenMap = new Map();
  const incomingCount = new Map();
  const edgeList = [];

  edges.forEach((edge) => {
    const sourceId = edge.source || edge.from;
    const targetId = edge.target || edge.to;
    if (!sourceId || !targetId || !nodeMap.has(sourceId) || !nodeMap.has(targetId)) {
      return;
    }

    if (!outgoingChildrenMap.has(sourceId)) {
      outgoingChildrenMap.set(sourceId, new Set());
    }
    outgoingChildrenMap.get(sourceId).add(targetId);
    incomingCount.set(targetId, (incomingCount.get(targetId) || 0) + 1);
    edgeList.push(edge);
  });

  if (!edgeList.length) {
    state.hiddenNodeCount = 0;
    return graphPayload;
  }

  const allowedChildrenByParent = new Map();
  outgoingChildrenMap.forEach((childSet, parentId) => {
    const orderedChildren = [...childSet];
    const keptChildren =
      orderedChildren.length > MAX_CHILDREN_PER_PARENT
        ? orderedChildren.slice(0, MAX_CHILDREN_PER_PARENT)
        : orderedChildren;
    allowedChildrenByParent.set(parentId, new Set(keptChildren));
  });

  const cappedEdges = edgeList.filter((edge) => {
    const sourceId = edge.source || edge.from;
    const targetId = edge.target || edge.to;
    const allowedChildren = allowedChildrenByParent.get(sourceId);
    return !!allowedChildren && allowedChildren.has(targetId);
  });

  const cappedOutgoingMap = new Map();
  cappedEdges.forEach((edge) => {
    const sourceId = edge.source || edge.from;
    const targetId = edge.target || edge.to;
    if (!cappedOutgoingMap.has(sourceId)) {
      cappedOutgoingMap.set(sourceId, []);
    }
    cappedOutgoingMap.get(sourceId).push(targetId);
  });

  const rootIds = techniqueIds.length
    ? techniqueIds
    : nodes
        .filter((node) => (incomingCount.get(node.id) || 0) === 0)
        .map((node) => node.id);

  const reachableIds = new Set(rootIds);
  const queue = [...rootIds];
  while (queue.length) {
    const nodeId = queue.shift();
    (cappedOutgoingMap.get(nodeId) || []).forEach((nextId) => {
      if (reachableIds.has(nextId)) {
        return;
      }
      reachableIds.add(nextId);
      queue.push(nextId);
    });
  }

  let filteredNodes;
  let filteredEdges;
  if (reachableIds.size) {
    filteredNodes = nodes.filter((node) => reachableIds.has(node.id));
    filteredEdges = cappedEdges.filter((edge) => {
      const sourceId = edge.source || edge.from;
      const targetId = edge.target || edge.to;
      return reachableIds.has(sourceId) && reachableIds.has(targetId);
    });
  } else {
    filteredNodes = nodes;
    filteredEdges = cappedEdges;
  }

  state.hiddenNodeCount = Math.max(0, nodes.length - filteredNodes.length);
  return {
    ...graphPayload,
    nodes: filteredNodes,
    edges: filteredEdges,
  };
}

function buildLayoutOptions(nodeCount) {
  return {
    name: "cose",
    fit: true,
    padding: 24,
    animate: false,
    randomize: false,
  };
}

function renderGraph(graphPayload) {
  const container = document.getElementById("graph");
  const renderableGraph = buildRenderableGraph(graphPayload);
  const elements = toElements(renderableGraph);
  const nodeCount = (renderableGraph.nodes || []).length;
  const layout = buildLayoutOptions(nodeCount);

  if (!state.cy) {
    state.cy = cytoscape({
      container,
      elements,
      pixelRatio: 1,
      motionBlur: false,
      textureOnViewport: nodeCount >= 180,
      hideEdgesOnViewport: nodeCount >= 260,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#0f8b8d",
            label: "data(label)",
            "font-size": 9,
            color: "#111",
            "text-wrap": "wrap",
            "text-max-width": 120,
          },
        },
        {
          selector: "node[group = 'Technique']",
          style: {
            "background-color": "#d9a441",
            shape: "diamond",
            width: 24,
            height: 24,
            "font-size": 10,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.1,
            "line-color": "#9c9287",
            "target-arrow-color": "#9c9287",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "",
          },
        },
        {
          selector: "edge[edgeType = 'HAS_ROOT']",
          style: {
            "line-style": "dashed",
            opacity: 0.5,
          },
        },
        {
          selector: ".dimmed",
          style: {
            opacity: 0.12,
          },
        },
        {
          selector: ".matched",
          style: {
            "background-color": "#e0523e",
            width: 20,
            height: 20,
            "font-weight": "bold",
          },
        },
      ],
      layout,
    });
    return;
  }

  state.cy.elements().remove();
  state.cy.add(elements);
  state.cy.layout(layout).run();
}

function renderSummary(result) {
  const lines = (result.algorithms || []).map(
    (item) => `${item.algorithm}: top1=${item.top1_technique} score=${item.top1_score.toFixed(3)} acc=${item.accuracy.toFixed(2)} runtime=${item.runtime_ms.toFixed(1)}ms`
  );
  const totalNodes = (state.graphPayload?.nodes || []).length;
  const renderedNodes = state.cy ? state.cy.nodes().length : totalNodes;
  const pruneInfo =
    state.hiddenNodeCount > 0
      ? `<br><strong>Render optimization:</strong> showing ${renderedNodes}/${totalNodes} nodes (hidden ${state.hiddenNodeCount} overflow child nodes).`
      : "";

  summaryEl.innerHTML = `<strong>Target technique:</strong> ${result.target_technique}${pruneInfo}<br>${lines.join("<br>")}`;
}

function renderTabs(result) {
  tabsEl.innerHTML = "";
  result.algorithms.forEach((algo, index) => {
    const button = document.createElement("button");
    button.className = `tab ${index === 0 ? "active" : ""}`;
    button.textContent = algo.algorithm;
    button.onclick = () => {
      state.activeAlgorithm = algo.algorithm;
      state.activeTechnique = null;
      Array.from(tabsEl.children).forEach((child) => child.classList.remove("active"));
      button.classList.add("active");
      renderResultList();
      clearHighlight();
    };
    tabsEl.appendChild(button);
  });

  state.activeAlgorithm = result.algorithms[0]?.algorithm || null;
}

function renderResultList() {
  const result = state.matchResult;
  if (!result || !state.activeAlgorithm) {
    resultListEl.innerHTML = "";
    return;
  }

  const algo = result.algorithms.find((item) => item.algorithm === state.activeAlgorithm);
  if (!algo) {
    resultListEl.innerHTML = "";
    return;
  }

  resultListEl.innerHTML = "";
  algo.matches.forEach((match) => {
    const div = document.createElement("div");
    div.className = "result-item";
    if (state.activeTechnique === match.technique) {
      div.classList.add("active");
    }

    div.innerHTML = `
      <strong>${match.technique}</strong>
      <div class="meta">score=${match.score.toFixed(4)} runtime=${match.runtime_ms.toFixed(2)}ms</div>
      <div class="meta">matched_nodes=${match.matched_node_ids.length}</div>
    `;

    div.onclick = () => {
      state.activeTechnique = match.technique;
      highlightMatch(match.matched_node_ids || []);
      renderResultList();
    };

    resultListEl.appendChild(div);
  });
}

function clearHighlight() {
  if (!state.cy) {
    return;
  }
  state.cy.elements().removeClass("dimmed");
  state.cy.nodes().removeClass("matched");
}

function highlightMatch(nodeIds) {
  if (!state.cy) {
    return;
  }
  const set = new Set(nodeIds || []);
  clearHighlight();

  state.cy.elements().forEach((ele) => {
    if (ele.isNode()) {
      if (set.has(ele.id())) {
        ele.addClass("matched");
      } else {
        ele.addClass("dimmed");
      }
      return;
    }

    const srcIn = set.has(ele.data("source"));
    const dstIn = set.has(ele.data("target"));
    if (!(srcIn && dstIn)) {
      ele.addClass("dimmed");
    }
  });
}

async function runMatch() {
  const technique = targetSelect.value;
  if (!technique) {
    setStatus("Select a technique first.", true);
    return;
  }

  setStatus("Building offline graph from raw logs and running matching algorithms...");

  try {
    if (!state.graphPayload || state.graphTechnique !== technique) {
      await loadGraph(technique);
    }
    const response = await fetch("/api/match", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        technique,
        algorithms: selectedAlgorithms(),
        top_k: 15,
      }),
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Match request failed.");
    }

    state.matchResult = payload;
    renderSummary(payload);
    renderTabs(payload);
    renderResultList();
    clearHighlight();
    setStatus("Matching completed.");
  } catch (error) {
    setStatus(error.message || "Unexpected error.", true);
  }
}

async function init() {
  try {
    await loadTargets();
    if (targetSelect.value) {
      await loadGraph(targetSelect.value);
    }
    setStatus("Ready.");
  } catch (error) {
    setStatus(error.message || "Cannot initialize UI.", true);
  }
}

runBtn.addEventListener("click", runMatch);
targetSelect.addEventListener("change", async () => {
  try {
    await loadGraph(targetSelect.value);
    clearHighlight();
  } catch (error) {
    setStatus(error.message || "Cannot build graph for selected technique.", true);
  }
});

init();
