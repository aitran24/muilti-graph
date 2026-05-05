const state = {
  techniques: [],
  techniqueIndex: -1,
  activeTechnique: "",
  datasetFolder: "",
  outputFolder: "",
  activeTechniqueSaved: false,

  collapseProcessNodesForView: true,
  fullGraph: null,
  displayGraph: null,
  renderedGraph: null,
  filteredNodeMap: new Map(),
  basePositions: new Map(),

  nodeDataSet: null,
  edgeDataSet: null,
  network: null,

  hiddenSubnodes: new Map(),
  lastClickedNodeId: null,
  selectedInspectRawNodeId: "",
  dragRearrangeMode: false, // false = bubble layout (circle)

  maliciousPatterns: [],
  whitelistPatterns: [],
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
  graphViewModeToggle: document.getElementById("graph-view-mode-toggle"),
  status: document.getElementById("status-message"),
  graphCanvas: document.getElementById("graph-canvas"),

  buildCurrentBtn: document.getElementById("build-current"),
  buildAllBtn: document.getElementById("build-all"),
  reloadSavedBtn: document.getElementById("reload-saved"),
  buildSummary: document.getElementById("build-summary"),

  maliciousPatternList: document.getElementById("pattern-malicious-list"),
  whitelistPatternList: document.getElementById("pattern-whitelist-list"),

  inspectBox: document.getElementById("node-inspect"),
  inspectNodeSourceSelect: document.getElementById("inspect-node-source-select"),
  hideSubnodeBtn: document.getElementById("hide-subnode-btn"),
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
    body: JSON.stringify(body || {}),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Request failed");
  }
  return payload;
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

function updateTechniqueControls() {
  const hasTechniques = state.techniques.length > 0;
  el.prevBtn.disabled = !hasTechniques || state.techniqueIndex <= 0;
  el.nextBtn.disabled = !hasTechniques || state.techniqueIndex >= state.techniques.length - 1;
  el.techniqueSelect.disabled = !hasTechniques;
}

function updateBuildSummary(extraText = "") {
  const technique = state.activeTechnique || "(none)";
  const saveState = state.activeTechnique ? (state.activeTechniqueSaved ? "saved" : "not-saved") : "unknown";

  const lines = [
    `Technique: ${technique}`,
    `Status: ${saveState}`,
    `Dataset: ${state.datasetFolder || "(unknown)"}`,
    `Output: ${state.outputFolder || "(unknown)"}`,
  ];

  if (extraText) {
    lines.push(extraText);
  }

  el.buildSummary.textContent = lines.join("\n");
}

function renderTechniqueOptions() {
  el.techniqueSelect.innerHTML = "";

  state.techniques.forEach((techniqueRecord) => {
    const option = document.createElement("option");
    option.value = techniqueRecord.name;
    option.textContent = techniqueRecord.saved
      ? `${techniqueRecord.name} (saved)`
      : `${techniqueRecord.name} (not saved)`;
    el.techniqueSelect.appendChild(option);
  });

  if (state.techniqueIndex >= 0 && state.techniqueIndex < state.techniques.length) {
    el.techniqueSelect.value = state.techniques[state.techniqueIndex].name;
  }

  updateTechniqueControls();
}

function renderPatternList(targetElement, patterns, emptyText) {
  targetElement.innerHTML = "";

  if (!patterns.length) {
    const item = document.createElement("li");
    item.className = "empty";
    item.textContent = emptyText;
    targetElement.appendChild(item);
    return;
  }

  patterns.forEach((pattern) => {
    const item = document.createElement("li");
    item.textContent = pattern;
    targetElement.appendChild(item);
  });
}

function renderPatternPreview() {
  renderPatternList(el.maliciousPatternList, state.maliciousPatterns, "No malicious pattern.");
  renderPatternList(el.whitelistPatternList, state.whitelistPatterns, "No whitelist pattern.");
}

function updateGraphViewModeUI() {
  const isGroupedByGuid = state.collapseProcessNodesForView;
  el.graphViewModeToggle.textContent = isGroupedByGuid ? "Grouped by GUID" : "Raw by Event";
  el.graphViewModeToggle.classList.toggle("raw-mode", !isGroupedByGuid);
  el.graphViewModeToggle.title = isGroupedByGuid
    ? "Switch to raw event-node view"
    : "Switch to grouped-by-guid view";
}

function normalizePatternPreview(values) {
  if (!Array.isArray(values)) {
    return [];
  }
  const seen = new Set();
  const normalized = [];
  values.forEach((raw) => {
    const value = String(raw || "").trim();
    if (!value || seen.has(value)) {
      return;
    }
    seen.add(value);
    normalized.push(value);
  });
  return normalized;
}

function resetInspectPanel(message = "Click a node to inspect properties.") {
  state.selectedInspectRawNodeId = "";

  el.inspectNodeSourceSelect.innerHTML = "";
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Select grouped source node";
  el.inspectNodeSourceSelect.appendChild(placeholder);
  el.inspectNodeSourceSelect.value = "";
  el.inspectNodeSourceSelect.disabled = true;
  el.inspectNodeSourceSelect.hidden = true;

  el.inspectBox.textContent = message;
}

function buildRawNodeMap() {
  return new Map((((state.fullGraph && state.fullGraph.nodes) || []).map((node) => [node.id, node])));
}

function getCollapsedRawNodeCandidates(displayNode, rawNodeMap) {
  if (!state.collapseProcessNodesForView || !displayNode) {
    return [];
  }

  const rawIds = Array.isArray((displayNode.properties || {})._ui_collapsed_node_ids)
    ? (displayNode.properties || {})._ui_collapsed_node_ids
    : [];

  const uniqueRawIds = [...new Set(rawIds.map((nodeId) => String(nodeId || "").trim()).filter(Boolean))];
  if (uniqueRawIds.length < 2) {
    return [];
  }

  return uniqueRawIds
    .map((nodeId) => rawNodeMap.get(nodeId))
    .filter(Boolean)
    .sort((leftNode, rightNode) => {
      const leftEventId = String((leftNode.properties || {}).event_id || "").trim();
      const rightEventId = String((rightNode.properties || {}).event_id || "").trim();
      const leftPriority = leftEventId === "1" || String(leftNode.id).endsWith(":1") ? 0 : 1;
      const rightPriority = rightEventId === "1" || String(rightNode.id).endsWith(":1") ? 0 : 1;
      if (leftPriority !== rightPriority) {
        return leftPriority - rightPriority;
      }
      return String(leftNode.id).localeCompare(String(rightNode.id));
    });
}

function formatCollapsedNodeOption(rawNode) {
  const props = rawNode.properties || {};
  const eventId = String(props.event_id || "").trim();
  const eventHint = eventId === "1"
    ? "Process Create"
    : eventId === "10"
      ? "Process Access"
      : eventId
        ? `Event ${eventId}`
        : "Unknown Event";
  const label = props.display_name || rawNode.label || rawNode.id;
  return `${eventHint} | ${label}`;
}

function populateInspectNodeSourceSelect(displayNode, candidates) {
  el.inspectNodeSourceSelect.innerHTML = "";

  if (!candidates.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Select grouped source node";
    el.inspectNodeSourceSelect.appendChild(option);
    el.inspectNodeSourceSelect.value = "";
    el.inspectNodeSourceSelect.disabled = true;
    el.inspectNodeSourceSelect.hidden = true;
    state.selectedInspectRawNodeId = "";
    return;
  }

  candidates.forEach((rawNode) => {
    const option = document.createElement("option");
    option.value = rawNode.id;
    option.textContent = formatCollapsedNodeOption(rawNode);
    el.inspectNodeSourceSelect.appendChild(option);
  });

  const defaultNodeId = candidates.some((rawNode) => rawNode.id === displayNode.id)
    ? displayNode.id
    : candidates[0].id;

  if (!candidates.some((rawNode) => rawNode.id === state.selectedInspectRawNodeId)) {
    state.selectedInspectRawNodeId = defaultNodeId;
  }

  el.inspectNodeSourceSelect.value = state.selectedInspectRawNodeId;
  el.inspectNodeSourceSelect.disabled = false;
  el.inspectNodeSourceSelect.hidden = false;
}

function refreshInspectPanel() {
  if (!state.lastClickedNodeId) {
    resetInspectPanel();
    return;
  }

  const displayNode = state.filteredNodeMap.get(state.lastClickedNodeId);
  if (!displayNode) {
    state.lastClickedNodeId = null;
    resetInspectPanel("Node data not found.");
    return;
  }

  const rawNodeMap = buildRawNodeMap();
  const collapsedCandidates = getCollapsedRawNodeCandidates(displayNode, rawNodeMap);
  populateInspectNodeSourceSelect(displayNode, collapsedCandidates);

  let inspectTarget = displayNode;
  if (collapsedCandidates.length >= 2) {
    const selectedRawNode = rawNodeMap.get(state.selectedInspectRawNodeId);
    if (selectedRawNode) {
      inspectTarget = selectedRawNode;
    }
  }

  el.inspectBox.textContent = JSON.stringify(inspectTarget.properties || inspectTarget, null, 2);
}

function isMeaningfulValue(value) {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === "string") {
    return value.trim() !== "";
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (typeof value === "object") {
    return Object.keys(value).length > 0;
  }
  return true;
}

function mergeNodeProperties(current, incoming) {
  const merged = { ...(current || {}) };
  Object.entries(incoming || {}).forEach(([key, incomingValue]) => {
    const currentValue = merged[key];
    if (currentValue === undefined) {
      merged[key] = incomingValue;
      return;
    }

    if (isMeaningfulValue(incomingValue) && !isMeaningfulValue(currentValue)) {
      merged[key] = incomingValue;
    }
  });
  return merged;
}

function cloneGraphData(graph) {
  if (!graph) {
    return { nodes: [], edges: [] };
  }

  const nodes = Array.isArray(graph.nodes)
    ? graph.nodes.map((node) => ({
        ...node,
        properties: { ...(node.properties || {}) },
      }))
    : [];

  const edges = Array.isArray(graph.edges)
    ? graph.edges.map((edge) => ({
        ...edge,
        properties: { ...(edge.properties || {}) },
      }))
    : [];

  return {
    ...graph,
    nodes,
    edges,
  };
}

function collapseGraphForDisplay(graph) {
  if (!graph) {
    return { nodes: [], edges: [] };
  }

  const rawNodes = Array.isArray(graph.nodes) ? graph.nodes.map((n) => ({ ...n })) : [];
  const rawEdges = Array.isArray(graph.edges) ? graph.edges.map((e) => ({ ...e })) : [];

  const nodeMap = new Map(rawNodes.map((node) => [node.id, node]));
  const guidGroups = new Map();

  rawNodes.forEach((node) => {
    if (String(node.group || "").toLowerCase() !== "process") {
      return;
    }

    const guid = String((node.properties || {}).guid || "").trim().toLowerCase();
    if (!guid) {
      return;
    }

    if (!guidGroups.has(guid)) {
      guidGroups.set(guid, []);
    }
    guidGroups.get(guid).push(node.id);
  });

  const idRedirects = new Map();

  guidGroups.forEach((nodeIds) => {
    if (!nodeIds || nodeIds.length < 2) {
      return;
    }

    const canonicalId = [...nodeIds].sort((leftId, rightId) => {
      const leftNode = nodeMap.get(leftId) || {};
      const rightNode = nodeMap.get(rightId) || {};
      const leftEventId = String((leftNode.properties || {}).event_id || "").trim();
      const rightEventId = String((rightNode.properties || {}).event_id || "").trim();
      const leftPriority = leftEventId === "1" || String(leftId).endsWith(":1") ? 0 : 1;
      const rightPriority = rightEventId === "1" || String(rightId).endsWith(":1") ? 0 : 1;
      if (leftPriority !== rightPriority) {
        return leftPriority - rightPriority;
      }
      return String(leftId).localeCompare(String(rightId));
    })[0];

    const canonicalNode = nodeMap.get(canonicalId);
    if (!canonicalNode) {
      return;
    }

    let mergedProps = { ...(canonicalNode.properties || {}) };
    const collapsedNodeIds = [];

    nodeIds.forEach((nodeId) => {
      const node = nodeMap.get(nodeId);
      if (!node) {
        return;
      }

      collapsedNodeIds.push(nodeId);
      if (nodeId !== canonicalId) {
        mergedProps = mergeNodeProperties(mergedProps, node.properties || {});
        idRedirects.set(nodeId, canonicalId);
        nodeMap.delete(nodeId);
      }
    });

    mergedProps._ui_collapsed_count = collapsedNodeIds.length;
    mergedProps._ui_collapsed_node_ids = collapsedNodeIds;
    canonicalNode.properties = mergedProps;
    canonicalNode.label = mergedProps.display_name || canonicalNode.label || canonicalId;
    nodeMap.set(canonicalId, canonicalNode);
  });

  const resolveId = (nodeId) => {
    let current = nodeId;
    const visited = new Set();
    while (idRedirects.has(current) && !visited.has(current)) {
      visited.add(current);
      current = idRedirects.get(current);
    }
    return current;
  };

  const edgeMap = new Map();
  rawEdges.forEach((edge) => {
    const mappedSource = resolveId(edge.source || edge.from);
    const mappedTarget = resolveId(edge.target || edge.to);
    if (!mappedSource || !mappedTarget || mappedSource === mappedTarget) {
      return;
    }

    const label = edge.label || edge.type || "";
    const dedupeKey = `${mappedSource}::${mappedTarget}::${label}`;

    if (edgeMap.has(dedupeKey)) {
      const existingEdge = edgeMap.get(dedupeKey);
      const props = { ...(existingEdge.properties || {}) };
      const previousCount = Number(props._ui_collapsed_count || 1);
      props._ui_collapsed_count = previousCount + 1;
      const previousIds = Array.isArray(props._ui_collapsed_edge_ids)
        ? props._ui_collapsed_edge_ids
        : [existingEdge.id];
      props._ui_collapsed_edge_ids = [...previousIds, edge.id];
      existingEdge.properties = props;
      edgeMap.set(dedupeKey, existingEdge);
      return;
    }

    edgeMap.set(dedupeKey, {
      ...edge,
      source: mappedSource,
      from: mappedSource,
      target: mappedTarget,
      to: mappedTarget,
      properties: {
        ...(edge.properties || {}),
        _ui_collapsed_count: 1,
        _ui_collapsed_edge_ids: [edge.id],
      },
    });
  });

  const isHasRootEdge = (edge) => {
    const edgeType = String(edge.type || edge.label || "").toUpperCase();
    return edgeType === "HAS_ROOT";
  };

  const incomingRelationTargets = new Set();
  edgeMap.forEach((edge) => {
    if (isHasRootEdge(edge)) {
      return;
    }
    const targetId = edge.target || edge.to;
    if (targetId) {
      incomingRelationTargets.add(targetId);
    }
  });

  const prunedEdges = [...edgeMap.values()].filter((edge) => {
    if (!isHasRootEdge(edge)) {
      return true;
    }
    const targetId = edge.target || edge.to;
    return !incomingRelationTargets.has(targetId);
  });

  return {
    ...graph,
    nodes: [...nodeMap.values()],
    edges: prunedEdges,
  };
}

function buildDisplayGraph(graph) {
  return state.collapseProcessNodesForView ? collapseGraphForDisplay(graph) : cloneGraphData(graph);
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

function getAllDescendants(nodeId, childrenMap) {
  const descendants = new Set();
  const stack = [nodeId];
  while (stack.length) {
    const current = stack.pop();
    const children = childrenMap.get(current) || [];
    for (const childId of children) {
      if (!descendants.has(childId)) {
        descendants.add(childId);
        stack.push(childId);
      }
    }
  }
  return descendants;
}

function getHiddenNodeIds() {
  const hiddenIds = new Set();
  state.hiddenSubnodes.forEach((descendantSet) => {
    descendantSet.forEach((id) => hiddenIds.add(id));
  });
  return hiddenIds;
}

function updateHideButtonState() {
  if (!state.lastClickedNodeId || !state.hiddenSubnodes.has(state.lastClickedNodeId)) {
    el.hideSubnodeBtn.textContent = "Hide";
    el.hideSubnodeBtn.classList.remove("active");
  } else {
    el.hideSubnodeBtn.textContent = "Show";
    el.hideSubnodeBtn.classList.add("active");
  }
}

function toggleHideSubnodes(nodeId) {
  if (!nodeId) {
    return;
  }

  const { children } = buildChildrenMap((state.displayGraph && state.displayGraph.edges) || []);
  const descendants = getAllDescendants(nodeId, children);

  if (state.hiddenSubnodes.has(nodeId)) {
    state.hiddenSubnodes.delete(nodeId);
  } else {
    state.hiddenSubnodes.set(nodeId, descendants);
  }

  applyHideStateAndRender();
  updateHideButtonState();
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
      state.lastClickedNodeId = null;
      resetInspectPanel();
      if (el.hideSubnodeBtn) {
        el.hideSubnodeBtn.disabled = true;
      }
      return;
    }

    const nodeId = params.nodes[0];
    state.lastClickedNodeId = nodeId;
    const node = state.filteredNodeMap.get(nodeId);
    if (!node) {
      state.lastClickedNodeId = null;
      resetInspectPanel("Node data not found.");
      if (el.hideSubnodeBtn) {
        el.hideSubnodeBtn.disabled = true;
      }
      return;
    }

    refreshInspectPanel();
    if (el.hideSubnodeBtn) {
      el.hideSubnodeBtn.disabled = false;
      updateHideButtonState();
    }
  });

  state.network.on("dragEnd", (params) => {
    if (!params.nodes || !params.nodes.length) {
      return;
    }

    const draggedIds = params.nodes;
    const { children } = buildChildrenMap((state.displayGraph && state.displayGraph.edges) || []);
    const latestPositions = state.network.getPositions(draggedIds);
    const positionsToUpdate = {};

    draggedIds.forEach((parentId) => {
      const oldParentPos = state.basePositions.get(parentId) || { x: 0, y: 0 };
      const newParentPos = latestPositions[parentId];
      if (!newParentPos) {
        return;
      }

      const parentNode = state.filteredNodeMap.get(parentId);
      const isRootTechnique =
        parentNode && String(parentNode.type || "").toLowerCase() === "technique";

      state.basePositions.set(parentId, { x: newParentPos.x, y: newParentPos.y });
      positionsToUpdate[parentId] = { x: newParentPos.x, y: newParentPos.y };

      const directChildren = children.get(parentId) || [];
      if (directChildren.length === 0) {
        return;
      }

      const visibleDirectChildren = directChildren.filter(
        (nodeId) => state.nodeDataSet && state.nodeDataSet.get(nodeId)
      );
      if (visibleDirectChildren.length === 0) {
        return;
      }

      if (isRootTechnique) {
        const deltaX = newParentPos.x - oldParentPos.x;
        const deltaY = newParentPos.y - oldParentPos.y;

        visibleDirectChildren.forEach((childId) => {
          const oldChildPos = state.basePositions.get(childId) || { x: 0, y: 0 };
          const newChildX = oldChildPos.x + deltaX;
          const newChildY = oldChildPos.y + deltaY;

          state.basePositions.set(childId, { x: newChildX, y: newChildY });
          positionsToUpdate[childId] = { x: newChildX, y: newChildY };

          const allDescendants = getAllDescendants(childId, children);
          allDescendants.forEach((descendantId) => {
            const oldDescPos = state.basePositions.get(descendantId) || { x: 0, y: 0 };
            state.basePositions.set(descendantId, {
              x: oldDescPos.x + deltaX,
              y: oldDescPos.y + deltaY,
            });
            positionsToUpdate[descendantId] = {
              x: oldDescPos.x + deltaX,
              y: oldDescPos.y + deltaY,
            };
          });
        });
        return;
      }

      if (state.dragRearrangeMode) {
        const subtreeNodes = new Set([parentId]);
        const subtreeEdges = [];
        const queue = [parentId];
        const visited = new Set();

        while (queue.length) {
          const nodeId = queue.shift();
          if (visited.has(nodeId)) {
            continue;
          }
          visited.add(nodeId);
          subtreeNodes.add(nodeId);

          const nodeChildren = children.get(nodeId) || [];
          nodeChildren.forEach((childId) => {
            if (state.nodeDataSet && state.nodeDataSet.get(childId)) {
              queue.push(childId);
            }
          });
        }

        ((state.displayGraph && state.displayGraph.edges) || []).forEach((edge) => {
          const from = edge.source || edge.from;
          const to = edge.target || edge.to;
          if (subtreeNodes.has(from) && subtreeNodes.has(to)) {
            subtreeEdges.push(edge);
          }
        });

        const subtreeGraph = {
          nodes: ((state.displayGraph && state.displayGraph.nodes) || []).filter((n) =>
            subtreeNodes.has(n.id)
          ),
          edges: subtreeEdges,
        };

        const canvasWidth = Math.max(420, 600);
        let layoutPositions = {};
        try {
          const subtreeChildren = new Map();
          subtreeEdges.forEach((edge) => {
            const source = edge.source || edge.from;
            const target = edge.target || edge.to;
            if (!subtreeChildren.has(source)) {
              subtreeChildren.set(source, []);
            }
            subtreeChildren.get(source).push(target);
          });

          const layoutResult = layoutSubtreeWithDepthWrap(parentId, subtreeChildren, canvasWidth);
          layoutPositions = layoutResult.positions;
        } catch (error) {
          layoutPositions = buildFallbackGridLayout(subtreeGraph, canvasWidth);
        }

        const parentLayoutPos = layoutPositions[parentId];
        const shiftX = newParentPos.x - (parentLayoutPos ? parentLayoutPos.x : 0);
        const shiftY = newParentPos.y - (parentLayoutPos ? parentLayoutPos.y : 0);

        Object.entries(layoutPositions).forEach(([nodeId, pos]) => {
          const newX = pos.x + shiftX;
          const newY = pos.y + shiftY;
          state.basePositions.set(nodeId, { x: newX, y: newY });
          positionsToUpdate[nodeId] = { x: newX, y: newY };
        });
      } else {
        const childCount = visibleDirectChildren.length;
        const baseMinRadius = 100;
        const baseMaxRadius = 240;
        const expansionThreshold = 30;

        const minRadius =
          childCount > expansionThreshold
            ? baseMinRadius + (childCount - expansionThreshold) * 2
            : baseMinRadius;
        const maxRadius =
          childCount > expansionThreshold
            ? baseMaxRadius + (childCount - expansionThreshold) * 3
            : baseMaxRadius;
        const angleStep = (2 * Math.PI) / visibleDirectChildren.length;

        visibleDirectChildren.forEach((childId, index) => {
          const oldChildPos = state.basePositions.get(childId) || { x: 0, y: 0 };
          const angle = index * angleStep;
          const randomRadius = minRadius + Math.random() * (maxRadius - minRadius);

          const newChildX = newParentPos.x + randomRadius * Math.cos(angle);
          const newChildY = newParentPos.y + randomRadius * Math.sin(angle);
          const deltaX = newChildX - oldChildPos.x;
          const deltaY = newChildY - oldChildPos.y;

          state.basePositions.set(childId, { x: newChildX, y: newChildY });
          positionsToUpdate[childId] = { x: newChildX, y: newChildY };

          const grandChildren = getAllDescendants(childId, children);
          grandChildren.forEach((grandchildId) => {
            const oldGrandchildPos = state.basePositions.get(grandchildId) || {
              x: 0,
              y: 0,
            };
            state.basePositions.set(grandchildId, {
              x: oldGrandchildPos.x + deltaX,
              y: oldGrandchildPos.y + deltaY,
            });
            positionsToUpdate[grandchildId] = {
              x: oldGrandchildPos.x + deltaX,
              y: oldGrandchildPos.y + deltaY,
            };
          });
        });
      }
    });

    const nodesToUpdate = Object.entries(positionsToUpdate).map(([id, pos]) => ({
      id,
      x: pos.x,
      y: pos.y,
    }));

    if (state.nodeDataSet && nodesToUpdate.length > 0) {
      state.nodeDataSet.update(nodesToUpdate);
    }
  });
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

async function buildPackedBaseLayout() {
  if (!state.displayGraph) {
    return;
  }

  const canvasWidth = Math.max(620, Math.floor(el.graphCanvas.clientWidth * 0.92));
  let packed = {};

  try {
    packed = buildWrappedDepthLayout(state.displayGraph, canvasWidth);
  } catch (error) {
    packed = {};
  }

  const expectedCount = ((state.displayGraph && state.displayGraph.nodes) || []).length;
  const actualCount = Object.keys(packed).length;
  if (!expectedCount || actualCount < Math.max(1, Math.floor(expectedCount * 0.6))) {
    packed = buildFallbackGridLayout(state.displayGraph, canvasWidth);
  }

  state.basePositions = new Map(Object.entries(packed));
  renderGraph(state.displayGraph, true);
}

function renderGraph(graph, keepOriginalLayout = false) {
  ensureNetwork();

  const { visNodes, visEdges } = toVisGraph(graph, keepOriginalLayout);

  state.renderedGraph = graph;
  state.filteredNodeMap = new Map((graph.nodes || []).map((node) => [node.id, node]));
  updateDataSet(state.nodeDataSet, visNodes);
  updateDataSet(state.edgeDataSet, visEdges);

  const nodeCount = visNodes.length;
  const edgeCount = visEdges.length;
  const matchedMalicious = Number((state.fullGraph && state.fullGraph.stats && state.fullGraph.stats.matched_malicious_nodes) || 0);
  const matchedWhitelist = Number((state.fullGraph && state.fullGraph.stats && state.fullGraph.stats.matched_whitelist_nodes) || 0);
  el.graphStats.textContent = `${nodeCount} nodes | ${edgeCount} edges | matched malicious ${matchedMalicious} | matched whitelist ${matchedWhitelist}`;
}

function applyHideStateAndRender() {
  const hiddenNodeIds = getHiddenNodeIds();

  let graphToRender = state.displayGraph || { nodes: [], edges: [] };

  if (hiddenNodeIds.size > 0) {
    const visibleNodes = graphToRender.nodes.filter((n) => !hiddenNodeIds.has(n.id));
    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));
    const visibleEdges = graphToRender.edges.filter((edge) => {
      const from = edge.source || edge.from;
      const to = edge.target || edge.to;
      return visibleNodeIds.has(from) && visibleNodeIds.has(to);
    });

    graphToRender = { ...graphToRender, nodes: visibleNodes, edges: visibleEdges };
  }

  renderGraph(graphToRender, true);
  refreshInspectPanel();
}

function applyDisplayAndRender() {
  state.displayGraph = buildDisplayGraph(state.fullGraph);

  const displayNodeIds = new Set((state.displayGraph.nodes || []).map((node) => node.id));
  const nextHiddenSubnodes = new Map();
  state.hiddenSubnodes.forEach((descendantSet, parentId) => {
    if (!displayNodeIds.has(parentId)) {
      return;
    }
    const nextSet = new Set([...descendantSet].filter((id) => displayNodeIds.has(id)));
    nextHiddenSubnodes.set(parentId, nextSet);
  });
  state.hiddenSubnodes = nextHiddenSubnodes;

  if (state.lastClickedNodeId && !displayNodeIds.has(state.lastClickedNodeId)) {
    state.lastClickedNodeId = null;
    el.hideSubnodeBtn.disabled = true;
    resetInspectPanel();
  }

  applyHideStateAndRender();
}

async function toggleGraphViewMode() {
  state.collapseProcessNodesForView = !state.collapseProcessNodesForView;
  updateGraphViewModeUI();

  state.hiddenSubnodes = new Map();
  state.lastClickedNodeId = null;
  el.hideSubnodeBtn.disabled = true;
  el.hideSubnodeBtn.textContent = "Hide";
  el.hideSubnodeBtn.classList.remove("active");
  resetInspectPanel();

  applyDisplayAndRender();
  await buildPackedBaseLayout();
  if (state.network) {
    state.network.fit({ animation: false });
  }

  const modeLabel = state.collapseProcessNodesForView ? "grouped-by-guid" : "raw event-node";
  setStatus(`Switched to ${modeLabel} view.`);
}

function updateTechniqueSavedState(techniqueName, saved) {
  const idx = state.techniques.findIndex((item) => item.name === techniqueName);
  if (idx < 0) {
    return;
  }
  state.techniques[idx] = { ...state.techniques[idx], saved };
  if (state.activeTechnique === techniqueName) {
    state.activeTechniqueSaved = saved;
  }
}

async function loadTechnique(technique, rebuild = false) {
  if (!technique) {
    return;
  }

  try {
    setStatus(`${rebuild ? "Building" : "Loading"} pure attack graph for ${technique}...`);
    const graphPayload = await apiGet(`/api/pure/graph?technique=${encodeURIComponent(technique)}&rebuild=${rebuild ? "1" : "0"}`);

    state.activeTechnique = technique;
    state.activeTechniqueSaved = true;
    updateTechniqueSavedState(technique, true);

    state.fullGraph = graphPayload;
    state.maliciousPatterns = normalizePatternPreview((((graphPayload || {}).patterns || {}).malicious) || []);
    state.whitelistPatterns = normalizePatternPreview((((graphPayload || {}).patterns || {}).whitelist) || []);

    state.displayGraph = null;
    state.renderedGraph = null;
    state.basePositions = new Map();
    state.hiddenSubnodes = new Map();
    state.lastClickedNodeId = null;
    resetInspectPanel();

    renderPatternPreview();
    applyDisplayAndRender();
    await buildPackedBaseLayout();

    if (state.network) {
      state.network.fit({ animation: false });
    }

    const sourceFile = graphPayload.source_file || "unknown";
    const outputHint = `Saved file: ${state.outputFolder || "clean_attack_tree"}`;
    updateBuildSummary(outputHint);
    setStatus(`Loaded pure attack graph for ${technique} from ${sourceFile}`);
  } catch (error) {
    state.fullGraph = { nodes: [], edges: [], stats: {} };
    state.displayGraph = { nodes: [], edges: [], stats: {} };
    state.renderedGraph = { nodes: [], edges: [], stats: {} };
    state.basePositions = new Map();
    state.hiddenSubnodes = new Map();
    state.lastClickedNodeId = null;
    state.maliciousPatterns = [];
    state.whitelistPatterns = [];
    resetInspectPanel();
    renderPatternPreview();
    renderGraph(state.displayGraph);
    setStatus(error.message, true);
  }
}

async function loadTechniques() {
  try {
    setStatus("Loading technique list...");
    const payload = await apiGet("/api/pure/techniques");

    const techniques = Array.isArray(payload.techniques) ? payload.techniques : [];
    state.techniques = techniques
      .map((item) => {
        if (typeof item === "string") {
          return { name: item, saved: false, output_file: "" };
        }
        return {
          name: String(item.name || "").trim(),
          saved: Boolean(item.saved),
          output_file: String(item.output_file || ""),
        };
      })
      .filter((item) => item.name);

    state.datasetFolder = String(payload.dataset_folder || "");
    state.outputFolder = String(payload.output_folder || "");

    if (!state.techniques.length) {
      state.techniqueIndex = -1;
      renderTechniqueOptions();
      updateBuildSummary();
      setStatus(`No Sysmon logs found in ${state.datasetFolder || "configured dataset folder"}.`, true);
      return;
    }

    state.techniqueIndex = 0;
    renderTechniqueOptions();
    updateBuildSummary();
    await loadTechnique(state.techniques[0].name, false);
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function selectTechniqueAt(index, rebuild = false) {
  if (index < 0 || index >= state.techniques.length) {
    return;
  }

  state.techniqueIndex = index;
  renderTechniqueOptions();
  await loadTechnique(state.techniques[index].name, rebuild);
}

async function buildCurrentTechnique() {
  if (!state.activeTechnique) {
    return;
  }

  try {
    setStatus(`Building and saving pure attack tree for ${state.activeTechnique}...`);
    const payload = await apiPost("/api/pure/build", {
      technique: state.activeTechnique,
      force_rebuild: true,
    });

    if (payload && payload.graph) {
      state.fullGraph = payload.graph;
      state.activeTechniqueSaved = true;
      updateTechniqueSavedState(state.activeTechnique, true);
      renderTechniqueOptions();
      renderPatternPreview();
      applyDisplayAndRender();
      await buildPackedBaseLayout();
      if (state.network) {
        state.network.fit({ animation: false });
      }
    }

    updateBuildSummary(`Saved: ${payload.output_file || "(unknown file)"}`);
    setStatus(`Built and saved pure attack tree for ${state.activeTechnique}.`);
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function buildAllTechniques() {
  try {
    setStatus("Building and saving pure attack trees for all techniques...");
    const payload = await apiPost("/api/pure/build-all", {
      force_rebuild: true,
    });

    const summary = `Built ${payload.built}/${payload.requested}, failed ${payload.failed}`;
    updateBuildSummary(summary);
    setStatus(`Build-all completed. ${summary}.`);

    await loadTechniques();
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function reloadSavedGraph() {
  if (!state.activeTechnique) {
    return;
  }
  await loadTechnique(state.activeTechnique, false);
}

function bindEvents() {
  el.prevBtn.addEventListener("click", async () => {
    await selectTechniqueAt(state.techniqueIndex - 1, false);
  });

  el.nextBtn.addEventListener("click", async () => {
    await selectTechniqueAt(state.techniqueIndex + 1, false);
  });

  el.techniqueSelect.addEventListener("change", async (event) => {
    const technique = event.target.value;
    const index = state.techniques.findIndex((item) => item.name === technique);
    await selectTechniqueAt(index, false);
  });

  el.graphViewModeToggle.addEventListener("click", async () => {
    await toggleGraphViewMode();
  });

  el.hideSubnodeBtn.addEventListener("click", () => {
    if (state.lastClickedNodeId) {
      toggleHideSubnodes(state.lastClickedNodeId);
    }
  });

  el.inspectNodeSourceSelect.addEventListener("change", (event) => {
    state.selectedInspectRawNodeId = String(event.target.value || "");
    refreshInspectPanel();
  });

  el.buildCurrentBtn.addEventListener("click", async () => {
    await buildCurrentTechnique();
  });

  el.buildAllBtn.addEventListener("click", async () => {
    await buildAllTechniques();
  });

  el.reloadSavedBtn.addEventListener("click", async () => {
    await reloadSavedGraph();
  });
}

async function init() {
  bindEvents();
  updateGraphViewModeUI();
  resetInspectPanel();
  updateBuildSummary();
  await loadTechniques();
}

init().catch((error) => {
  const message = error && error.message ? error.message : "Unexpected initialization error";
  setStatus(message, true);
});
