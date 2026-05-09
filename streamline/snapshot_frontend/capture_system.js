const el = {
  reloadBtn: document.getElementById("btn-reload"),
  openSnapshotBtn: document.getElementById("btn-open-snapshot"),
  graphMeta: document.getElementById("graph-meta"),
  graphCanvas: document.getElementById("graph-canvas"),
  captureDetail: document.getElementById("capture-detail"),
  nodeDetail: document.getElementById("node-detail"),
};

const GROUP_COLORS = {
  Root: "#0f766e",
  Technique: "#0f766e",
  Process: "#3f3f46",
  File: "#1d4ed8",
  Network: "#b45309",
  Registry: "#6d28d9",
  User: "#065f46",
  Wmi: "#7c2d12",
  UnknownEntity: "#475569",
};

const nodeData = new vis.DataSet([]);
const edgeData = new vis.DataSet([]);

const network = new vis.Network(
  el.graphCanvas,
  { nodes: nodeData, edges: edgeData },
  {
    layout: {
      improvedLayout: false,
      hierarchical: false,
    },
    interaction: {
      dragNodes: false,
      dragView: true,
      hover: true,
      zoomView: true,
      navigationButtons: true,
      keyboard: false,
    },
    nodes: {
      shape: "dot",
      size: 13,
      borderWidth: 1,
      font: {
        face: "Space Grotesk",
        size: 13,
      },
    },
    edges: {
      arrows: "to",
      width: 1.1,
      color: {
        color: "#8c8b87",
        highlight: "#0f766e",
      },
      font: {
        face: "IBM Plex Mono",
        size: 10,
      },
      smooth: {
        enabled: false,
      },
    },
    physics: {
      enabled: false,
    },
  }
);

let activeNodeMap = new Map();

function appendLog(message, level = "info") {
  const line = `[${new Date().toLocaleTimeString()}] ${message}`;
  if (level === "error") {
    console.error(line);
    return;
  }
  if (level === "warn") {
    console.warn(line);
    return;
  }
  console.info(line);
}

async function fetchJson(path) {
  const response = await fetch(path, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `HTTP ${response.status}`);
  }

  return response.json();
}

function normalizeNodeId(value) {
  return String(value || "").trim();
}

function normalizeRelationType(edge) {
  return String(edge.type || edge.label || ((edge.properties || {}).action || "")).trim();
}

function edgeIdFor(edge, index = 0) {
  const from = normalizeNodeId(edge.source || edge.from);
  const to = normalizeNodeId(edge.target || edge.to);
  const type = normalizeRelationType(edge) || "RELATED_TO";
  return String(edge.id || `edge:${index + 1}:${from}:${to}:${type}`);
}

function colorForGroup(group) {
  const normalizedGroup = String(group || "UnknownEntity").trim();
  if (!normalizedGroup) {
    return GROUP_COLORS.UnknownEntity;
  }

  if (GROUP_COLORS[normalizedGroup]) {
    return GROUP_COLORS[normalizedGroup];
  }

  const matchedKey = Object.keys(GROUP_COLORS).find(
    (key) => key.toLowerCase() === normalizedGroup.toLowerCase()
  );

  return matchedKey ? GROUP_COLORS[matchedKey] : GROUP_COLORS.UnknownEntity;
}

function buildCaptureGraph(rawGraph) {
  const nodeMap = new Map();
  const edgeByKey = new Map();
  const inDegree = new Map();
  const outDegree = new Map();

  const ensureDegree = (nodeId) => {
    if (!nodeId) {
      return;
    }
    if (!inDegree.has(nodeId)) {
      inDegree.set(nodeId, 0);
    }
    if (!outDegree.has(nodeId)) {
      outDegree.set(nodeId, 0);
    }
  };

  (rawGraph.nodes || []).forEach((node) => {
    const nodeId = normalizeNodeId(node && node.id);
    if (!nodeId) {
      return;
    }

    const properties = (node && node.properties) || {};
    const group = String((node && (node.group || node.type)) || "UnknownEntity").trim() || "UnknownEntity";
    const type = String((node && (node.type || node.group)) || group).trim() || group;
    const label = String(
      (node && node.label) || properties.display_name || properties.name || nodeId
    ).trim() || nodeId;

    nodeMap.set(nodeId, {
      ...node,
      id: nodeId,
      label,
      type,
      group,
      properties,
    });

    ensureDegree(nodeId);
  });

  (rawGraph.edges || []).forEach((edge, index) => {
    const source = normalizeNodeId(edge && (edge.source || edge.from));
    const target = normalizeNodeId(edge && (edge.target || edge.to));
    if (!source || !target || source === target || !nodeMap.has(source) || !nodeMap.has(target)) {
      return;
    }

    const type = normalizeRelationType(edge) || "RELATED_TO";
    const edgeKey = `${source}|${target}|${type}`;
    if (!edgeByKey.has(edgeKey)) {
      edgeByKey.set(edgeKey, {
        ...edge,
        id: edgeIdFor(edge, index),
        source,
        target,
        type,
      });
    }

    ensureDegree(source);
    ensureDegree(target);
    outDegree.set(source, Number(outDegree.get(source) || 0) + 1);
    inDegree.set(target, Number(inDegree.get(target) || 0) + 1);
  });

  const looksLikeLiveSysmon = (node) => {
    const properties = (node && node.properties) || {};
    const tokens = [
      String(node && node.id || ""),
      String(node && node.label || ""),
      String(node && node.type || ""),
      String(node && node.group || ""),
      String(properties.display_name || ""),
      String(properties.name || ""),
    ].join(" ").toLowerCase();

    return (
      tokens.includes("live_sysmon") ||
      tokens.includes("live sysmon") ||
      tokens.includes("sysmon root")
    );
  };

  let syntheticRootId = "";
  nodeMap.forEach((node, nodeId) => {
    if (!syntheticRootId && looksLikeLiveSysmon(node)) {
      syntheticRootId = nodeId;
    }
  });

  if (!syntheticRootId) {
    syntheticRootId = "LIVE_SYSMON_ROOT";
    let suffix = 1;
    while (nodeMap.has(syntheticRootId)) {
      suffix += 1;
      syntheticRootId = `LIVE_SYSMON_ROOT_${suffix}`;
    }

    nodeMap.set(syntheticRootId, {
      id: syntheticRootId,
      label: "LIVE_SYSMON Root",
      type: "Root",
      group: "Root",
      properties: {
        synthetic: true,
      },
    });
    ensureDegree(syntheticRootId);
  }

  const rootIds = [...nodeMap.keys()].filter(
    (nodeId) => nodeId !== syntheticRootId && Number(inDegree.get(nodeId) || 0) === 0
  );

  if (!rootIds.length) {
    [...outDegree.entries()]
      .map(([nodeId, degree]) => ({
        nodeId,
        degree: Number(degree) || 0,
      }))
      .filter((entry) => entry.nodeId !== syntheticRootId && entry.degree > 0)
      .sort((left, right) => right.degree - left.degree)
      .slice(0, 64)
      .forEach((entry) => {
        rootIds.push(entry.nodeId);
      });
  }

  if (!rootIds.length) {
    const firstNode = [...nodeMap.keys()].find((nodeId) => nodeId !== syntheticRootId);
    if (firstNode) {
      rootIds.push(firstNode);
    }
  }

  rootIds.forEach((rootId, index) => {
    const edgeKey = `${syntheticRootId}|${rootId}|HAS_ROOT`;
    if (edgeByKey.has(edgeKey)) {
      return;
    }

    edgeByKey.set(edgeKey, {
      id: `capture_root:${index + 1}:${syntheticRootId}:${rootId}`,
      source: syntheticRootId,
      target: rootId,
      type: "HAS_ROOT",
      properties: {
        synthetic: true,
      },
    });
  });

  return {
    nodes: [...nodeMap.values()],
    edges: [...edgeByKey.values()],
    syntheticRootId,
    rootIds,
  };
}

function computeLayout(graph) {
  const MIN_ARC_SPACING = 120;
  const MIN_RADIAL_GAP = 180;
  const START_ANGLE = -Math.PI / 2;

  const nodeById = new Map(
    (graph.nodes || [])
      .map((node) => [normalizeNodeId(node.id), node])
      .filter((entry) => Boolean(entry[0]))
  );

  const syntheticRootId = normalizeNodeId(graph.syntheticRootId);
  const adjacency = new Map();

  nodeById.forEach((_node, nodeId) => {
    adjacency.set(nodeId, new Set());
  });

  (graph.edges || []).forEach((edge) => {
    const source = normalizeNodeId(edge.source || edge.from);
    const target = normalizeNodeId(edge.target || edge.to);
    if (!source || !target || source === target || !nodeById.has(source) || !nodeById.has(target)) {
      return;
    }

    adjacency.get(source).add(target);
    adjacency.get(target).add(source);
  });

  const depthByNode = new Map();
  const queue = [];

  if (syntheticRootId && nodeById.has(syntheticRootId)) {
    depthByNode.set(syntheticRootId, 0);
    queue.push(syntheticRootId);
  }

  while (queue.length) {
    const current = queue.shift();
    const currentDepth = Number(depthByNode.get(current) || 0);
    const neighbors = adjacency.get(current) || new Set();

    neighbors.forEach((neighborId) => {
      if (depthByNode.has(neighborId)) {
        return;
      }

      depthByNode.set(neighborId, currentDepth + 1);
      queue.push(neighborId);
    });
  }

  let fallbackDepth = depthByNode.size
    ? Math.max(...[...depthByNode.values()].map((value) => Number(value) || 0)) + 1
    : 1;

  [...nodeById.keys()]
    .filter((nodeId) => !depthByNode.has(nodeId))
    .sort((left, right) => {
      const leftNode = nodeById.get(left) || {};
      const rightNode = nodeById.get(right) || {};
      const leftLabel = String(leftNode.label || leftNode.id || left);
      const rightLabel = String(rightNode.label || rightNode.id || right);
      return leftLabel.localeCompare(rightLabel);
    })
    .forEach((nodeId) => {
      depthByNode.set(nodeId, fallbackDepth);
      fallbackDepth += 1;
    });

  const levels = new Map();
  depthByNode.forEach((depth, nodeId) => {
    const normalizedDepth = Math.max(0, Number(depth) || 0);
    if (!levels.has(normalizedDepth)) {
      levels.set(normalizedDepth, []);
    }
    levels.get(normalizedDepth).push(nodeId);
  });

  const positions = new Map();
  let previousRadius = 0;

  [...levels.keys()]
    .sort((left, right) => left - right)
    .forEach((depth) => {
      const levelNodeIds = levels.get(depth) || [];
      levelNodeIds.sort((left, right) => {
        const leftNode = nodeById.get(left) || {};
        const rightNode = nodeById.get(right) || {};
        const leftGroup = String(leftNode.group || "");
        const rightGroup = String(rightNode.group || "");
        if (leftGroup !== rightGroup) {
          return leftGroup.localeCompare(rightGroup);
        }
        const leftLabel = String(leftNode.label || leftNode.id || left);
        const rightLabel = String(rightNode.label || rightNode.id || right);
        return leftLabel.localeCompare(rightLabel);
      });

      if (depth === 0) {
        levelNodeIds.forEach((nodeId, index) => {
          if (index === 0) {
            positions.set(nodeId, { x: 0, y: 0 });
            return;
          }

          const extraRadius = MIN_RADIAL_GAP;
          const angle = START_ANGLE + (index * (2 * Math.PI)) / Math.max(1, levelNodeIds.length - 1);
          positions.set(nodeId, {
            x: Math.cos(angle) * extraRadius,
            y: Math.sin(angle) * extraRadius,
          });
        });
        previousRadius = Math.max(previousRadius, MIN_RADIAL_GAP);
        return;
      }

      const count = levelNodeIds.length;
      const spacingRadius = count <= 1 ? 0 : (count * MIN_ARC_SPACING) / (2 * Math.PI);
      const radius = Math.max(previousRadius + MIN_RADIAL_GAP, spacingRadius);
      const angleStep = (2 * Math.PI) / Math.max(1, count);
      const angleOffset = START_ANGLE + (depth * Math.PI) / 12;

      levelNodeIds.forEach((nodeId, index) => {
        const angle = angleOffset + angleStep * index;
        positions.set(nodeId, {
          x: Math.cos(angle) * radius,
          y: Math.sin(angle) * radius,
        });
      });

      previousRadius = radius;
    });

  if (syntheticRootId && !positions.has(syntheticRootId)) {
    positions.set(syntheticRootId, { x: 0, y: 0 });
  }

  return positions;
}

function inspectValue(value) {
  if (value === null || value === undefined) {
    return "-";
  }

  if (typeof value === "string") {
    const trimmed = value.replace(/[\u0000-\u001F\u007F]/g, " ").replace(/\s+/g, " ").trim();
    return trimmed || "-";
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  try {
    return JSON.stringify(value);
  } catch (_error) {
    return String(value);
  }
}

function formatInspectRows(rows) {
  if (!rows.length) {
    return [];
  }

  const keyWidth = rows.reduce((maxWidth, row) => Math.max(maxWidth, row[0].length), 0);
  return rows.map((row) => `${row[0].padEnd(keyWidth, " ")} : ${row[1]}`);
}

function formatNodeInspect(node) {
  const props = (node && node.properties) || {};
  const lines = [];

  const identityRows = [
    ["id", inspectValue(node && node.id)],
    ["label", inspectValue(node && node.label)],
    ["type", inspectValue(node && node.type)],
    ["group", inspectValue(node && node.group)],
  ];

  lines.push("[Node]");
  lines.push(...formatInspectRows(identityRows));

  const propKeys = Object.keys(props).sort((left, right) => left.localeCompare(right));
  if (propKeys.length) {
    lines.push("");
    lines.push(`[Properties: ${propKeys.length}]`);
    lines.push(...formatInspectRows(propKeys.map((key) => [key, inspectValue(props[key])] )));
  }

  return lines.join("\n");
}

function renderCapture(rawGraph) {
  const captureGraph = buildCaptureGraph(rawGraph || { nodes: [], edges: [] });
  const layout = computeLayout(captureGraph);

  activeNodeMap = new Map(
    (captureGraph.nodes || [])
      .map((node) => [normalizeNodeId(node.id), node])
      .filter((entry) => Boolean(entry[0]))
  );

  const visNodes = (captureGraph.nodes || []).map((node) => {
    const nodeId = normalizeNodeId(node.id);
    const group = String(node.group || "UnknownEntity");
    const color = colorForGroup(group);
    const isCaptureRoot = nodeId === captureGraph.syntheticRootId;
    const position = layout.get(nodeId) || { x: 0, y: 0 };

    return {
      id: nodeId,
      label: String(node.label || node.id || ""),
      title: `${group}: ${String(node.label || node.id || "")}`,
      x: position.x,
      y: position.y,
      fixed: {
        x: true,
        y: true,
      },
      size: isCaptureRoot ? 22 : 13,
      color: {
        border: isCaptureRoot ? "#0f766e" : color,
        background: isCaptureRoot ? "#d4f3ef" : `${color}22`,
        highlight: {
          border: isCaptureRoot ? "#0f766e" : color,
          background: isCaptureRoot ? "#a7e6dc" : `${color}44`,
        },
      },
      font: {
        color: "#1f2937",
        size: isCaptureRoot ? 15 : 13,
      },
    };
  });

  const visEdges = (captureGraph.edges || [])
    .map((edge, index) => {
      const from = normalizeNodeId(edge.source || edge.from);
      const to = normalizeNodeId(edge.target || edge.to);
      if (!from || !to) {
        return null;
      }

      const type = normalizeRelationType(edge) || "RELATED_TO";
      const isRootRelation = type.toUpperCase() === "HAS_ROOT";

      return {
        id: edgeIdFor(edge, index),
        from,
        to,
        label: type,
        title: type,
        dashes: isRootRelation,
        width: isRootRelation ? 1.5 : 1.1,
        color: {
          color: isRootRelation ? "#0f766e" : "#8c8b87",
          highlight: "#0f766e",
        },
      };
    })
    .filter(Boolean);

  nodeData.clear();
  edgeData.clear();
  nodeData.add(visNodes);
  edgeData.add(visEdges);

  const rootNode = activeNodeMap.get(captureGraph.syntheticRootId) || null;
  const rootLabel = String((rootNode && (rootNode.label || rootNode.id)) || "LIVE_SYSMON Root");

  if (visNodes.length) {
    const rootPosition = layout.get(captureGraph.syntheticRootId) || { x: 0, y: 0 };
    const rootId = String(captureGraph.syntheticRootId || "").trim();
    const focusRoot = () => {
      if (rootId) {
        try {
          network.focus(rootId, {
            scale: 1,
            animation: false,
          });
        } catch (_error) {
          // Ignore focus failures and still enforce moveTo fallback.
        }
      }

      network.moveTo({
        position: {
          x: Number(rootPosition.x) || 0,
          y: Number(rootPosition.y) || 0,
        },
        scale: 1,
        animation: false,
      });
    };

    focusRoot();
    if (typeof network.once === "function") {
      network.once("afterDrawing", focusRoot);
    }
    if (typeof requestAnimationFrame === "function") {
      requestAnimationFrame(focusRoot);
    }
    if (typeof setTimeout === "function") {
      setTimeout(focusRoot, 0);
      setTimeout(focusRoot, 140);
      setTimeout(focusRoot, 900);
    }
  }

  const generatedAt = new Date().toLocaleString();
  el.graphMeta.textContent = [
    "static capture",
    "layout radial_360",
    "drag nodes disabled",
    "infinite canvas pan/zoom",
    `${visNodes.length} nodes`,
    `${visEdges.length} edges`,
    `roots ${captureGraph.rootIds.length}`,
  ].join(" | ");

  el.captureDetail.textContent = [
    `capture_time: ${generatedAt}`,
    `root_node: ${rootLabel}`,
    `roots_linked: ${captureGraph.rootIds.length}`,
    `total_nodes: ${visNodes.length}`,
    `total_edges: ${visEdges.length}`,
    "render_mode: static_once_radial_360",
    "interaction: hover, click, pan, zoom",
    "layout_edit: disabled",
    "drag_nodes: disabled",
  ].join("\n");

  el.nodeDetail.textContent = "Click a node to inspect.";
}

async function loadCapture() {
  el.graphMeta.textContent = "Loading capture...";
  try {
    const payload = await fetchJson("/api/live/raw");
    const rawGraph = payload.graph || { nodes: [], edges: [], stats: {} };
    renderCapture(rawGraph);
    appendLog("Capture rendered.");
  } catch (error) {
    appendLog(`Capture load failed: ${error.message || error}`, "error");
    el.graphMeta.textContent = "Failed to load capture.";
  }
}

network.on("click", (params) => {
  if (!params.nodes || !params.nodes.length) {
    el.nodeDetail.textContent = "Click a node to inspect.";
    return;
  }

  const nodeId = normalizeNodeId(params.nodes[0]);
  const node = activeNodeMap.get(nodeId);
  if (!node) {
    el.nodeDetail.textContent = `Node not found: ${nodeId}`;
    return;
  }

  el.nodeDetail.textContent = formatNodeInspect(node);
});

el.reloadBtn.addEventListener("click", () => {
  loadCapture().catch((error) => {
    appendLog(`Reload failed: ${error.message || error}`, "error");
  });
});

el.openSnapshotBtn.addEventListener("click", () => {
  window.open("./index.html", "_blank", "noopener,noreferrer");
});

loadCapture().catch((error) => {
  appendLog(`Initial capture load failed: ${error.message || error}`, "error");
});
