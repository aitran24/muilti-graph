const el = {
  refreshBtn: document.getElementById("btn-refresh"),
  listMeta: document.getElementById("list-meta"),
  snapshotList: document.getElementById("snapshot-list"),
  graphTitle: document.getElementById("graph-title"),
  graphMeta: document.getElementById("graph-meta"),
  graphCanvas: document.getElementById("graph-canvas"),
  matchDetail: document.getElementById("match-detail"),
  nodeDetail: document.getElementById("node-detail"),
};

const GROUP_COLORS = {
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
      hierarchical: {
        enabled: true,
        direction: "UD",
        sortMethod: "directed",
        levelSeparation: 170,
        nodeSpacing: 165,
        treeSpacing: 210,
      },
    },
    interaction: {
      dragNodes: true,
      dragView: true,
      hover: true,
      zoomView: true,
      navigationButtons: true,
      keyboard: true,
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

let snapshots = [];
let activeSnapshotId = "";
let activeNodeMap = new Map();

function colorForGroup(group) {
  return GROUP_COLORS[group] || "#334155";
}

function normalizeRelationType(edge) {
  return String(edge.type || edge.label || ((edge.properties || {}).action || "")).trim();
}

function edgeIdFor(edge, index = 0) {
  const from = String(edge.source || edge.from || "").trim();
  const to = String(edge.target || edge.to || "").trim();
  const type = normalizeRelationType(edge) || "RELATED_TO";
  return String(edge.id || `edge:${index + 1}:${from}:${to}:${type}`);
}

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

function fmtScore(value) {
  return Number(value || 0).toFixed(4);
}

function fmtTime(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString();
}

function snapshotQueryParam() {
  const params = new URLSearchParams(window.location.search || "");
  return String(params.get("snapshot_id") || "").trim();
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

async function loadSnapshotList(preferredId = "") {
  try {
    const payload = await fetchJson("/api/snapshots?limit=300");
    snapshots = Array.isArray(payload.snapshots) ? payload.snapshots : [];
    renderSnapshotList();

    const selected = preferredId || activeSnapshotId;
    if (selected && snapshots.some((item) => item.snapshot_id === selected)) {
      await openSnapshot(selected);
      return;
    }

    if (snapshots.length) {
      await openSnapshot(snapshots[0].snapshot_id);
      return;
    }

    activeSnapshotId = "";
    activeNodeMap = new Map();
    nodeData.clear();
    edgeData.clear();
    el.graphTitle.textContent = "Snapshot Graph";
    el.listMeta.textContent = "0 snapshots";
    el.graphMeta.textContent = "No snapshots available.";
    el.matchDetail.textContent = "-";
    el.nodeDetail.textContent = "Click a node to inspect.";
  } catch (error) {
    appendLog(`Failed to load snapshots: ${error.message || error}`, "error");
    el.listMeta.textContent = "Failed to load";
  }
}

function renderSnapshotList() {
  el.snapshotList.innerHTML = "";
  el.listMeta.textContent = `${snapshots.length} snapshots`;

  if (!snapshots.length) {
    const empty = document.createElement("article");
    empty.className = "snapshot-item empty";
    empty.textContent = "No snapshots yet. Trigger one from the match UI.";
    el.snapshotList.appendChild(empty);
    return;
  }

  snapshots.forEach((item) => {
    const card = document.createElement("article");
    card.className = `snapshot-item${item.snapshot_id === activeSnapshotId ? " active" : ""}`;
    card.dataset.snapshotId = item.snapshot_id;

    const id = document.createElement("div");
    id.className = "snapshot-id";
    id.textContent = item.snapshot_id;
    card.appendChild(id);

    const meta = document.createElement("div");
    meta.className = "snapshot-meta";
    meta.textContent = [
      item.technique || "unknown",
      item.algorithm || "unknown",
      `score=${fmtScore(item.score)}`,
      fmtTime(item.created_at),
    ].join(" | ");
    card.appendChild(meta);

    card.addEventListener("click", () => {
      openSnapshot(item.snapshot_id).catch((error) => {
        appendLog(`Failed to open snapshot: ${error.message || error}`, "error");
      });
    });

    el.snapshotList.appendChild(card);
  });
}

function buildFallbackContextGraph(snapshot) {
  const fullGraph = snapshot.graph || { nodes: [], edges: [], stats: {} };
  const fullNodes = Array.isArray(fullGraph.nodes) ? fullGraph.nodes : [];
  const fullEdges = Array.isArray(fullGraph.edges) ? fullGraph.edges : [];
  const selectedNodeIds = new Set(((snapshot.highlight || {}).node_ids || []).map((value) => String(value || "").trim()).filter(Boolean));

  if (!selectedNodeIds.size) {
    return null;
  }

  const nodes = fullNodes.filter((node) => selectedNodeIds.has(String(node.id || "").trim()));
  const edges = fullEdges.filter((edge) => {
    const from = String(edge.source || edge.from || "").trim();
    const to = String(edge.target || edge.to || "").trim();
    return selectedNodeIds.has(from) && selectedNodeIds.has(to);
  });

  return {
    nodes,
    edges,
    stats: {
      ...(fullGraph.stats || {}),
      total_nodes: fullNodes.length,
      total_edges: fullEdges.length,
      context_nodes: nodes.length,
      context_edges: edges.length,
      is_context_filtered: true,
      built_from_highlight: true,
    },
  };
}

function renderGraph(snapshot) {
  const contextGraph = snapshot.context_graph || {};
  const hasStoredContextGraph = Array.isArray(contextGraph.nodes) && contextGraph.nodes.length > 0;
  const fallbackContextGraph = hasStoredContextGraph ? null : buildFallbackContextGraph(snapshot);
  const hasContextGraph = hasStoredContextGraph || Boolean(fallbackContextGraph);
  const graph = hasStoredContextGraph
    ? contextGraph
    : (fallbackContextGraph || (snapshot.graph || { nodes: [], edges: [] }));
  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];
  const fullGraph = snapshot.graph || { nodes: [], edges: [] };
  const fullNodes = Array.isArray(fullGraph.nodes) ? fullGraph.nodes : [];
  const fullEdges = Array.isArray(fullGraph.edges) ? fullGraph.edges : [];

  activeNodeMap = new Map(nodes.map((node) => [String(node.id), node]));

  const highlight = snapshot.highlight || {};
  const highlightNodeIds = new Set((highlight.node_ids || []).map((value) => String(value)));
  const highlightEdgeIds = new Set((highlight.edge_ids || []).map((value) => String(value)));
  const matchedNodeIds = new Set((snapshot.matched_node_ids || []).map((value) => String(value)));

  const visNodes = nodes.map((node) => {
    const nodeId = String(node.id || "");
    const group = String(node.group || "UnknownEntity");
    const color = colorForGroup(group);
    const isHighlighted = highlightNodeIds.has(nodeId);
    const isMatched = matchedNodeIds.has(nodeId);

    return {
      id: nodeId,
      label: String(node.label || node.id || ""),
      title: `${group}: ${String(node.label || node.id || "")}`,
      hidden: false,
      size: isMatched ? 17 : isHighlighted ? 14 : 13,
      color: {
        border: isMatched ? "#dc2626" : isHighlighted ? "#2563eb" : color,
        background: isMatched ? "#fee2e2" : isHighlighted ? "#dbeafe" : `${color}22`,
        highlight: {
          border: isMatched ? "#dc2626" : isHighlighted ? "#2563eb" : color,
          background: isMatched ? "#fecaca" : isHighlighted ? "#bfdbfe" : `${color}44`,
        },
      },
      font: {
        color: "#1f2937",
      },
    };
  });

  const visEdges = edges
    .map((edge, index) => {
      const from = String(edge.source || edge.from || "").trim();
      const to = String(edge.target || edge.to || "").trim();
      if (!from || !to) {
        return null;
      }

      const edgeId = edgeIdFor(edge, index);
      const type = normalizeRelationType(edge) || "RELATED_TO";
      const isRoot = type.toUpperCase() === "HAS_ROOT";
      const isHighlighted = highlightEdgeIds.has(edgeId);

      return {
        id: edgeId,
        from,
        to,
        label: type,
        title: type,
        hidden: false,
        dashes: isRoot,
        width: isHighlighted ? 1.8 : 1.1,
        color: {
          color: isHighlighted ? "#2563eb" : isRoot ? "#0f766e" : "#8c8b87",
          highlight: isHighlighted ? "#2563eb" : "#0f766e",
        },
      };
    })
    .filter(Boolean);

  nodeData.clear();
  edgeData.clear();
  nodeData.add(visNodes);
  edgeData.add(visEdges);

  if (visNodes.length) {
    network.fit({ animation: false });
  }

  const matchedVisibleCount = visNodes.reduce(
    (count, node) => (matchedNodeIds.has(String(node.id || "")) ? count + 1 : count),
    0
  );

  const stats = graph.stats || {};
  el.graphMeta.textContent = [
    hasContextGraph ? "view context-only" : "view full-pruned",
    `nodes ${visNodes.length}`,
    `edges ${visEdges.length}`,
    `full ${fullNodes.length}N/${fullEdges.length}E`,
    `trees ${Number((snapshot.trees || []).length)}`,
    `subtrees ${Number((snapshot.subtrees || []).length)}`,
    `matched_visible ${matchedVisibleCount}/${matchedNodeIds.size}`,
    `highlight ${highlightNodeIds.size}`,
    `stored ${fmtTime(snapshot.created_at)}`,
    stats.total_nodes ? `raw_total ${stats.total_nodes}` : "",
  ]
    .filter(Boolean)
    .join(" | ");
}

function _inspectValue(value) {
  if (value === null || value === undefined) {
    return "-";
  }

  let text = "";
  if (typeof value === "string") {
    text = value;
  } else if (typeof value === "number" || typeof value === "boolean") {
    text = String(value);
  } else {
    try {
      text = JSON.stringify(value);
    } catch {
      text = String(value);
    }
  }

  const compact = String(text)
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  if (!compact) {
    return "-";
  }

  return compact;
}

function _formatInspectRows(rows) {
  if (!rows.length) {
    return [];
  }

  const keyWidth = rows.reduce((maxWidth, row) => Math.max(maxWidth, row[0].length), 0);
  return rows.map(([key, value]) => `${key.padEnd(keyWidth, " ")} : ${value}`);
}

function _collectInspectRows(props, keys, rendered) {
  const rows = [];
  keys.forEach((key) => {
    if (!(key in props)) {
      return;
    }

    const value = _inspectValue(props[key]);
    if (value === "-") {
      return;
    }

    rendered.add(key);
    rows.push([key, value]);
  });
  return rows;
}

function formatNodeInspect(node) {
  const props = (node && node.properties) || {};
  const lines = [];
  const rendered = new Set();

  const identityRows = [
    ["id", _inspectValue(node && node.id)],
    ["label", _inspectValue(node && node.label)],
    ["type", _inspectValue(node && node.type)],
    ["group", _inspectValue(node && node.group)],
  ];
  lines.push("[Node]");
  lines.push(..._formatInspectRows(identityRows));

  const processKeys = [
    "display_name",
    "name",
    "process_name",
    "image_path",
    "command_line",
    "original_file_name",
    "parent_process_id",
    "user_id",
    "event_id",
  ];
  const processRows = _collectInspectRows(props, processKeys, rendered);
  if (processRows.length) {
    lines.push("");
    lines.push("[Process]");
    lines.push(..._formatInspectRows(processRows));
  }

  const artifactKeys = [
    "file_path",
    "source_image_path",
    "destination_ip",
    "destination_port",
    "source_ip",
    "source_port",
    "protocol",
    "target_object",
    "query_name",
  ];
  const artifactRows = _collectInspectRows(props, artifactKeys, rendered);
  if (artifactRows.length) {
    lines.push("");
    lines.push("[Artifacts]");
    lines.push(..._formatInspectRows(artifactRows));
  }

  const hashKeys = [
    "image_hash",
    "command_hash",
  ];
  const hashRows = _collectInspectRows(props, hashKeys, rendered);
  if (hashRows.length) {
    lines.push("");
    lines.push("[Hashes]");
    lines.push(..._formatInspectRows(hashRows));
  }

  const otherEntries = Object.keys(props)
    .filter((key) => !rendered.has(key))
    .sort((left, right) => left.localeCompare(right));

  if (otherEntries.length) {
    lines.push("");
    lines.push(`[Other Properties: ${otherEntries.length}]`);

    const otherRows = otherEntries.map((key) => [key, _inspectValue(props[key])]);
    lines.push(..._formatInspectRows(otherRows));
  }

  return lines.join("\n");
}

function renderMatchDetail(snapshot) {
  const match = snapshot.match || {};
  const lines = [
    `snapshot_id: ${snapshot.snapshot_id || ""}`,
    `graph_revision: ${snapshot.graph_revision || 0}`,
    `algorithm: ${match.algorithm || ""}`,
    `technique: ${match.technique || ""}`,
    `score: ${fmtScore(match.score)}`,
    `runtime_ms: ${Number(match.runtime_ms || 0).toFixed(2)}`,
    `matched_nodes: ${(snapshot.matched_node_ids || []).length}`,
    `trees: ${(snapshot.trees || []).length}`,
    `subtrees: ${(snapshot.subtrees || []).length}`,
    `created_at: ${fmtTime(snapshot.created_at)}`,
    "",
    "notes:",
    String(match.notes || "(none)"),
  ];

  el.matchDetail.textContent = lines.join("\n");
}

async function openSnapshot(snapshotId) {
  const id = String(snapshotId || "").trim();
  if (!id) {
    return;
  }

  const payload = await fetchJson(`/api/snapshots/${encodeURIComponent(id)}`);
  activeSnapshotId = id;
  renderSnapshotList();

  const technique = (((payload.match || {}).technique) || "unknown").trim();
  el.graphTitle.textContent = `Snapshot Graph - ${technique}`;

  renderGraph(payload);
  renderMatchDetail(payload);
  el.nodeDetail.textContent = "Click a node to inspect.";
}

network.on("click", (params) => {
  if (!params.nodes || !params.nodes.length) {
    el.nodeDetail.textContent = "Click a node to inspect.";
    return;
  }

  const nodeId = String(params.nodes[0] || "").trim();
  const node = activeNodeMap.get(nodeId);
  if (!node) {
    el.nodeDetail.textContent = `Node not found: ${nodeId}`;
    return;
  }

  el.nodeDetail.textContent = formatNodeInspect(node);
});

el.refreshBtn.addEventListener("click", () => {
  loadSnapshotList(activeSnapshotId).catch((error) => {
    appendLog(`Refresh failed: ${error.message || error}`, "error");
  });
});

loadSnapshotList(snapshotQueryParam()).catch((error) => {
  appendLog(`Initial load failed: ${error.message || error}`, "error");
});
