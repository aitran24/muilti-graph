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

const GraphView = window.Streamline && window.Streamline.GraphView;
if (!GraphView) {
  throw new Error("Snapshot frontend initialization failed: missing Streamline.GraphView.");
}

const graphView = new GraphView(el.graphCanvas, {
  defaultViewMode: "raw",
  childHideThreshold: 0,
});

let snapshots = [];
let activeSnapshotId = "";

function normalizeRelationType(edge) {
  return String(edge.type || edge.label || ((edge.properties || {}).action || "")).trim();
}

function normalizeRelationForFilter(edge) {
  return normalizeRelationType(edge).toLowerCase().replace(/[\s_-]+/g, "");
}

function normalizeNodeId(value) {
  return String(value || "").trim();
}

function edgeEndpoints(edge) {
  return {
    from: normalizeNodeId(edge && (edge.source || edge.from)),
    to: normalizeNodeId(edge && (edge.target || edge.to)),
  };
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
    graphView.renderSnapshot({ nodes: [], edges: [] });
    graphView.clearHighlightContext();
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
  const sourceNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const sourceEdges = Array.isArray(graph.edges) ? graph.edges : [];

  const processAccessEndpointIds = new Set();
  const nonProcessAccessIncidentIds = new Set();
  sourceEdges.forEach((edge) => {
    const from = String(edge.source || edge.from || "").trim();
    const to = String(edge.target || edge.to || "").trim();
    if (!from || !to) {
      return;
    }

    if (normalizeRelationForFilter(edge) === "processaccess") {
      processAccessEndpointIds.add(from);
      processAccessEndpointIds.add(to);
      return;
    }

    nonProcessAccessIncidentIds.add(from);
    nonProcessAccessIncidentIds.add(to);
  });

  const processAccessOnlyNodeIds = new Set(
    [...processAccessEndpointIds].filter((nodeId) => !nonProcessAccessIncidentIds.has(nodeId))
  );

  const candidateNodes = sourceNodes.filter((node) => {
    const nodeId = String((node && node.id) || "").trim();
    return nodeId && !processAccessOnlyNodeIds.has(nodeId);
  });

  const candidateNodeIds = new Set(
    candidateNodes.map((node) => String((node && node.id) || "").trim()).filter(Boolean)
  );

  const candidateEdges = sourceEdges.filter((edge) => {
    if (normalizeRelationForFilter(edge) === "processaccess") {
      return false;
    }
    const { from, to } = edgeEndpoints(edge);
    return candidateNodeIds.has(from) && candidateNodeIds.has(to);
  });

  const connectedNodeIds = new Set();
  candidateEdges.forEach((edge) => {
    const { from, to } = edgeEndpoints(edge);
    if (from) {
      connectedNodeIds.add(from);
    }
    if (to) {
      connectedNodeIds.add(to);
    }
  });

  const nodes = candidateNodes.filter((node) => connectedNodeIds.has(normalizeNodeId(node && node.id)));

  const loadedNodeIds = new Set(
    nodes.map((node) => normalizeNodeId(node && node.id)).filter(Boolean)
  );

  const edges = candidateEdges.filter((edge) => {
    const { from, to } = edgeEndpoints(edge);
    return loadedNodeIds.has(from) && loadedNodeIds.has(to);
  });

  const hiddenProcessAccessNodeCount = processAccessOnlyNodeIds.size;
  const hiddenDanglingNodeCount = Math.max(0, candidateNodes.length - nodes.length);
  const fullGraph = snapshot.graph || { nodes: [], edges: [] };
  const fullNodes = Array.isArray(fullGraph.nodes) ? fullGraph.nodes : [];
  const fullEdges = Array.isArray(fullGraph.edges) ? fullGraph.edges : [];

  const highlight = snapshot.highlight || {};
  const highlightNodeIds = new Set((highlight.node_ids || []).map((value) => String(value)));
  const highlightEdgeIds = new Set((highlight.edge_ids || []).map((value) => String(value)));
  const maliciousNodeIds = new Set(
    (snapshot.malicious_node_ids || [])
      .map((value) => String(value || "").trim())
      .filter(Boolean)
  );
  const coreNodeIds = new Set(
    (snapshot.core_node_ids || [])
      .map((value) => String(value || "").trim())
      .filter(Boolean)
  );
  const evidenceNodeIds = new Set(
    (snapshot.evidence_node_ids || [])
      .map((value) => String(value || "").trim())
      .filter(Boolean)
  );
  const matchedNodeIds = evidenceNodeIds.size
    ? new Set(evidenceNodeIds)
    : new Set([...maliciousNodeIds, ...coreNodeIds]);
  const strongNodeIds = new Set((highlight.strong_node_ids || []).map((value) => String(value || "").trim()).filter(Boolean));
  const strongEdgeIds = new Set((highlight.strong_edge_ids || []).map((value) => String(value || "").trim()).filter(Boolean));

  // Backward compatibility for older snapshots without precomputed strong sets.
  if (!strongNodeIds.size && !strongEdgeIds.size) {
    [...(snapshot.trees || []), ...(snapshot.subtrees || [])]
      .filter((tree) => Boolean(tree && tree.contains_core_hit))
      .forEach((tree) => {
        (tree.node_ids || []).forEach((nodeId) => {
          const normalized = String(nodeId || "").trim();
          if (normalized) {
            strongNodeIds.add(normalized);
          }
        });
        (tree.edge_ids || []).forEach((edgeId) => {
          const normalized = String(edgeId || "").trim();
          if (normalized) {
            strongEdgeIds.add(normalized);
          }
        });
      });
  }

  graphView.renderSnapshot({ ...graph, nodes, edges });
  if (loadedNodeIds.size) {
    graphView.setNodeVisibilityFilter(loadedNodeIds, []);
  } else {
    graphView.clearNodeVisibilityFilter();
  }

  const loadedEdgeIds = new Set(
    edges
      .map((edge) => String((edge && edge.id) || "").trim())
      .filter(Boolean)
  );
  const boundedHighlightNodeIds = new Set(
    [...highlightNodeIds].filter((nodeId) => loadedNodeIds.has(String(nodeId || "").trim()))
  );
  const boundedMatchedNodeIds = new Set(
    [...matchedNodeIds].filter((nodeId) => loadedNodeIds.has(String(nodeId || "").trim()))
  );
  const boundedStrongNodeIds = new Set(
    [...strongNodeIds].filter((nodeId) => loadedNodeIds.has(String(nodeId || "").trim()))
  );
  const boundedHighlightEdgeIds = new Set(
    [...highlightEdgeIds].filter((edgeId) => loadedEdgeIds.has(String(edgeId || "").trim()))
  );
  const boundedStrongEdgeIds = new Set(
    [...strongEdgeIds].filter((edgeId) => loadedEdgeIds.has(String(edgeId || "").trim()))
  );

  graphView.setHighlightContext({
    highlight: {
      node_ids: [...boundedHighlightNodeIds],
      edge_ids: [...boundedHighlightEdgeIds],
      strong_node_ids: [...boundedStrongNodeIds],
      strong_edge_ids: [...boundedStrongEdgeIds],
    },
    matched_node_ids: [...boundedMatchedNodeIds],
  });

  const visibleStats = graphView.getVisibleStats();

  const matchedVisibleCount = [...boundedMatchedNodeIds].filter((nodeId) => graphView.visibleNodeMap.has(nodeId)).length;

  const stats = graph.stats || {};
  el.graphMeta.textContent = [
    hasContextGraph ? "view context-only" : "view full-pruned",
    `visible ${visibleStats.nodes}N/${visibleStats.edges}E`,
    `loaded ${nodes.length}N/${edges.length}E`,
    `full ${fullNodes.length}N/${fullEdges.length}E`,
    hiddenProcessAccessNodeCount ? `hidden_pa_nodes ${hiddenProcessAccessNodeCount}` : "",
    hiddenDanglingNodeCount ? `hidden_dangling_nodes ${hiddenDanglingNodeCount}` : "",
    `trees ${Number((snapshot.trees || []).length)}`,
    `subtrees ${Number((snapshot.subtrees || []).length)}`,
    `matched_visible ${matchedVisibleCount}/${boundedMatchedNodeIds.size}`,
    `highlight ${boundedHighlightNodeIds.size}`,
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
  const evidenceNodeIds = new Set(
    ((snapshot.evidence_node_ids || []).length
      ? snapshot.evidence_node_ids
      : [
          ...(snapshot.malicious_node_ids || []),
          ...(snapshot.core_node_ids || []),
        ])
      .map((value) => String(value || "").trim())
      .filter(Boolean)
  );
  const lines = [
    `snapshot_id: ${snapshot.snapshot_id || ""}`,
    `graph_revision: ${snapshot.graph_revision || 0}`,
    `algorithm: ${match.algorithm || ""}`,
    `technique: ${match.technique || ""}`,
    `score: ${fmtScore(match.score)}`,
    `runtime_ms: ${Number(match.runtime_ms || 0).toFixed(2)}`,
    `matched_nodes: ${(snapshot.matched_node_ids || []).length}`,
    `malicious_nodes: ${(snapshot.malicious_node_ids || []).length}`,
    `core_nodes: ${(snapshot.core_node_ids || []).length}`,
    `evidence_nodes: ${evidenceNodeIds.size}`,
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

graphView.setNodeSelectHandler((details) => {
  if (!details || !details.node) {
    el.nodeDetail.textContent = "Click a node to inspect.";
    return;
  }

  el.nodeDetail.textContent = formatNodeInspect(details.node);
});

el.refreshBtn.addEventListener("click", () => {
  loadSnapshotList(activeSnapshotId).catch((error) => {
    appendLog(`Refresh failed: ${error.message || error}`, "error");
  });
});

loadSnapshotList(snapshotQueryParam()).catch((error) => {
  appendLog(`Initial load failed: ${error.message || error}`, "error");
});
