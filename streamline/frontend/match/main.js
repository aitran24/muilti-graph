const el = {
  graphCanvas: document.getElementById("graph-canvas"),
  statsBox: document.getElementById("stats-box"),
  statsInline: document.getElementById("stats-inline"),
  reconnectBtn: document.getElementById("btn-reconnect"),
  snapshotBtn: document.getElementById("btn-snapshot"),
  captureSystemBtn: document.getElementById("btn-capture-system"),
  clearHighlightBtn: document.getElementById("btn-clear-highlight"),
  openSnapshotUiBtn: document.getElementById("btn-open-snapshot-ui"),
  refreshMatchBtn: document.getElementById("btn-refresh-match"),
  observationMeta: document.getElementById("observation-meta"),
  observationLevels: document.getElementById("observation-levels"),
  matchSummary: document.getElementById("match-summary"),
  matchList: document.getElementById("match-list"),
  inspectMeta: document.getElementById("inspect-meta"),
  inspectBox: document.getElementById("node-inspect"),
  inspectCopyBtn: document.getElementById("btn-copy-inspect"),
};

const GraphStore = window.Streamline && window.Streamline.GraphStore;
const GraphView = window.Streamline && window.Streamline.GraphView;
const StreamWsClient = window.Streamline && window.Streamline.StreamWsClient;
const InspectPanel = window.Streamline && window.Streamline.InspectPanel;

if (!GraphStore || !GraphView || !StreamWsClient || !InspectPanel) {
  throw new Error("Match frontend initialization failed: missing script dependencies.");
}

const store = new GraphStore();
const graphView = new GraphView(el.graphCanvas, {
  defaultViewMode: "prune",
  childHideThreshold: 0,
  disableDefaultHiddenRelations: true,
});
const inspectPanel = new InspectPanel({
  metaEl: el.inspectMeta,
  boxEl: el.inspectBox,
  copyBtnEl: el.inspectCopyBtn,
  onNotify: (message, level) => appendStatus(message, level),
});

const OBSERVATION_LEVELS = {
  info: "Info",
  warning: "Warning",
  high: "High Risk",
};

let latestMatchPayload = null;
let snapshotUiUrl = "";
let latestMatchRevision = 0;
let observationLevel = "warning";
let selectedMatchKey = "";

const keyScoreByKey = new Map();
const keyMetaByKey = new Map();
const matchContextByKey = new Map();
const pendingContextRequests = new Set();

let latestObservationSnapshot = {
  attackNodeCount: 0,
  loadedContextCount: 0,
  totalContextCount: 0,
  levelNodeIds: {
    info: new Set(),
    warning: new Set(),
    high: new Set(),
  },
};

function appendStatus(message, level = "info") {
  const prefix = `[${new Date().toLocaleTimeString()}]`;
  const line = `${prefix} ${message}`;
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

function normalizeKey(value) {
  return String(value || "").trim();
}

function normalizeNodeId(value) {
  return String(value || "").trim();
}

function toNumericScore(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) {
    return 0;
  }
  return score;
}

function scoreToObservationLevel(score) {
  const normalized = toNumericScore(score);
  if (normalized < 0.2) {
    return "info";
  }
  if (normalized <= 0.6) {
    return "warning";
  }
  return "high";
}

function riskLabel(level) {
  return OBSERVATION_LEVELS[level] || OBSERVATION_LEVELS.warning;
}

function renderStats(state) {
  const totalNodes = state.nodes.length;
  const totalEdges = state.edges.length;
  const visible = graphView.getVisibleStats();
  const graphMode = graphView.getViewMode();
  const selectedMeta = selectedMatchKey ? keyMetaByKey.get(selectedMatchKey) : null;
  const selectedTechnique = selectedMeta ? selectedMeta.technique : "(none)";
  const levelNodeCount = latestObservationSnapshot.levelNodeIds[observationLevel].size;

  el.statsInline.textContent = [
    `mode ${graphMode}`,
    `obs ${riskLabel(observationLevel)}`,
    `visible ${visible.nodes}N/${visible.edges}E`,
    `total ${totalNodes}N/${totalEdges}E`,
  ].join(" | ");

  el.statsBox.textContent = [
    `view_mode: ${graphMode}`,
    `observation_level: ${riskLabel(observationLevel)}`,
    `level_nodes: ${levelNodeCount}`,
    `contexts_loaded: ${latestObservationSnapshot.loadedContextCount}/${latestObservationSnapshot.totalContextCount}`,
    `selected_technique: ${selectedTechnique}`,
    `visible_nodes: ${visible.nodes}`,
    `visible_edges: ${visible.edges}`,
    `total_nodes: ${totalNodes}`,
    `total_edges: ${totalEdges}`,
  ].join("\n");
}

function renderMatchSummary(payload) {
  const selectedMeta = selectedMatchKey ? keyMetaByKey.get(selectedMatchKey) : null;
  const selectedText = selectedMeta
    ? `${selectedMeta.technique} (${toNumericScore(selectedMeta.score).toFixed(3)})`
    : "(none)";

  if (!payload) {
    el.matchSummary.textContent = [
      "Waiting for first matching result...",
      `obs ${riskLabel(observationLevel)}`,
      `selected ${selectedText}`,
    ].join(" | ");
    return;
  }

  const rawStats = payload.raw_graph_stats || {};
  const prunedStats = payload.pruned_graph_stats || {};
  el.matchSummary.textContent = [
    `rev ${payload.graph_revision || 0}`,
    `obs ${riskLabel(observationLevel)}`,
    `contexts ${latestObservationSnapshot.loadedContextCount}/${latestObservationSnapshot.totalContextCount}`,
    `selected ${selectedText}`,
    `raw ${rawStats.nodes || 0}N/${rawStats.edges || 0}E`,
    `pruned ${prunedStats.nodes || 0}N/${prunedStats.edges || 0}E`,
  ].join(" | ");
}

function renderMatchList(payload) {
  el.matchList.innerHTML = "";

  if (!payload || !Array.isArray(payload.algorithms) || !payload.algorithms.length) {
    const empty = document.createElement("div");
    empty.className = "inspect-meta";
    empty.textContent = "No matching results yet.";
    el.matchList.appendChild(empty);
    return;
  }

  payload.algorithms.forEach((algorithm) => {
    const section = document.createElement("section");
    section.className = "match-section";

    const title = document.createElement("h3");
    title.className = "match-section-title";
    title.textContent = `${algorithm.name} | top1 ${algorithm.top1_technique || "-"} (${Number(algorithm.top1_score || 0).toFixed(3)})`;
    section.appendChild(title);

    const matches = Array.isArray(algorithm.top_matches) ? algorithm.top_matches : [];
    if (!matches.length) {
      const empty = document.createElement("p");
      empty.className = "match-meta";
      empty.textContent = "No candidates.";
      section.appendChild(empty);
    }

    matches.forEach((match) => {
      const item = document.createElement("article");
      item.className = "match-item";

      const key = normalizeKey(match.key);
      const scoreValue = toNumericScore(match.score);
      const level = scoreToObservationLevel(scoreValue);
      const isSelected = key === selectedMatchKey;
      const hasContext = matchContextByKey.has(key);
      const isPendingContext = pendingContextRequests.has(key);

      if (isSelected) {
        item.classList.add("active");
      }

      const head = document.createElement("div");
      head.className = "match-item-head";

      const techniqueWrap = document.createElement("div");
      techniqueWrap.className = "match-technique-wrap";

      const technique = document.createElement("span");
      technique.className = "match-technique";
      technique.textContent = `${match.rank}. ${match.technique}`;

      const riskTag = document.createElement("span");
      riskTag.className = `match-risk-tag ${level}`;
      riskTag.textContent = riskLabel(level);

      techniqueWrap.appendChild(technique);
      techniqueWrap.appendChild(riskTag);

      const score = document.createElement("span");
      score.className = "match-score";
      score.textContent = scoreValue.toFixed(4);

      head.appendChild(techniqueWrap);
      head.appendChild(score);
      item.appendChild(head);

      const meta = document.createElement("p");
      meta.className = "match-meta";
      meta.textContent = `matched_nodes=${match.matched_node_count || 0} | runtime=${Number(match.runtime_ms || 0).toFixed(1)}ms`;
      item.appendChild(meta);

      const contextState = document.createElement("p");
      contextState.className = "match-context-state";
      if (hasContext) {
        contextState.textContent = "context: ready";
      } else if (isPendingContext) {
        contextState.textContent = "context: loading...";
      } else {
        contextState.textContent = "context: pending request";
      }
      item.appendChild(contextState);

      const actions = document.createElement("div");
      actions.className = "match-actions";

      const selectBtn = document.createElement("button");
      selectBtn.type = "button";
      selectBtn.textContent = isSelected ? "Deselect Technique" : "Select Technique";
      selectBtn.dataset.action = "select";
      selectBtn.dataset.key = key;

      const snapshotBtn = document.createElement("button");
      snapshotBtn.type = "button";
      snapshotBtn.textContent = "Create Snapshot";
      snapshotBtn.dataset.action = "snapshot";
      snapshotBtn.dataset.key = key;

      actions.appendChild(selectBtn);
      actions.appendChild(snapshotBtn);
      item.appendChild(actions);

      section.appendChild(item);
    });

    el.matchList.appendChild(section);
  });
}

function resolveWsUrl() {
  const params = new URLSearchParams(window.location.search || "");
  const explicitWs = String(params.get("ws") || "").trim();
  if (explicitWs) {
    return explicitWs;
  }

  const defaultHost = String(window.location.hostname || "127.0.0.1").trim() || "127.0.0.1";
  const host = String(params.get("host") || defaultHost).trim() || defaultHost;
  const parsedPort = Number.parseInt(String(params.get("port") || ""), 10);
  const port = Number.isInteger(parsedPort) && parsedPort > 0 ? parsedPort : 8877;
  return `ws://${host}:${port}`;
}

function contextNodeIdSet(context) {
  const nodeIds = new Set();

  ((context && context.matched_node_ids) || []).forEach((nodeId) => {
    const normalized = normalizeNodeId(nodeId);
    if (normalized) {
      nodeIds.add(normalized);
    }
  });

  (((context && context.highlight) || {}).node_ids || []).forEach((nodeId) => {
    const normalized = normalizeNodeId(nodeId);
    if (normalized) {
      nodeIds.add(normalized);
    }
  });

  ((context && context.trees) || []).forEach((tree) => {
    ((tree && tree.node_ids) || []).forEach((nodeId) => {
      const normalized = normalizeNodeId(nodeId);
      if (normalized) {
        nodeIds.add(normalized);
      }
    });
  });

  ((context && context.subtrees) || []).forEach((subtree) => {
    ((subtree && subtree.node_ids) || []).forEach((nodeId) => {
      const normalized = normalizeNodeId(nodeId);
      if (normalized) {
        nodeIds.add(normalized);
      }
    });
  });

  return nodeIds;
}

function getSelectedContext() {
  if (!selectedMatchKey) {
    return null;
  }

  return matchContextByKey.get(selectedMatchKey) || null;
}

function collectAlwaysVisibleRootNodeIds(state) {
  const rootNodeIds = new Set();
  const inDegree = new Map();
  const outDegree = new Map();

  const ensureDegreeSlot = (nodeId) => {
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

  (state.nodes || []).forEach((node) => {
    const nodeId = normalizeNodeId(node && node.id);
    if (!nodeId) {
      return;
    }

    ensureDegreeSlot(nodeId);

    const type = String((node && node.type) || "").trim().toLowerCase();
    const group = String((node && node.group) || "").trim().toLowerCase();
    const label = String((node && node.label) || ((node && node.properties && node.properties.display_name) || ""))
      .trim()
      .toLowerCase();

    const properties = (node && node.properties) || {};
    const displayName = String(properties.display_name || "").trim().toLowerCase();
    const name = String(properties.name || "").trim().toLowerCase();
    const keywordText = `${type} ${group} ${label} ${displayName} ${name}`;

    const hasLiveSysmonKeyword =
      keywordText.includes("live_sysmon") ||
      keywordText.includes("live sysmon") ||
      keywordText.includes("sysmon root") ||
      keywordText.includes("synthetic_root") ||
      keywordText.includes("synthetic root") ||
      keywordText.includes("live_root") ||
      keywordText.includes("live root");

    const hasRootType = type === "root" || group === "root";

    if (hasLiveSysmonKeyword || hasRootType) {
      rootNodeIds.add(nodeId);
    }
  });

  (state.edges || []).forEach((edge) => {
    const source = normalizeNodeId((edge && (edge.source || edge.from)) || "");
    const target = normalizeNodeId((edge && (edge.target || edge.to)) || "");

    if (!source || !target || source === target) {
      return;
    }

    ensureDegreeSlot(source);
    ensureDegreeSlot(target);
    outDegree.set(source, Number(outDegree.get(source) || 0) + 1);
    inDegree.set(target, Number(inDegree.get(target) || 0) + 1);
  });

  if (!rootNodeIds.size) {
    const fallbackCandidate = [...outDegree.entries()]
      .map(([nodeId, out]) => ({
        nodeId,
        outDegree: Number(out) || 0,
        inDegree: Number(inDegree.get(nodeId) || 0),
      }))
      .filter((entry) => entry.outDegree > 0 && entry.inDegree === 0)
      .sort((left, right) => right.outDegree - left.outDegree)[0];

    if (fallbackCandidate && fallbackCandidate.nodeId) {
      rootNodeIds.add(fallbackCandidate.nodeId);
    }
  }

  return rootNodeIds;
}

function buildObservationSnapshot(state) {
  const allNodeIds = new Set((state.nodes || []).map((node) => normalizeNodeId(node.id)).filter(Boolean));
  const levelNodeIds = {
    info: new Set(),
    warning: new Set(),
    high: new Set(),
  };

  const nodeMaxScore = new Map();
  let loadedContextCount = 0;
  const totalContextCount = keyScoreByKey.size;

  keyScoreByKey.forEach((score, key) => {
    const context = matchContextByKey.get(key);
    if (!context) {
      return;
    }

    loadedContextCount += 1;
    const normalizedScore = toNumericScore(score);
    const contextNodes = contextNodeIdSet(context);
    contextNodes.forEach((nodeId) => {
      const previous = nodeMaxScore.has(nodeId) ? nodeMaxScore.get(nodeId) : Number.NEGATIVE_INFINITY;
      if (normalizedScore > previous) {
        nodeMaxScore.set(nodeId, normalizedScore);
      }
    });
  });

  allNodeIds.forEach((nodeId) => {
    if (!nodeMaxScore.has(nodeId)) {
      levelNodeIds.info.add(nodeId);
      return;
    }

    const nodeLevel = scoreToObservationLevel(nodeMaxScore.get(nodeId));
    levelNodeIds[nodeLevel].add(nodeId);
  });

  const rootNodeIds = collectAlwaysVisibleRootNodeIds(state);
  rootNodeIds.forEach((nodeId) => {
    levelNodeIds.info.add(nodeId);
    levelNodeIds.warning.add(nodeId);
    levelNodeIds.high.add(nodeId);
  });

  return {
    attackNodeCount: nodeMaxScore.size,
    loadedContextCount,
    totalContextCount,
    rootNodeIds,
    levelNodeIds,
  };
}

function renderObservationControls() {
  if (!el.observationLevels) {
    return;
  }

  const buttons = el.observationLevels.querySelectorAll(".observation-level-btn");
  buttons.forEach((button) => {
    const level = normalizeKey(button.dataset.level).toLowerCase();
    const isActive = level === observationLevel;
    button.classList.toggle("active", isActive);
    button.setAttribute("aria-checked", isActive ? "true" : "false");
  });
}

function applyObservationVisibility() {
  const state = store.getState();
  latestObservationSnapshot = buildObservationSnapshot(state);

  const selectedContext = getSelectedContext();
  const allowedNodeIds = latestObservationSnapshot.levelNodeIds[observationLevel] || new Set();
  const forcedNodeIds = selectedContext ? contextNodeIdSet(selectedContext) : new Set();
  (latestObservationSnapshot.rootNodeIds || new Set()).forEach((nodeId) => {
    forcedNodeIds.add(nodeId);
  });

  graphView.setNodeVisibilityFilter(allowedNodeIds, forcedNodeIds);
  if (selectedContext) {
    graphView.setHighlightContext(selectedContext);
  } else {
    graphView.clearHighlightContext();
  }

  renderObservationControls();

  if (el.observationMeta) {
    const selectedMeta = selectedMatchKey ? keyMetaByKey.get(selectedMatchKey) : null;
    const selectedText = selectedMeta
      ? `${selectedMeta.technique} (${toNumericScore(selectedMeta.score).toFixed(3)})`
      : "(none)";

    el.observationMeta.textContent = [
      `Level: ${riskLabel(observationLevel)}`,
      `nodes ${allowedNodeIds.size}`,
      `contexts ${latestObservationSnapshot.loadedContextCount}/${latestObservationSnapshot.totalContextCount}`,
      `selected ${selectedText}`,
    ].join(" | ");
  }

  return selectedContext;
}

function collectTopMatchEntries(payload) {
  const entries = [];
  if (!payload || !Array.isArray(payload.algorithms)) {
    return entries;
  }

  payload.algorithms.forEach((algorithm) => {
    const algorithmName = String((algorithm && algorithm.name) || "").trim() || "unknown";
    const matches = Array.isArray(algorithm && algorithm.top_matches) ? algorithm.top_matches : [];

    matches.forEach((match) => {
      const key = normalizeKey(match && match.key);
      if (!key) {
        return;
      }

      entries.push({
        key,
        algorithm: algorithmName,
        technique: String((match && match.technique) || "").trim() || "unknown",
        score: toNumericScore(match && match.score),
        rank: Number(match && match.rank) || 0,
      });
    });
  });

  return entries;
}

function syncMatchIndexes(payload) {
  keyScoreByKey.clear();
  keyMetaByKey.clear();

  collectTopMatchEntries(payload).forEach((entry) => {
    keyScoreByKey.set(entry.key, entry.score);
    keyMetaByKey.set(entry.key, entry);
  });

  [...matchContextByKey.keys()].forEach((key) => {
    if (!keyScoreByKey.has(key)) {
      matchContextByKey.delete(key);
    }
  });

  [...pendingContextRequests].forEach((key) => {
    if (!keyScoreByKey.has(key)) {
      pendingContextRequests.delete(key);
    }
  });

  if (selectedMatchKey && !keyScoreByKey.has(selectedMatchKey)) {
    selectedMatchKey = "";
  }
}

function requestMissingContexts(wsClientInstance) {
  keyScoreByKey.forEach((_score, key) => {
    if (matchContextByKey.has(key) || pendingContextRequests.has(key)) {
      return;
    }

    const ok = wsClientInstance.send({ type: "request_match_context", key });
    if (ok) {
      pendingContextRequests.add(key);
    }
  });
}

function resolveCaptureSystemUrl() {
  if (snapshotUiUrl) {
    try {
      const parsed = new URL(snapshotUiUrl);
      if (parsed.pathname.toLowerCase().endsWith("/index.html")) {
        parsed.pathname = `${parsed.pathname.slice(0, -"/index.html".length)}/capture_system.html`;
      } else {
        parsed.pathname = "/capture_system.html";
      }
      parsed.search = "";
      parsed.hash = "";
      return parsed.toString();
    } catch (_error) {
      // Fall through to default URL resolution.
    }
  }

  const params = new URLSearchParams(window.location.search || "");
  const defaultHost = String(window.location.hostname || "127.0.0.1").trim() || "127.0.0.1";
  const host = String(params.get("ui_host") || params.get("host") || defaultHost).trim() || defaultHost;
  const parsedSnapshotPort = Number.parseInt(String(params.get("snapshot_ui_port") || ""), 10);
  const snapshotPort = Number.isInteger(parsedSnapshotPort) && parsedSnapshotPort > 0
    ? parsedSnapshotPort
    : 8081;
  return `http://${host}:${snapshotPort}/capture_system.html`;
}

const wsUrl = resolveWsUrl();
const wsClient = new StreamWsClient(wsUrl, {
  onOpen: () => {
    appendStatus(`Connected to ${wsUrl}`);
    wsClient.send({ type: "request_match_state" });
  },
  onClose: () => {
    appendStatus("Disconnected from backend.", "error");
  },
  onError: (message) => {
    appendStatus(message, "error");
  },
  onMessage: (payload) => {
    const messageType = String(payload.type || "").toLowerCase();

    if (messageType === "snapshot") {
      const graph = payload.graph || { nodes: [], edges: [], stats: {} };
      store.applySnapshot(graph);
      graphView.renderSnapshot(store.getState());
      applyObservationVisibility();
      renderStats(store.getState());
      return;
    }

    if (messageType === "delta") {
      const delta = payload.payload || {};
      store.applyDelta(delta);
      graphView.applyDelta(delta);
      applyObservationVisibility();
      renderStats(store.getState());
      return;
    }

    if (messageType === "match_update") {
      latestMatchPayload = payload.payload || null;
      snapshotUiUrl = String((latestMatchPayload && latestMatchPayload.snapshot_ui_url) || "").trim();

      const nextRevision = Number((latestMatchPayload && latestMatchPayload.graph_revision) || 0);
      if (nextRevision && nextRevision !== latestMatchRevision) {
        latestMatchRevision = nextRevision;
        matchContextByKey.clear();
        pendingContextRequests.clear();
      }

      syncMatchIndexes(latestMatchPayload);
      requestMissingContexts(wsClient);

      applyObservationVisibility();
      renderMatchSummary(latestMatchPayload);
      renderMatchList(latestMatchPayload);
      renderStats(store.getState());
      return;
    }

    if (messageType === "match_context") {
      const data = payload.payload || {};
      const key = normalizeKey(data.key);
      if (!key) {
        return;
      }

      const contextRevision = Number(data.graph_revision || 0);
      if (latestMatchRevision && contextRevision && contextRevision !== latestMatchRevision) {
        return;
      }

      if (!keyMetaByKey.has(key) && key !== selectedMatchKey) {
        return;
      }

      matchContextByKey.set(key, data);
      pendingContextRequests.delete(key);

      applyObservationVisibility();
      renderMatchSummary(latestMatchPayload);
      renderMatchList(latestMatchPayload);
      renderStats(store.getState());
      return;
    }

    if (messageType === "snapshot_created") {
      const data = payload.payload || {};
      const viewerUrl = String(data.viewer_url || "").trim();
      if (viewerUrl) {
        appendStatus(`Snapshot ${data.snapshot_id || ""} created.`);
        window.open(viewerUrl, "_blank", "noopener,noreferrer");
        return;
      }
      appendStatus(`Snapshot ${data.snapshot_id || ""} created.`);
      return;
    }

    if (messageType === "status") {
      appendStatus(String(payload.message || ""), String(payload.level || "info"));
      return;
    }

    if (messageType === "pong") {
      appendStatus("Received pong from backend.");
    }
  },
});

graphView.setNodeSelectHandler((details) => {
  inspectPanel.render(details);
});

el.reconnectBtn.addEventListener("click", () => {
  appendStatus("Reconnecting...");
  wsClient.reconnect();
});

el.snapshotBtn.addEventListener("click", () => {
  const ok = wsClient.send({ type: "request_snapshot" });
  if (!ok) {
    appendStatus("Cannot request snapshot: socket is not connected.", "error");
  }
});

if (el.captureSystemBtn) {
  el.captureSystemBtn.addEventListener("click", () => {
    const captureUrl = resolveCaptureSystemUrl();
    appendStatus(`Opening Capture System: ${captureUrl}`);
    const opened = window.open(captureUrl, "_blank", "noopener,noreferrer");
    if (!opened) {
      window.location.assign(captureUrl);
    }
  });
}

el.clearHighlightBtn.addEventListener("click", () => {
  selectedMatchKey = "";
  applyObservationVisibility();
  renderMatchSummary(latestMatchPayload);
  renderMatchList(latestMatchPayload);
  renderStats(store.getState());
  appendStatus("Technique selection cleared.");
});

el.refreshMatchBtn.addEventListener("click", () => {
  const ok = wsClient.send({ type: "request_match_state" });
  if (!ok) {
    appendStatus("Cannot refresh matching state: socket is not connected.", "error");
  }
});

el.openSnapshotUiBtn.addEventListener("click", () => {
  if (!snapshotUiUrl) {
    appendStatus("Snapshot UI URL is not available yet.", "error");
    return;
  }
  appendStatus(`Opening Snapshot UI: ${snapshotUiUrl}`);
  const opened = window.open(snapshotUiUrl, "_blank", "noopener,noreferrer");
  if (!opened) {
    window.location.assign(snapshotUiUrl);
  }
});

el.matchList.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }

  const action = String(target.dataset.action || "").trim();
  const key = String(target.dataset.key || "").trim();
  if (!action || !key) {
    return;
  }

  if (action === "select") {
    if (selectedMatchKey === key) {
      selectedMatchKey = "";
    } else {
      selectedMatchKey = key;
      if (!matchContextByKey.has(key) && !pendingContextRequests.has(key)) {
        const ok = wsClient.send({ type: "request_match_context", key });
        if (ok) {
          pendingContextRequests.add(key);
        }
      }
    }

    applyObservationVisibility();
    renderMatchSummary(latestMatchPayload);
    renderMatchList(latestMatchPayload);
    renderStats(store.getState());
    return;
  }

  if (action === "snapshot") {
    const ok = wsClient.send({ type: "create_match_snapshot", key });
    if (!ok) {
      appendStatus("Cannot create snapshot: socket is not connected.", "error");
    }
  }
});

if (el.observationLevels) {
  el.observationLevels.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }

    const trigger = target.closest(".observation-level-btn");
    if (!(trigger instanceof HTMLElement)) {
      return;
    }

    const level = normalizeKey(trigger.dataset.level).toLowerCase();
    if (!level || !OBSERVATION_LEVELS[level] || level === observationLevel) {
      return;
    }

    observationLevel = level;
    applyObservationVisibility();
    renderMatchSummary(latestMatchPayload);
    renderMatchList(latestMatchPayload);
    renderStats(store.getState());
  });
}

wsClient.connect();
renderObservationControls();
applyObservationVisibility();
renderMatchSummary(null);
renderMatchList(null);
renderStats(store.getState());
appendStatus("Prune+matching frontend ready.");
