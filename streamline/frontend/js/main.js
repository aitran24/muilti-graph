const el = {
  graphCanvas: document.getElementById("graph-canvas"),
  graphModeToggleBtn: document.getElementById("graph-mode-toggle"),
  statsBox: document.getElementById("stats-box"),
  statsInline: document.getElementById("stats-inline"),
  reconnectBtn: document.getElementById("btn-reconnect"),
  snapshotBtn: document.getElementById("btn-snapshot"),
  installBtn: document.getElementById("btn-install"),
  relationFilterInput: document.getElementById("relation-filter-input"),
  relationFilterAddBtn: document.getElementById("add-relation-filter"),
  relationFilterList: document.getElementById("relation-filter-list"),
  relationFilterClearBtn: document.getElementById("clear-relation-filters"),
  relationSuggestions: document.getElementById("relation-suggestions"),
  inspectMeta: document.getElementById("inspect-meta"),
  inspectBox: document.getElementById("node-inspect"),
  inspectToggleChildrenBtn: document.getElementById("btn-toggle-children"),
  inspectCopyBtn: document.getElementById("btn-copy-inspect"),
};

const GraphStore = window.Streamline && window.Streamline.GraphStore;
const GraphView = window.Streamline && window.Streamline.GraphView;
const StreamWsClient = window.Streamline && window.Streamline.StreamWsClient;
const RelationFilterPanel = window.Streamline && window.Streamline.RelationFilterPanel;
const InspectPanel = window.Streamline && window.Streamline.InspectPanel;

if (!GraphStore || !GraphView || !StreamWsClient || !RelationFilterPanel || !InspectPanel) {
  throw new Error("Streamline frontend failed to initialize: missing script dependencies.");
}

const store = new GraphStore();
const graphView = new GraphView(el.graphCanvas);
const relationFilterPanel = new RelationFilterPanel({
  inputEl: el.relationFilterInput,
  addBtnEl: el.relationFilterAddBtn,
  listEl: el.relationFilterList,
  clearBtnEl: el.relationFilterClearBtn,
  suggestionsEl: el.relationSuggestions,
});
const inspectPanel = new InspectPanel({
  metaEl: el.inspectMeta,
  boxEl: el.inspectBox,
  copyBtnEl: el.inspectCopyBtn,
  onNotify: (message, level) => appendStatus(message, level),
});

let selectedNodeDetails = null;

function renderParentChildrenToggleButton(details) {
  if (!el.inspectToggleChildrenBtn) {
    return;
  }

  const nodeId = details && details.node ? String(details.node.id || "").trim() : "";
  const state = graphView.getParentChildrenToggleState(nodeId);

  if (!state.canToggle) {
    el.inspectToggleChildrenBtn.disabled = true;
    el.inspectToggleChildrenBtn.textContent = "Hide Children";
    el.inspectToggleChildrenBtn.title = "Only available for parent nodes with more than 15 children.";
    return;
  }

  el.inspectToggleChildrenBtn.disabled = false;
  el.inspectToggleChildrenBtn.textContent = state.allHidden ? "Unhide Children" : "Hide Children";
  el.inspectToggleChildrenBtn.title = `Children: ${state.totalChildren} | Hidden: ${state.hiddenChildren}`;
}

graphView.setNodeSelectHandler((details) => {
  selectedNodeDetails = details && details.node ? details : null;
  inspectPanel.render(details);
  renderParentChildrenToggleButton(details);
});

function renderGraphModeToggle() {
  if (!el.graphModeToggleBtn) {
    return;
  }

  const currentMode = graphView.getViewMode();
  const isPrune = currentMode === "prune";
  el.graphModeToggleBtn.textContent = isPrune ? "Mode: Prune" : "Mode: Raw";
  el.graphModeToggleBtn.title = isPrune
    ? "Switch to raw graph mode"
    : "Switch to prune graph mode";
  el.graphModeToggleBtn.classList.toggle("prune", isPrune);
}

relationFilterPanel.setOnChange((filters) => {
  graphView.setRelationFilters(filters);
  syncRelationSuggestions();
  renderStats(store.getState());
});

function appendStatus(message, level = "info") {
  const timestamp = new Date().toLocaleTimeString();
  const prefix = `[${timestamp}]`;

  if (!el.statusLog) {
    const line = `${prefix} ${message}`;
    if (level === "error") {
      console.error(line);
    } else if (level === "warn") {
      console.warn(line);
    } else {
      console.info(line);
    }
    return;
  }

  const row = document.createElement("div");
  row.className = `status-row ${level}`;
  row.textContent = `${prefix} ${message}`;

  el.statusLog.prepend(row);

  const maxRows = 150;
  while (el.statusLog.childNodes.length > maxRows) {
    el.statusLog.removeChild(el.statusLog.lastChild);
  }
}

function renderStats(state) {
  const totalNodes = state.nodes.length;
  const totalEdges = state.edges.length;
  const relationEdges = Number((state.stats && state.stats.relation_edges) || 0);
  const rootEdges = Number((state.stats && state.stats.root_edges) || 0);
  const visible = graphView.getVisibleStats();
  const activeFilters = relationFilterPanel.getFilters();
  const graphMode = graphView.getViewMode();

  el.statsInline.textContent = [
    `mode ${graphMode}`,
    `visible ${visible.nodes}N/${visible.edges}E`,
    `total ${totalNodes}N/${totalEdges}E`,
    `relation ${relationEdges}`,
    `root ${rootEdges}`,
    `filters ${activeFilters.length}`,
  ].join(" | ");

  el.statsBox.textContent = [
    `view_mode: ${graphMode}`,
    `visible_nodes: ${visible.nodes}`,
    `visible_edges: ${visible.edges}`,
    `total_nodes: ${totalNodes}`,
    `total_edges: ${totalEdges}`,
    `relation_edges: ${relationEdges}`,
    `root_edges: ${rootEdges}`,
    `active_relation_filters: ${activeFilters.length ? activeFilters.join(", ") : "(none)"}`,
  ].join("\n");
}

function syncRelationSuggestions() {
  relationFilterPanel.setSuggestions(graphView.getRelationTypeCounts());
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

const wsUrl = resolveWsUrl();
const wsClient = new StreamWsClient(wsUrl, {
  onOpen: () => {
    appendStatus(`Connected to ${wsUrl}`);
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
      syncRelationSuggestions();
      renderStats(store.getState());
      renderParentChildrenToggleButton(selectedNodeDetails);
      appendStatus("Snapshot applied.");
      return;
    }

    if (messageType === "delta") {
      const delta = payload.payload || {};
      store.applyDelta(delta);
      graphView.applyDelta(delta);
      syncRelationSuggestions();
      renderStats(store.getState());
      renderParentChildrenToggleButton(selectedNodeDetails);
      return;
    }

    if (messageType === "status") {
      appendStatus(String(payload.message || ""), String(payload.level || "info"));
      return;
    }

    if (messageType === "pong") {
      appendStatus("Received pong from backend.");
      return;
    }
  },
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

el.installBtn.addEventListener("click", () => {
  const ok = wsClient.send({ type: "install_sysmon" });
  if (!ok) {
    appendStatus("Cannot install Sysmon: socket is not connected.", "error");
  }
});

if (el.inspectToggleChildrenBtn) {
  el.inspectToggleChildrenBtn.addEventListener("click", () => {
    if (!selectedNodeDetails || !selectedNodeDetails.node) {
      appendStatus("Select a parent node before toggling children visibility.", "error");
      return;
    }

    const nodeId = selectedNodeDetails.node.id;
    const state = graphView.toggleParentChildrenVisibility(nodeId);
    if (!state.canToggle) {
      appendStatus("This node does not have a hide/unhide children action.", "error");
      renderParentChildrenToggleButton(selectedNodeDetails);
      return;
    }

    renderParentChildrenToggleButton(selectedNodeDetails);
    renderStats(store.getState());
    appendStatus(
      state.allHidden
        ? `Children hidden for parent ${nodeId}.`
        : `Children shown for parent ${nodeId}.`
    );
  });
}

if (el.graphModeToggleBtn) {
  el.graphModeToggleBtn.addEventListener("click", () => {
    const changed = graphView.toggleViewMode();
    if (!changed) {
      return;
    }

    renderGraphModeToggle();
    renderStats(store.getState());
    appendStatus(`Graph mode changed to ${graphView.getViewMode()}.`);
  });
}

wsClient.connect();
syncRelationSuggestions();
renderGraphModeToggle();
renderParentChildrenToggleButton(null);
renderStats(store.getState());
appendStatus("Frontend ready.");
