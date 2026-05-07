const el = {
  graphCanvas: document.getElementById("graph-canvas"),
  statsBox: document.getElementById("stats-box"),
  statsInline: document.getElementById("stats-inline"),
  reconnectBtn: document.getElementById("btn-reconnect"),
  snapshotBtn: document.getElementById("btn-snapshot"),
  clearHighlightBtn: document.getElementById("btn-clear-highlight"),
  openSnapshotUiBtn: document.getElementById("btn-open-snapshot-ui"),
  refreshMatchBtn: document.getElementById("btn-refresh-match"),
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
});
const inspectPanel = new InspectPanel({
  metaEl: el.inspectMeta,
  boxEl: el.inspectBox,
  copyBtnEl: el.inspectCopyBtn,
  onNotify: (message, level) => appendStatus(message, level),
});

let latestMatchPayload = null;
let snapshotUiUrl = "";

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

function renderStats(state) {
  const totalNodes = state.nodes.length;
  const totalEdges = state.edges.length;
  const visible = graphView.getVisibleStats();
  const graphMode = graphView.getViewMode();

  el.statsInline.textContent = [
    `mode ${graphMode}`,
    `visible ${visible.nodes}N/${visible.edges}E`,
    `total ${totalNodes}N/${totalEdges}E`,
  ].join(" | ");

  el.statsBox.textContent = [
    `view_mode: ${graphMode}`,
    `visible_nodes: ${visible.nodes}`,
    `visible_edges: ${visible.edges}`,
    `total_nodes: ${totalNodes}`,
    `total_edges: ${totalEdges}`,
  ].join("\n");
}

function renderMatchSummary(payload) {
  if (!payload) {
    el.matchSummary.textContent = "Matching state is not ready yet.";
    return;
  }

  const rawStats = payload.raw_graph_stats || {};
  const prunedStats = payload.pruned_graph_stats || {};
  el.matchSummary.textContent = [
    `rev ${payload.graph_revision || 0}`,
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

      const head = document.createElement("div");
      head.className = "match-item-head";

      const technique = document.createElement("span");
      technique.className = "match-technique";
      technique.textContent = `${match.rank}. ${match.technique}`;

      const score = document.createElement("span");
      score.className = "match-score";
      score.textContent = Number(match.score || 0).toFixed(4);

      head.appendChild(technique);
      head.appendChild(score);
      item.appendChild(head);

      const meta = document.createElement("p");
      meta.className = "match-meta";
      meta.textContent = `matched_nodes=${match.matched_node_count || 0} | runtime=${Number(match.runtime_ms || 0).toFixed(1)}ms`;
      item.appendChild(meta);

      const actions = document.createElement("div");
      actions.className = "match-actions";

      const highlightBtn = document.createElement("button");
      highlightBtn.type = "button";
      highlightBtn.textContent = "Highlight Context";
      highlightBtn.dataset.action = "highlight";
      highlightBtn.dataset.key = String(match.key || "");

      const snapshotBtn = document.createElement("button");
      snapshotBtn.type = "button";
      snapshotBtn.textContent = "Create Snapshot";
      snapshotBtn.dataset.action = "snapshot";
      snapshotBtn.dataset.key = String(match.key || "");

      actions.appendChild(highlightBtn);
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
      renderStats(store.getState());
      return;
    }

    if (messageType === "delta") {
      const delta = payload.payload || {};
      store.applyDelta(delta);
      graphView.applyDelta(delta);
      renderStats(store.getState());
      return;
    }

    if (messageType === "match_update") {
      latestMatchPayload = payload.payload || null;
      snapshotUiUrl = String((latestMatchPayload && latestMatchPayload.snapshot_ui_url) || "").trim();
      renderMatchSummary(latestMatchPayload);
      renderMatchList(latestMatchPayload);
      return;
    }

    if (messageType === "match_context") {
      const data = payload.payload || {};
      graphView.setHighlightContext(data);
      appendStatus(
        `Highlighted ${((data.highlight || {}).node_ids || []).length} nodes from ${data.technique || "unknown"}.`
      );
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

el.clearHighlightBtn.addEventListener("click", () => {
  graphView.clearHighlightContext();
  appendStatus("Highlight cleared.");
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
  window.open(snapshotUiUrl, "_blank", "noopener,noreferrer");
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

  if (action === "highlight") {
    const ok = wsClient.send({ type: "request_match_context", key });
    if (!ok) {
      appendStatus("Cannot request match context: socket is not connected.", "error");
    }
    return;
  }

  if (action === "snapshot") {
    const ok = wsClient.send({ type: "create_match_snapshot", key });
    if (!ok) {
      appendStatus("Cannot create snapshot: socket is not connected.", "error");
    }
  }
});

wsClient.connect();
renderMatchSummary(null);
renderMatchList(null);
renderStats(store.getState());
appendStatus("Prune+matching frontend ready.");
