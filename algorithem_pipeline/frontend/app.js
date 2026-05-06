const state = {
  cy: null,
  graphPayload: null,
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

function renderGraph(graphPayload) {
  const container = document.getElementById("graph");
  const elements = toElements(graphPayload);

  if (!state.cy) {
    state.cy = cytoscape({
      container,
      elements,
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
      layout: {
        name: "cose",
        animate: true,
        animationDuration: 450,
      },
    });
    return;
  }

  state.cy.elements().remove();
  state.cy.add(elements);
  state.cy.layout({ name: "cose", animate: true, animationDuration: 350 }).run();
}

function renderSummary(result) {
  const lines = (result.algorithms || []).map(
    (item) => `${item.algorithm}: top1=${item.top1_technique} score=${item.top1_score.toFixed(3)} acc=${item.accuracy.toFixed(2)} runtime=${item.runtime_ms.toFixed(1)}ms`
  );
  summaryEl.innerHTML = `<strong>Target technique:</strong> ${result.target_technique}<br>${lines.join("<br>")}`;
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
    await loadGraph(technique);
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
