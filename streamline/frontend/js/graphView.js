(() => {
window.Streamline = window.Streamline || {};
const internals = window.Streamline.GraphViewInternals || {};
const layoutApi = internals.layout || {};
const dragApi = internals.drag || {};
const pruneApi = internals.prune || {};

const DEFAULT_CHILDREN_HIDE_THRESHOLD = 15;
const DEFAULT_HIDDEN_RELATIONS = new Set(["processaccess"]);
const DEFAULT_COLLAPSED_PROCESS_PREFIXES = [
  "svchost",
  "msedge",
  "taskhost",
  "conhost",
  "wmiprvse.exe",
  "aggregatorhost.exe",
  "git-credential-manager.exe",
  "code.exe",
  "git.exe",
];

if (
  !internals.FREE_LAYOUT ||
  typeof internals.colorForGroup !== "function" ||
  typeof internals.normalizeRelationType !== "function" ||
  typeof internals.normalizeRelationFilters !== "function" ||
  typeof internals.updateDataSet !== "function" ||
  typeof pruneApi.buildPrunedGraph !== "function" ||
  typeof layoutApi.recomputeBaseLayout !== "function" ||
  typeof dragApi.applyDragEnd !== "function"
) {
  throw new Error(
    "GraphView dependencies are missing. Load js/graphView/helpers.js, js/graphView/prune.js, js/graphView/layout.js, and js/graphView/drag.js before js/graphView.js."
  );
}

class GraphView {
  constructor(canvasElement, options = {}) {
    this.canvasElement = canvasElement;
    this.options = options || {};
    this.childHideThreshold = Number.isFinite(Number(this.options.childHideThreshold))
      ? Number(this.options.childHideThreshold)
      : DEFAULT_CHILDREN_HIDE_THRESHOLD;
    if (this.childHideThreshold < 0) {
      this.childHideThreshold = 0;
    }
    this.defaultCollapsedProcessPrefixes = Array.isArray(this.options.defaultCollapsedProcessPrefixes)
      ? this.options.defaultCollapsedProcessPrefixes
      : DEFAULT_COLLAPSED_PROCESS_PREFIXES;

    this.nodeMap = new Map();
    this.edgeMap = new Map();
    this.visibleNodeMap = new Map();
    this.visibleEdgeMap = new Map();
    this.currentNodeMap = new Map();
    this.currentEdgeMap = new Map();
    this.basePositions = new Map();
    this.currentDisplayGraph = { nodes: [], edges: [] };

    this.viewMode = String(this.options.defaultViewMode || "raw").trim().toLowerCase() === "prune"
      ? "prune"
      : "raw";
    this.graphRevision = 0;
    this.cachedPrunedRevision = -1;
    this.cachedPrunedGraph = null;

    this.highlightNodeIds = new Set();
    this.highlightEdgeIds = new Set();
    this.matchedNodeIds = new Set();

    this.depthMap = new Map();
    this.autoHiddenChildrenByParent = new Map();
    this.hiddenCountByParent = new Map();
    this.manualHiddenChildrenByParent = new Map();
    this._bloomingFrameHandle = 0;

    this.relationFilters = [];
    this.selectedNodeId = "";
    this.onNodeSelect = null;

    this.nodeDataSet = new vis.DataSet([]);
    this.edgeDataSet = new vis.DataSet([]);

    this.network = new vis.Network(
      canvasElement,
      {
        nodes: this.nodeDataSet,
        edges: this.edgeDataSet,
      },
      {
        layout: internals.FREE_LAYOUT,
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
      }
    );

    this.network.on("click", (params) => {
      this._handleClick(params);
    });

    this.network.on("dragEnd", (params) => {
      this._handleDragEnd(params);
      this._scheduleBloomingRefresh();
    });
  }

  setViewMode(mode) {
    const normalizedMode = String(mode || "").trim().toLowerCase() === "prune" ? "prune" : "raw";
    if (this.viewMode === normalizedMode) {
      return false;
    }

    this.viewMode = normalizedMode;
    this.selectedNodeId = "";
    this._emitNodeSelection();
    this._renderFromState({ fit: true, preserveExisting: false });
    return true;
  }

  toggleViewMode() {
    const nextMode = this.viewMode === "prune" ? "raw" : "prune";
    return this.setViewMode(nextMode);
  }

  getViewMode() {
    return this.viewMode;
  }

  setRelationFilters(filters) {
    this.relationFilters = internals.normalizeRelationFilters(filters);
    this._renderFromState({ fit: true, preserveExisting: false });
  }

  getRelationFilters() {
    return [...this.relationFilters];
  }

  setNodeSelectHandler(callback) {
    this.onNodeSelect = typeof callback === "function" ? callback : null;
  }

  getVisibleStats() {
    return {
      nodes: this.visibleNodeMap.size,
      edges: this.visibleEdgeMap.size,
    };
  }

  setHighlightContext(context = {}) {
    const normalizedContext = context && context.highlight ? context.highlight : context;
    const nextNodeIds = new Set(
      ((normalizedContext && normalizedContext.node_ids) || [])
        .map((nodeId) => String(nodeId || "").trim())
        .filter(Boolean)
    );
    const nextEdgeIds = new Set(
      ((normalizedContext && normalizedContext.edge_ids) || [])
        .map((edgeId) => String(edgeId || "").trim())
        .filter(Boolean)
    );
    const nextMatchedNodeIds = new Set(
      ((context && context.matched_node_ids) || [])
        .map((nodeId) => String(nodeId || "").trim())
        .filter(Boolean)
    );

    this.highlightNodeIds = nextNodeIds;
    this.highlightEdgeIds = nextEdgeIds;
    this.matchedNodeIds = nextMatchedNodeIds;
    this._updateBloomingModelAndData({ fit: false });
  }

  clearHighlightContext() {
    if (!this.highlightNodeIds.size && !this.highlightEdgeIds.size && !this.matchedNodeIds.size) {
      return;
    }

    this.highlightNodeIds.clear();
    this.highlightEdgeIds.clear();
    this.matchedNodeIds.clear();
    this._updateBloomingModelAndData({ fit: false });
  }

  getParentChildrenToggleState(nodeId) {
    const parentId = String(nodeId || "").trim();
    if (!parentId) {
      return {
        canToggle: false,
        parentId: "",
        totalChildren: 0,
        hiddenChildren: 0,
        allHidden: false,
      };
    }

    const autoChildren = this.autoHiddenChildrenByParent.get(parentId);
    if (!autoChildren || !autoChildren.size) {
      return {
        canToggle: false,
        parentId,
        totalChildren: 0,
        hiddenChildren: 0,
        allHidden: false,
      };
    }

    const manualHidden = this.manualHiddenChildrenByParent.get(parentId) || new Set();
    const hiddenChildren = [...autoChildren].filter((childId) => manualHidden.has(childId)).length;

    return {
      canToggle: true,
      parentId,
      totalChildren: autoChildren.size,
      hiddenChildren,
      allHidden: hiddenChildren === autoChildren.size,
    };
  }

  toggleParentChildrenVisibility(nodeId) {
    const parentId = String(nodeId || "").trim();
    const toggleState = this.getParentChildrenToggleState(parentId);
    if (!toggleState.canToggle) {
      return toggleState;
    }

    const childIds = this.autoHiddenChildrenByParent.get(parentId);
    const currentlyAllHidden = Boolean(toggleState.allHidden);
    if (currentlyAllHidden) {
      this.manualHiddenChildrenByParent.set(parentId, new Set());
    } else {
      this.manualHiddenChildrenByParent.set(parentId, new Set(childIds));
    }

    this._updateBloomingModelAndData({ fit: false });
    return this.getParentChildrenToggleState(parentId);
  }

  getRelationTypeCounts() {
    const sourceGraph = this.currentDisplayGraph || { edges: [] };
    const counts = {};
    (sourceGraph.edges || []).forEach((edge) => {
      const relation = internals.normalizeRelationType(edge);
      if (!relation) {
        return;
      }
      counts[relation] = (counts[relation] || 0) + 1;
    });
    return counts;
  }

  getNodeDetails(nodeId) {
    const key = String(nodeId || "").trim();
    if (!key) {
      return null;
    }

    const node = this.currentNodeMap.get(key);
    if (!node) {
      return null;
    }

    const outgoing = [];
    const incoming = [];

    this.currentEdgeMap.forEach((edge) => {
      const from = String(edge.source || edge.from || "").trim();
      const to = String(edge.target || edge.to || "").trim();
      if (!from || !to) {
        return;
      }

      const relation = internals.normalizeRelationType(edge) || "RELATED_TO";
      const edgeId = this._getEdgeId(edge);
      const visible = this.visibleEdgeMap.has(edgeId);

      if (from === key) {
        const targetNode = this.currentNodeMap.get(to);
        outgoing.push({
          edge_id: edgeId,
          relation,
          to,
          to_label: targetNode ? (targetNode.label || targetNode.id) : to,
          visible,
        });
      } else if (to === key) {
        const sourceNode = this.currentNodeMap.get(from);
        incoming.push({
          edge_id: edgeId,
          relation,
          from,
          from_label: sourceNode ? (sourceNode.label || sourceNode.id) : from,
          visible,
        });
      }
    });

    outgoing.sort((left, right) => {
      const relCmp = left.relation.localeCompare(right.relation);
      if (relCmp !== 0) {
        return relCmp;
      }
      return String(left.to_label || "").localeCompare(String(right.to_label || ""));
    });

    incoming.sort((left, right) => {
      const relCmp = left.relation.localeCompare(right.relation);
      if (relCmp !== 0) {
        return relCmp;
      }
      return String(left.from_label || "").localeCompare(String(right.from_label || ""));
    });

    return {
      node,
      outgoing,
      incoming,
    };
  }

  renderSnapshot(graphState) {
    this._setFullState(graphState);
    this._renderFromState({ fit: true, preserveExisting: false });
  }

  applyDelta(delta) {
    const addedNodesRaw = (delta && delta.added_nodes) || [];
    const updatedNodesRaw = (delta && delta.updated_nodes) || [];
    const addedEdgesRaw = (delta && delta.added_edges) || [];
    const removedEdgeIds = (delta && delta.removed_edge_ids) || [];

    addedNodesRaw.forEach((node) => {
      this.nodeMap.set(node.id, node);
    });
    updatedNodesRaw.forEach((node) => {
      this.nodeMap.set(node.id, node);
    });

    addedEdgesRaw.forEach((edge) => {
      this.edgeMap.set(edge.id, edge);
    });
    removedEdgeIds.forEach((edgeId) => {
      this.edgeMap.delete(edgeId);
    });

    this._markGraphChanged();
    this._renderFromState({ fit: false, preserveExisting: true });
  }

  _setFullState(graphState) {
    this.nodeMap.clear();
    this.edgeMap.clear();

    ((graphState && graphState.nodes) || []).forEach((node) => {
      this.nodeMap.set(node.id, node);
    });
    ((graphState && graphState.edges) || []).forEach((edge) => {
      this.edgeMap.set(edge.id, edge);
    });

    this._markGraphChanged();
  }

  _markGraphChanged() {
    this.graphRevision += 1;
    this.cachedPrunedRevision = -1;
    this.cachedPrunedGraph = null;
  }

  _edgeMatchesFilters(edge) {
    const relation = internals.normalizeRelationType(edge).toLowerCase();
    if (!relation) {
      return false;
    }

    if (!this.relationFilters.length) {
      return !DEFAULT_HIDDEN_RELATIONS.has(relation);
    }

    return this.relationFilters.some((filter) => relation.includes(filter));
  }

  _getSourceGraphForMode() {
    const rawGraph = {
      nodes: [...this.nodeMap.values()],
      edges: [...this.edgeMap.values()],
    };

    if (this.viewMode !== "prune") {
      return rawGraph;
    }

    if (this.cachedPrunedGraph && this.cachedPrunedRevision === this.graphRevision) {
      return this.cachedPrunedGraph;
    }

    this.cachedPrunedGraph = pruneApi.buildPrunedGraph(rawGraph);
    this.cachedPrunedRevision = this.graphRevision;
    return this.cachedPrunedGraph;
  }

  _buildDisplayGraph() {
    const sourceGraph = this._getSourceGraphForMode();
    const allNodes = [...(sourceGraph.nodes || [])];
    const allEdges = [...(sourceGraph.edges || [])];

    const visibleEdges = allEdges.filter((edge) => this._edgeMatchesFilters(edge));
    const visibleNodeIds = new Set();
    visibleEdges.forEach((edge) => {
      const from = String(edge.source || edge.from || "").trim();
      const to = String(edge.target || edge.to || "").trim();
      if (from) {
        visibleNodeIds.add(from);
      }
      if (to) {
        visibleNodeIds.add(to);
      }
    });

    allNodes.forEach((node) => {
      if (String(node.type || "").toLowerCase() === "technique") {
        visibleNodeIds.add(node.id);
      }
    });

    const visibleNodes = allNodes.filter((node) => visibleNodeIds.has(node.id));

    return {
      nodes: visibleNodes,
      edges: visibleEdges.filter((edge) => {
        const from = String(edge.source || edge.from || "").trim();
        const to = String(edge.target || edge.to || "").trim();
        return visibleNodeIds.has(from) && visibleNodeIds.has(to);
      }),
    };
  }

  _renderFromState(options = {}) {
    const fit = Boolean(options.fit);
    const preserveExisting = Boolean(options.preserveExisting);

    const displayGraph = this._buildDisplayGraph();
    this.currentDisplayGraph = displayGraph;
    this.currentNodeMap = new Map((displayGraph.nodes || []).map((node) => [String(node.id), node]));
    this.currentEdgeMap = new Map(
      (displayGraph.edges || []).map((edge) => [this._getEdgeId(edge), edge])
    );

    this._recomputeBaseLayout(displayGraph, preserveExisting);
    this._updateBloomingModelAndData({ fit });
  }

  _getScale() {
    if (!this.network || typeof this.network.getScale !== "function") {
      return 1;
    }

    const scale = Number(this.network.getScale());
    if (!Number.isFinite(scale) || scale <= 0) {
      return 1;
    }

    return scale;
  }

  _getViewCenter() {
    if (!this.network || typeof this.network.getViewPosition !== "function") {
      return { x: 0, y: 0 };
    }

    const center = this.network.getViewPosition();
    if (!center || !Number.isFinite(center.x) || !Number.isFinite(center.y)) {
      return { x: 0, y: 0 };
    }

    return center;
  }

  _computeDepthMap(nodes, edges) {
    const nodeIds = nodes.map((node) => String(node.id || "").trim()).filter(Boolean);
    const nodeIdSet = new Set(nodeIds);
    const { children, indegree } = internals.buildChildrenMap(edges || []);

    let roots = nodes
      .filter((node) => this._isTechniqueNode(node))
      .map((node) => String(node.id || "").trim())
      .filter(Boolean);

    if (!roots.length) {
      roots = nodeIds.filter((nodeId) => (indegree.get(nodeId) || 0) === 0);
    }

    if (!roots.length && nodeIds.length) {
      roots = [nodeIds[0]];
    }

    const depthMap = new Map();
    const queue = roots.map((rootId) => ({ nodeId: rootId, depth: 0 }));

    while (queue.length) {
      const current = queue.shift();
      if (!current || !nodeIdSet.has(current.nodeId)) {
        continue;
      }

      const existingDepth = depthMap.get(current.nodeId);
      if (Number.isFinite(existingDepth) && existingDepth <= current.depth) {
        continue;
      }

      depthMap.set(current.nodeId, current.depth);
      const nextChildren = children.get(current.nodeId) || [];
      nextChildren.forEach((childId) => {
        const normalizedChild = String(childId || "").trim();
        if (!normalizedChild || !nodeIdSet.has(normalizedChild)) {
          return;
        }

        queue.push({ nodeId: normalizedChild, depth: current.depth + 1 });
      });
    }

    nodeIds.forEach((nodeId) => {
      if (!depthMap.has(nodeId)) {
        depthMap.set(nodeId, Number.MAX_SAFE_INTEGER);
      }
    });

    return depthMap;
  }

  _buildAutoHiddenChildrenMap(nodes, edges) {
    const collapsePrefixes = this.defaultCollapsedProcessPrefixes
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean);

    if (this.childHideThreshold <= 0 && !collapsePrefixes.length) {
      return new Map();
    }

    const childrenByParent = new Map();
    const nodeById = new Map(
      (nodes || [])
        .map((node) => [String((node && node.id) || "").trim(), node])
        .filter(([nodeId]) => Boolean(nodeId))
    );

    (edges || []).forEach((edge) => {
      const source = String(edge.source || edge.from || "").trim();
      const target = String(edge.target || edge.to || "").trim();
      if (!source || !target) {
        return;
      }

      const relationType = (internals.normalizeRelationType(edge) || "").toUpperCase();
      if (relationType === "HAS_ROOT") {
        return;
      }

      if (!childrenByParent.has(source)) {
        childrenByParent.set(source, new Set());
      }

      childrenByParent.get(source).add(target);
    });

    const autoHiddenChildrenByParent = new Map();
    childrenByParent.forEach((childIds, parentId) => {
      const parentNode = nodeById.get(parentId);
      const shouldCollapseByCount = this.childHideThreshold > 0 && childIds.size > this.childHideThreshold;
      const shouldCollapseByName = this._isDefaultCollapsedProcessParent(parentNode, collapsePrefixes);

      if (shouldCollapseByCount || shouldCollapseByName) {
        autoHiddenChildrenByParent.set(parentId, childIds);
      }
    });

    return autoHiddenChildrenByParent;
  }

  _computeBloomingModel(graph) {
    const nodes = (graph && graph.nodes) || [];
    const edges = (graph && graph.edges) || [];

    if (!nodes.length) {
      return {
        activeNodeIds: new Set(),
        activeEdgeIds: new Set(),
        depthMap: new Map(),
        autoHiddenChildrenByParent: new Map(),
        hiddenCountByParent: new Map(),
      };
    }

    const depthMap = this._computeDepthMap(nodes, edges);
    const autoHiddenChildrenByParent = this._buildAutoHiddenChildrenMap(nodes, edges);

    autoHiddenChildrenByParent.forEach((childIds, parentId) => {
      const existingHidden = this.manualHiddenChildrenByParent.get(parentId);
      if (!existingHidden) {
        this.manualHiddenChildrenByParent.set(parentId, new Set(childIds));
        return;
      }

      if (!existingHidden.size) {
        this.manualHiddenChildrenByParent.set(parentId, new Set());
        return;
      }

      this.manualHiddenChildrenByParent.set(parentId, new Set(childIds));
    });

    const activeNodeIds = new Set();

    nodes.forEach((node) => {
      const nodeId = String(node.id || "").trim();
      if (!nodeId) {
        return;
      }
      activeNodeIds.add(nodeId);
    });

    autoHiddenChildrenByParent.forEach((children, parentId) => {
      const manualHidden = this.manualHiddenChildrenByParent.get(parentId) || new Set();
      children.forEach((childId) => {
        if (!manualHidden.has(childId)) {
          return;
        }
        activeNodeIds.delete(childId);
      });
    });

    const hiddenCountByParent = new Map();
    autoHiddenChildrenByParent.forEach((childIds, parentId) => {
      const parentIsActive = activeNodeIds.has(parentId);
      let hiddenCount = 0;
      childIds.forEach((childId) => {
        if (!activeNodeIds.has(childId)) {
          hiddenCount += 1;
        }
      });

      // Do not resurrect a parent that is already hidden by another parent.
      if (hiddenCount > 0 && parentIsActive) {
        hiddenCountByParent.set(parentId, hiddenCount);
      }
    });

    const activeEdgeIds = new Set();
    edges.forEach((edge) => {
      const source = String(edge.source || edge.from || "").trim();
      const target = String(edge.target || edge.to || "").trim();
      if (!source || !target) {
        return;
      }

      if (!activeNodeIds.has(source) || !activeNodeIds.has(target)) {
        return;
      }

      activeEdgeIds.add(this._getEdgeId(edge));
    });

    const connectedNodeIds = new Set();
    edges.forEach((edge) => {
      const edgeId = this._getEdgeId(edge);
      if (!activeEdgeIds.has(edgeId)) {
        return;
      }

      const source = String(edge.source || edge.from || "").trim();
      const target = String(edge.target || edge.to || "").trim();
      if (source) {
        connectedNodeIds.add(source);
      }
      if (target) {
        connectedNodeIds.add(target);
      }
    });

    [...activeNodeIds].forEach((nodeId) => {
      if (!connectedNodeIds.has(nodeId)) {
        activeNodeIds.delete(nodeId);
      }
    });

    [...hiddenCountByParent.keys()].forEach((parentId) => {
      if (!activeNodeIds.has(parentId)) {
        hiddenCountByParent.delete(parentId);
      }
    });

    return {
      activeNodeIds,
      activeEdgeIds,
      depthMap,
      autoHiddenChildrenByParent,
      hiddenCountByParent,
    };
  }

  _updateBloomingModelAndData(options = {}) {
    const fit = Boolean(options.fit);
    const displayGraph = this.currentDisplayGraph || { nodes: [], edges: [] };

    const bloomModel = this._computeBloomingModel(displayGraph);
    this.depthMap = bloomModel.depthMap;
    this.autoHiddenChildrenByParent = bloomModel.autoHiddenChildrenByParent;
    this.hiddenCountByParent = bloomModel.hiddenCountByParent;

    this.visibleNodeMap = new Map(
      (displayGraph.nodes || [])
        .filter((node) => bloomModel.activeNodeIds.has(String(node.id)))
        .map((node) => [String(node.id), node])
    );

    this.visibleEdgeMap = new Map(
      (displayGraph.edges || [])
        .filter((edge) => bloomModel.activeEdgeIds.has(this._getEdgeId(edge)))
        .map((edge) => [this._getEdgeId(edge), edge])
    );

    const visNodes = (displayGraph.nodes || []).map((node) => {
      const nodeId = String(node.id || "").trim();
      const hasHighlight =
        this.highlightNodeIds.size > 0 ||
        this.highlightEdgeIds.size > 0 ||
        this.matchedNodeIds.size > 0;
      const isHighlighted = this.highlightNodeIds.has(nodeId);
      const isMatched = this.matchedNodeIds.has(nodeId);
      return this._toVisNode(node, {
        isVisible: bloomModel.activeNodeIds.has(nodeId),
        hiddenCount: bloomModel.hiddenCountByParent.get(nodeId) || 0,
        isHighlighted,
        isMatched,
        isDimmed: hasHighlight && !isHighlighted && !isMatched,
      });
    });

    const visEdges = (displayGraph.edges || []).map((edge) => {
      const edgeId = this._getEdgeId(edge);
      const hasHighlight =
        this.highlightNodeIds.size > 0 ||
        this.highlightEdgeIds.size > 0 ||
        this.matchedNodeIds.size > 0;
      const isHighlighted = this.highlightEdgeIds.has(edgeId);
      return this._toVisEdge(edge, {
        isVisible: bloomModel.activeEdgeIds.has(edgeId),
        isHighlighted,
        isDimmed: hasHighlight && !isHighlighted,
      });
    });

    internals.updateDataSet(this.nodeDataSet, visNodes);
    internals.updateDataSet(this.edgeDataSet, visEdges);

    if (fit && this.visibleNodeMap.size > 0) {
      this.network.fit({
        nodes: [...this.visibleNodeMap.keys()],
        animation: false,
      });
    }

    if (this.selectedNodeId && !this.visibleNodeMap.has(this.selectedNodeId)) {
      this.selectedNodeId = "";
      this._emitNodeSelection();
      return;
    }

    if (this.selectedNodeId) {
      this._emitNodeSelection();
    }
  }

  _scheduleBloomingRefresh() {
    this._updateBloomingModelAndData({ fit: false });
  }

  _emitNodeSelection() {
    if (!this.onNodeSelect) {
      return;
    }

    if (!this.selectedNodeId) {
      this.onNodeSelect(null);
      return;
    }

    this.onNodeSelect(this.getNodeDetails(this.selectedNodeId));
  }

  _handleClick(params) {
    if (!params.nodes || !params.nodes.length) {
      this.selectedNodeId = "";
      this._emitNodeSelection();
      return;
    }

    this.selectedNodeId = String(params.nodes[0] || "").trim();
    this._emitNodeSelection();
  }

  _recomputeBaseLayout(graph, preserveExisting = false) {
    layoutApi.recomputeBaseLayout(this, graph, preserveExisting);
  }

  _handleDragEnd(params) {
    dragApi.applyDragEnd(this, params);
  }

  _isTechniqueNode(node) {
    if (typeof pruneApi.isTechniqueNode === "function") {
      return pruneApi.isTechniqueNode(node);
    }

    return String((node && (node.type || node.group)) || "").trim().toLowerCase() === "technique";
  }

  _isProcessNode(node) {
    if (typeof pruneApi.isProcessNode === "function") {
      return pruneApi.isProcessNode(node);
    }

    return String((node && (node.type || node.group)) || "").trim().toLowerCase() === "process";
  }

  _getEdgeId(edge) {
    const source = String(edge && (edge.source || edge.from || "")).trim();
    const target = String(edge && (edge.target || edge.to || "")).trim();
    const relation = internals.normalizeRelationType(edge) || "RELATED_TO";
    return String(edge && edge.id ? edge.id : `${source}::${target}::${relation}`);
  }

  _toVisNode(node, options = {}) {
    const isVisible = options.isVisible !== false;
    const hiddenCount = Number(options.hiddenCount || 0);
    const isHighlighted = options.isHighlighted === true;
    const isMatched = options.isMatched === true;
    const isDimmed = options.isDimmed === true;
    const color = internals.colorForGroup(node.group);
    const basePosition = this.basePositions.get(node.id);
    const withPosition = basePosition
      ? {
          x: basePosition.x,
          y: basePosition.y,
        }
      : {};

    const hiddenSuffix = hiddenCount > 0 ? ` (+${hiddenCount} hidden nodes)` : "";
    const label = `${node.label || node.id}${hiddenSuffix}`;

    const titleLines = [`${node.group || "Entity"}: ${node.label || node.id}`];
    if (hiddenCount > 0) {
      titleLines.push(`Hidden nodes: ${hiddenCount}`);
    }

    return {
      id: node.id,
      label,
      group: node.group,
      hidden: !isVisible,
      title: titleLines.join("\n"),
      size: isMatched ? 17 : isHighlighted ? 14 : 13,
      font: {
        color: "#1f2937",
      },
      color: {
        border: isMatched ? "#dc2626" : isHighlighted ? "#2563eb" : isDimmed ? "#a8a29e" : color,
        background: isMatched
          ? "#fee2e2"
          : isHighlighted
            ? "#dbeafe"
            : isDimmed
              ? `${color}10`
              : `${color}22`,
        highlight: {
          border: isMatched ? "#dc2626" : isHighlighted ? "#2563eb" : color,
          background: isMatched ? "#fecaca" : isHighlighted ? "#bfdbfe" : `${color}44`,
        },
      },
      ...withPosition,
    };
  }

  _toVisEdge(edge, options = {}) {
    const isVisible = options.isVisible !== false;
    const isHighlighted = options.isHighlighted === true;
    const isDimmed = options.isDimmed === true;
    const type = internals.normalizeRelationType(edge);
    const isRoot = type.toUpperCase() === "HAS_ROOT";

    return {
      id: this._getEdgeId(edge),
      from: edge.source || edge.from,
      to: edge.target || edge.to,
      label: type,
      title: type,
      hidden: !isVisible,
      dashes: isRoot,
      width: isHighlighted ? 1.8 : 1.1,
      color: {
        color: isHighlighted ? "#2563eb" : isDimmed ? "#bdb7af" : isRoot ? "#0f766e" : "#8c8b87",
        highlight: isHighlighted ? "#2563eb" : "#0f766e",
      },
    };
  }

  _isDefaultCollapsedProcessParent(node, collapsePrefixes = []) {
    if (!node || !this._isProcessNode(node) || !collapsePrefixes.length) {
      return false;
    }

    const name = this._processBaseName(node);
    if (!name) {
      return false;
    }

    return collapsePrefixes.some((prefix) => name === prefix || name === `${prefix}.exe` || name.startsWith(prefix));
  }

  _processBaseName(node) {
    const properties = (node && node.properties) || {};
    const candidates = [
      properties.image,
      properties.Image,
      properties.image_path,
      properties.ImagePath,
      properties.process_image,
      properties.ProcessImage,
      properties.command_line,
      properties.CommandLine,
      properties.process_command_line,
      properties.ProcessCommandLine,
      properties.source_image,
      properties.SourceImage,
      properties.source_image_path,
      properties.SourceImagePath,
      properties.original_file_name,
      properties.OriginalFileName,
      properties.image_file_name,
      properties.ImageFileName,
      properties.process_name,
      properties.ProcessName,
      properties.name,
      properties.Name,
      node && node.label,
      node && node.id,
    ];

    for (const candidate of candidates) {
      const text = String(candidate || "").trim().toLowerCase().replace(/\\/g, "/");
      if (!text) {
        continue;
      }

      const segments = text.split(/[/:]+/).filter(Boolean);
      const baseName = segments.length ? segments[segments.length - 1].replace(/^['\"]+|['\"]+$/g, "") : "";
      if (baseName) {
        return baseName;
      }
    }

    return "";
  }
}

window.Streamline.GraphView = GraphView;
})();
