(() => {
class GraphStore {
  constructor() {
    this.nodes = new Map();
    this.edges = new Map();
    this.stats = {};
    this.listeners = new Set();
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  _emit() {
    const snapshot = this.getState();
    this.listeners.forEach((listener) => listener(snapshot));
  }

  applySnapshot(graph) {
    this.nodes.clear();
    this.edges.clear();

    ((graph && graph.nodes) || []).forEach((node) => {
      this.nodes.set(node.id, node);
    });
    ((graph && graph.edges) || []).forEach((edge) => {
      this.edges.set(edge.id, edge);
    });

    this.stats = { ...((graph && graph.stats) || {}) };
    this._emit();
  }

  applyDelta(delta) {
    ((delta && delta.added_nodes) || []).forEach((node) => {
      this.nodes.set(node.id, node);
    });
    ((delta && delta.updated_nodes) || []).forEach((node) => {
      this.nodes.set(node.id, node);
    });

    ((delta && delta.added_edges) || []).forEach((edge) => {
      this.edges.set(edge.id, edge);
    });

    ((delta && delta.removed_edge_ids) || []).forEach((edgeId) => {
      this.edges.delete(edgeId);
    });

    if (delta && delta.stats) {
      this.stats = { ...delta.stats };
    }

    this._emit();
  }

  getState() {
    return {
      nodes: [...this.nodes.values()],
      edges: [...this.edges.values()],
      stats: { ...this.stats },
    };
  }
}

window.Streamline = window.Streamline || {};
window.Streamline.GraphStore = GraphStore;
})();
