(() => {
window.Streamline = window.Streamline || {};
const internals = window.Streamline.GraphViewInternals || {};
window.Streamline.GraphViewInternals = internals;

internals.GROUP_COLORS = {
  Technique: "#0f766e",
  Process: "#3f3f46",
  File: "#1d4ed8",
  Network: "#b45309",
  Registry: "#6d28d9",
  User: "#065f46",
  Wmi: "#7c2d12",
  UnknownEntity: "#475569",
};

internals.FREE_LAYOUT = {
  improvedLayout: true,
  hierarchical: {
    enabled: false,
  },
};

internals.colorForGroup = function colorForGroup(group) {
  return internals.GROUP_COLORS[group] || "#334155";
};

internals.normalizeRelationType = function normalizeRelationType(edge) {
  return String(
    edge && (edge.type || edge.label || ((edge.properties || {}).action || ""))
  ).trim();
};

internals.normalizeRelationFilters = function normalizeRelationFilters(filters) {
  const seen = new Set();
  const normalized = [];

  (filters || []).forEach((raw) => {
    const value = String(raw || "").trim().toLowerCase();
    if (!value || seen.has(value)) {
      return;
    }
    seen.add(value);
    normalized.push(value);
  });

  return normalized;
};

internals.buildChildrenMap = function buildChildrenMap(edges) {
  const children = new Map();
  const indegree = new Map();

  (edges || []).forEach((edge) => {
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
};

internals.getAllDescendants = function getAllDescendants(nodeId, childrenMap) {
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
};

internals.updateDataSet = function updateDataSet(dataSet, nextItems) {
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
};
})();
