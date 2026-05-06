(() => {
window.Streamline = window.Streamline || {};
const internals = window.Streamline.GraphViewInternals || {};
window.Streamline.GraphViewInternals = internals;

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function cloneNode(node) {
  return {
    ...node,
    properties: {
      ...((node && node.properties) || {}),
    },
  };
}

function cloneEdge(edge) {
  return {
    ...edge,
    properties: {
      ...((edge && edge.properties) || {}),
    },
  };
}

function normalizeText(value) {
  return String(value || "").trim().toLowerCase();
}

function isMeaningfulValue(value) {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === "string") {
    return value.trim().length > 0;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (isObject(value)) {
    return Object.keys(value).length > 0;
  }
  return true;
}

function isIdentifierLikeKey(key) {
  const normalized = normalizeText(key);
  if (!normalized) {
    return false;
  }

  if (
    normalized === "id" ||
    normalized === "pid" ||
    normalized === "guid" ||
    normalized.endsWith("_id") ||
    normalized.includes("guid") ||
    normalized.endsWith("pid") ||
    normalized.endsWith("processid") ||
    normalized.endsWith("threadid") ||
    normalized.endsWith("recordid")
  ) {
    return true;
  }

  return false;
}

function normalizeForSignature(value) {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeForSignature(item));
  }

  if (isObject(value)) {
    const sortedKeys = Object.keys(value).sort((left, right) => left.localeCompare(right));
    const normalizedObject = {};
    sortedKeys.forEach((key) => {
      normalizedObject[key] = normalizeForSignature(value[key]);
    });
    return normalizedObject;
  }

  if (typeof value === "string") {
    return value.trim().toLowerCase();
  }

  return value;
}

function sanitizeObjectForMergeSignature(payload) {
  if (Array.isArray(payload)) {
    return payload.map((item) => sanitizeObjectForMergeSignature(item));
  }

  if (!isObject(payload)) {
    return payload;
  }

  const sanitized = {};
  Object.keys(payload).forEach((key) => {
    if (isIdentifierLikeKey(key)) {
      return;
    }

    sanitized[key] = sanitizeObjectForMergeSignature(payload[key]);
  });

  return sanitized;
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  if (isObject(value)) {
    const sortedKeys = Object.keys(value).sort((left, right) => left.localeCompare(right));
    return `{${sortedKeys
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}

function makeNodeSignature(node) {
  const payload = {
    group: (node && node.group) || "",
    type: (node && node.type) || "",
    label: (node && node.label) || "",
    properties: sanitizeObjectForMergeSignature((node && node.properties) || {}),
  };

  return stableStringify(normalizeForSignature(payload));
}

function normalizeEdgeShape(edge) {
  const from = String(edge && (edge.source || edge.from || "")).trim();
  const to = String(edge && (edge.target || edge.to || "")).trim();
  const relation = internals.normalizeRelationType(edge) || "RELATED_TO";

  return {
    ...cloneEdge(edge),
    id: String(edge && edge.id ? edge.id : `${from}::${to}::${relation}`),
    source: from,
    target: to,
    from,
    to,
    label: relation,
    type: relation,
    properties: {
      ...(((edge && edge.properties) || {})),
      action: relation,
    },
  };
}

function mergeObjectLatest(existing, incoming) {
  const merged = {
    ...((existing && typeof existing === "object") ? existing : {}),
  };

  Object.entries((incoming && typeof incoming === "object") ? incoming : {}).forEach(
    ([key, incomingValue]) => {
      const currentValue = merged[key];

      if (isObject(currentValue) && isObject(incomingValue)) {
        merged[key] = mergeObjectLatest(currentValue, incomingValue);
        return;
      }

      if (isMeaningfulValue(incomingValue) || !isMeaningfulValue(currentValue)) {
        merged[key] = incomingValue;
      }
    }
  );

  return merged;
}

function mergeNodeLatest(existing, incoming) {
  const incomingClone = cloneNode(incoming);
  const merged = {
    ...cloneNode(existing),
    ...incomingClone,
    id: existing.id,
  };

  merged.properties = mergeObjectLatest(existing.properties || {}, incomingClone.properties || {});

  if (isMeaningfulValue(incomingClone.label)) {
    merged.label = incomingClone.label;
  } else if (isMeaningfulValue(merged.properties && merged.properties.display_name)) {
    merged.label = merged.properties.display_name;
  }

  return merged;
}

function mergeEdgeLatest(existing, incoming) {
  const merged = {
    ...cloneEdge(existing),
    ...cloneEdge(incoming),
    id: existing.id,
    source: existing.source,
    target: existing.target,
    from: existing.source,
    to: existing.target,
  };

  merged.properties = mergeObjectLatest(existing.properties || {}, incoming.properties || {});
  return merged;
}

function resolveRedirect(nodeId, redirectMap) {
  let current = String(nodeId || "").trim();
  const visited = new Set();

  while (current && redirectMap.has(current) && !visited.has(current)) {
    visited.add(current);
    current = redirectMap.get(current);
  }

  return current;
}

function applyRedirectsToEdges(edges, redirectMap) {
  return (edges || [])
    .map((edge) => normalizeEdgeShape(edge))
    .map((edge) => {
      const source = resolveRedirect(edge.source, redirectMap);
      const target = resolveRedirect(edge.target, redirectMap);
      return {
        ...edge,
        source,
        target,
        from: source,
        to: target,
      };
    })
    .filter((edge) => edge.source && edge.target && edge.source !== edge.target);
}

function dedupeEdgesLatest(edges) {
  const edgeMap = new Map();

  (edges || []).forEach((edge) => {
    const normalizedEdge = normalizeEdgeShape(edge);
    if (!normalizedEdge.source || !normalizedEdge.target || normalizedEdge.source === normalizedEdge.target) {
      return;
    }

    const relation = normalizeText(normalizedEdge.label || normalizedEdge.type || "RELATED_TO");
    const dedupeKey = `${normalizedEdge.source}::${normalizedEdge.target}::${relation}`;

    if (!edgeMap.has(dedupeKey)) {
      edgeMap.set(dedupeKey, normalizedEdge);
      return;
    }

    edgeMap.set(dedupeKey, mergeEdgeLatest(edgeMap.get(dedupeKey), normalizedEdge));
  });

  return [...edgeMap.values()];
}

function isTechniqueNode(node) {
  return normalizeText(node && (node.type || node.group)) === "technique";
}

function isProcessNode(node) {
  const nodeType = normalizeText(node && node.type);
  const groupType = normalizeText(node && node.group);
  return nodeType === "process" || groupType === "process";
}

function buildPrunedGraph(graph) {
  const rawNodes = Array.isArray(graph && graph.nodes) ? graph.nodes : [];
  const rawEdges = Array.isArray(graph && graph.edges) ? graph.edges : [];

  const nodeMap = new Map(
    rawNodes
      .map((node) => cloneNode(node))
      .filter((node) => node && node.id)
      .map((node) => [String(node.id).trim(), node])
  );

  const redirectMap = new Map();

  const processSignatureToCanonicalId = new Map();
  rawNodes.forEach((rawNode) => {
    const nodeId = String((rawNode && rawNode.id) || "").trim();
    if (!nodeId) {
      return;
    }

    const node = nodeMap.get(nodeId);
    if (!node || !isProcessNode(node)) {
      return;
    }

    const signature = makeNodeSignature(node);
    const canonicalId = processSignatureToCanonicalId.get(signature);
    if (!canonicalId) {
      processSignatureToCanonicalId.set(signature, nodeId);
      return;
    }

    if (canonicalId === nodeId) {
      return;
    }

    redirectMap.set(nodeId, canonicalId);
    nodeMap.set(canonicalId, mergeNodeLatest(nodeMap.get(canonicalId), node));
    nodeMap.delete(nodeId);
  });

  const processMergedEdges = dedupeEdgesLatest(applyRedirectsToEdges(rawEdges, redirectMap));

  const processNodeIds = new Set(
    [...nodeMap.values()].filter((node) => isProcessNode(node)).map((node) => String(node.id))
  );

  const relationMergeGroups = new Map();
  processMergedEdges.forEach((edge) => {
    const sourceId = String(edge.source || edge.from || "").trim();
    const targetId = String(edge.target || edge.to || "").trim();
    if (!sourceId || !targetId) {
      return;
    }

    const sourceIsProcess = processNodeIds.has(sourceId);
    const targetIsProcess = processNodeIds.has(targetId);
    if (sourceIsProcess === targetIsProcess) {
      return;
    }

    const processId = sourceIsProcess ? sourceId : targetId;
    const relatedId = sourceIsProcess ? targetId : sourceId;
    const relatedNode = nodeMap.get(relatedId);
    if (!relatedNode || isProcessNode(relatedNode) || isTechniqueNode(relatedNode)) {
      return;
    }

    const direction = sourceIsProcess ? "out" : "in";
    const relation = normalizeText(edge.label || edge.type || "RELATED_TO");
    const signature = makeNodeSignature(relatedNode);
    const mergeKey = `${processId}::${direction}::${relation}::${signature}`;

    const canonicalRelatedId = relationMergeGroups.get(mergeKey);
    if (!canonicalRelatedId) {
      relationMergeGroups.set(mergeKey, relatedId);
      return;
    }

    if (canonicalRelatedId === relatedId) {
      return;
    }

    redirectMap.set(relatedId, canonicalRelatedId);
    nodeMap.set(canonicalRelatedId, mergeNodeLatest(nodeMap.get(canonicalRelatedId), relatedNode));
    nodeMap.delete(relatedId);
  });

  const finalEdges = dedupeEdgesLatest(applyRedirectsToEdges(processMergedEdges, redirectMap));
  const referencedNodeIds = new Set();
  finalEdges.forEach((edge) => {
    if (edge.source) {
      referencedNodeIds.add(edge.source);
    }
    if (edge.target) {
      referencedNodeIds.add(edge.target);
    }
  });

  const finalNodes = [];
  nodeMap.forEach((node, nodeId) => {
    if (referencedNodeIds.has(nodeId) || isTechniqueNode(node)) {
      finalNodes.push(node);
    }
  });

  return {
    nodes: finalNodes,
    edges: finalEdges,
  };
}

internals.prune = {
  buildPrunedGraph,
  isProcessNode,
  isTechniqueNode,
};
})();
