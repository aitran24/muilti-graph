(() => {
window.Streamline = window.Streamline || {};
const internals = window.Streamline.GraphViewInternals || {};
window.Streamline.GraphViewInternals = internals;

function applyDragEnd(view, params) {
  if (!params.nodes || !params.nodes.length) {
    return;
  }

  const draggedIds = params.nodes;
  const { children } = internals.buildChildrenMap([...view.visibleEdgeMap.values()]);
  const latestPositions = view.network.getPositions(draggedIds);
  const positionsToUpdate = {};

  draggedIds.forEach((parentId) => {
    const oldParentPos = view.basePositions.get(parentId) || { x: 0, y: 0 };
    const newParentPos = latestPositions[parentId];
    if (!newParentPos) {
      return;
    }

    const parentNode = view.visibleNodeMap.get(parentId);
    const isRootTechnique =
      parentNode && String(parentNode.type || "").toLowerCase() === "technique";

    view.basePositions.set(parentId, { x: newParentPos.x, y: newParentPos.y });
    positionsToUpdate[parentId] = { x: newParentPos.x, y: newParentPos.y };

    const directChildren = children.get(parentId) || [];
    if (directChildren.length === 0) {
      return;
    }

    const visibleDirectChildren = directChildren.filter((nodeId) => view.nodeDataSet.get(nodeId));
    if (!visibleDirectChildren.length) {
      return;
    }

    if (isRootTechnique) {
      const deltaX = newParentPos.x - oldParentPos.x;
      const deltaY = newParentPos.y - oldParentPos.y;

      visibleDirectChildren.forEach((childId) => {
        const oldChildPos = view.basePositions.get(childId) || { x: 0, y: 0 };
        const newChildX = oldChildPos.x + deltaX;
        const newChildY = oldChildPos.y + deltaY;

        view.basePositions.set(childId, { x: newChildX, y: newChildY });
        positionsToUpdate[childId] = { x: newChildX, y: newChildY };

        const descendants = internals.getAllDescendants(childId, children);
        descendants.forEach((descendantId) => {
          const oldDescPos = view.basePositions.get(descendantId) || { x: 0, y: 0 };
          view.basePositions.set(descendantId, {
            x: oldDescPos.x + deltaX,
            y: oldDescPos.y + deltaY,
          });
          positionsToUpdate[descendantId] = {
            x: oldDescPos.x + deltaX,
            y: oldDescPos.y + deltaY,
          };
        });
      });
      return;
    }

    const childCount = visibleDirectChildren.length;
    const baseMinRadius = 100;
    const baseMaxRadius = 240;
    const expansionThreshold = 30;
    const minRadius =
      childCount > expansionThreshold
        ? baseMinRadius + (childCount - expansionThreshold) * 2
        : baseMinRadius;
    const maxRadius =
      childCount > expansionThreshold
        ? baseMaxRadius + (childCount - expansionThreshold) * 3
        : baseMaxRadius;
    const angleStep = (2 * Math.PI) / visibleDirectChildren.length;

    visibleDirectChildren.forEach((childId, index) => {
      const oldChildPos = view.basePositions.get(childId) || { x: 0, y: 0 };
      const angle = index * angleStep;
      const randomRadius = minRadius + Math.random() * (maxRadius - minRadius);

      const newChildX = newParentPos.x + randomRadius * Math.cos(angle);
      const newChildY = newParentPos.y + randomRadius * Math.sin(angle);
      const deltaX = newChildX - oldChildPos.x;
      const deltaY = newChildY - oldChildPos.y;

      view.basePositions.set(childId, { x: newChildX, y: newChildY });
      positionsToUpdate[childId] = { x: newChildX, y: newChildY };

      const descendants = internals.getAllDescendants(childId, children);
      descendants.forEach((descendantId) => {
        const oldDescPos = view.basePositions.get(descendantId) || { x: 0, y: 0 };
        view.basePositions.set(descendantId, {
          x: oldDescPos.x + deltaX,
          y: oldDescPos.y + deltaY,
        });
        positionsToUpdate[descendantId] = {
          x: oldDescPos.x + deltaX,
          y: oldDescPos.y + deltaY,
        };
      });
    });
  });

  const nodesToUpdate = Object.entries(positionsToUpdate).map(([id, pos]) => ({
    id,
    x: pos.x,
    y: pos.y,
  }));

  if (nodesToUpdate.length > 0) {
    view.nodeDataSet.update(nodesToUpdate);
  }
}

internals.drag = {
  applyDragEnd,
};
})();
