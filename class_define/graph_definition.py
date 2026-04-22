from __future__ import annotations

from enum import Enum

from class_define.object_definition import (
    BaseEntity,
    FileEntity,
    NetworkEntity,
    ProcessEntity,
    RegistryEntity,
    UserEntity,
    WmiEntity,
)


class GraphEntityType(str, Enum):
    PROCESS = "Process"
    USER = "User"
    FILE = "File"
    REGISTRY = "Registry"
    NETWORK = "Network"
    WMI = "Wmi"
    UNKNOWN = "UnknownEntity"


_ENTITY_CLASS_TO_GRAPH_TYPE = {
    ProcessEntity: GraphEntityType.PROCESS,
    UserEntity: GraphEntityType.USER,
    FileEntity: GraphEntityType.FILE,
    RegistryEntity: GraphEntityType.REGISTRY,
    NetworkEntity: GraphEntityType.NETWORK,
    WmiEntity: GraphEntityType.WMI,
}


def resolve_graph_entity_type(entity: BaseEntity) -> GraphEntityType:
    for entity_class, graph_type in _ENTITY_CLASS_TO_GRAPH_TYPE.items():
        if isinstance(entity, entity_class):
            return graph_type
    return GraphEntityType.UNKNOWN


def get_known_graph_labels() -> list[str]:
    return [
        GraphEntityType.PROCESS.value,
        GraphEntityType.USER.value,
        GraphEntityType.FILE.value,
        GraphEntityType.REGISTRY.value,
        GraphEntityType.NETWORK.value,
        GraphEntityType.WMI.value,
        GraphEntityType.UNKNOWN.value,
    ]
