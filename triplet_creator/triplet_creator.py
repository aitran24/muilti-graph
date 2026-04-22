from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, TYPE_CHECKING, Union

from class_define.object_definition import *
from globals.global_object import SYSMON_BEHAVIOR_MAP

if TYPE_CHECKING:
    from graph_db.neo4j_manager import Neo4jGraphManager


@dataclass
class Triplet:
    timestamp: str = ""
    action: str = ""
    subject: Optional[Union[ProcessEntity, UserEntity]] = None
    object: Optional[Any] = None
    event_id: str = ""


class SysmonTripletCreator: 
    def __init__(self, graph_manager: Optional["Neo4jGraphManager"] = None):
        self.graph_manager = graph_manager

    def create_triplet(self, entity: BaseEntity) -> Optional[Triplet]:
        triplet = Triplet()

        if not entity:
            return None
        
        event_id = str(entity.event_id)
        relation = SYSMON_BEHAVIOR_MAP.get(event_id, "UnknownBehavior")

        triplet.subject = getattr(entity, "parent_process", None)

        if not triplet.subject:
            return None

        triplet.object = entity
        triplet.action = relation
        triplet.event_id = event_id
        triplet.timestamp = datetime.now(timezone.utc).isoformat()

        return triplet

    def store_triplet(self, triplet: Triplet) -> bool:
        if not triplet:
            return False

        if not self.graph_manager:
            return True

        insert_result = self.graph_manager.add_triplet(triplet)
        return self.graph_manager.is_insert_success(insert_result, triplet)

    def create_and_store_triplet(self, entity: BaseEntity) -> Optional[Triplet]:
        triplet = self.create_triplet(entity)
        if not triplet:
            return None

        if not self.store_triplet(triplet):
            return None

        return triplet

        
        

