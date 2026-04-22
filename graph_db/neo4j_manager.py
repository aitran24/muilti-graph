from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

from class_define.graph_definition import get_known_graph_labels, resolve_graph_entity_type
from class_define.object_definition import (
    BaseEntity,
    FileEntity,
    NetworkEntity,
    ProcessEntity,
    RegistryEntity,
    UserEntity,
    WmiEntity,
)
from globals.logger_manager import LoggerManager

try:
    from neo4j import GraphDatabase
except ImportError as exc:
    GraphDatabase = None
    _neo4j_import_error = exc
else:
    _neo4j_import_error = None

if TYPE_CHECKING:
    from triplet_creator.triplet_creator import Triplet


logger = LoggerManager.get_logger(__name__)


class Neo4jGraphManager:
    DEFAULT_ADD_TRIPLET_QUERY_TEMPLATE = """
    MERGE (s:{subject_label} {{id: $subject_id}})
    SET s += $subject_props

    MERGE (o:{object_label} {{id: $object_id}})
    SET o += $object_props

    CREATE (s)-[r:{relation_type}]->(o)
    SET r.event_id = $event_id,
        r.action = $action,
        r.timestamp = $timestamp

    RETURN s.id AS subject_id,
           type(r) AS relation,
           o.id AS object_id,
           r.event_id AS event_id
    """

    DEFAULT_ATTACH_ROOTS_TO_TECHNIQUE_QUERY = """
    MERGE (t:Technique {id: $technique_id})
    SET t.name = $technique_name,
        t.display_name = $technique_name,
        t.type = "Technique",
        t.entity_class = "Technique"

    WITH t
    UNWIND $root_ids AS root_id
    MATCH (n {id: root_id})
    WHERE NOT n:Technique
    MERGE (t)-[:HAS_ROOT]->(n)
    RETURN count(n) AS attached_count
    """

    DEFAULT_GET_TRIPLETS_QUERY = """
        MATCH (s)-[r]->(o)
    RETURN s.id AS subject_id,
           s.type AS subject_type,
            labels(s) AS subject_labels,
           type(r) AS relation,
           r.action AS action,
           r.event_id AS event_id,
           r.timestamp AS timestamp,
           o.id AS object_id,
            o.type AS object_type,
            labels(o) AS object_labels
    ORDER BY r.timestamp DESC
    LIMIT $limit
    """

    _SAFE_CYPHER_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def __init__(
        self,
        uri: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "neo4j",
    ) -> None:
        self._ensure_driver_available()

        auth = (username, password) if username is not None and password is not None else None
        self._driver = GraphDatabase.driver(uri, auth=auth)
        self._database = database

    def close(self) -> None:
        self._driver.close()

    def __enter__(self) -> "Neo4jGraphManager":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def add_triplet(
        self,
        triplet: "Triplet",
        query_template: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not triplet or not triplet.subject or not triplet.object:
            raise ValueError("Triplet must include both subject and object entities.")

        subject_payload = self._build_entity_payload(triplet.subject)
        object_payload = self._build_entity_payload(triplet.object)

        query = (query_template or self.DEFAULT_ADD_TRIPLET_QUERY_TEMPLATE).format(
            subject_label=self._sanitize_cypher_token(subject_payload["label"], "UnknownEntity"),
            object_label=self._sanitize_cypher_token(object_payload["label"], "UnknownEntity"),
            relation_type=self._sanitize_cypher_token(triplet.action, "RELATED_TO"),
        )

        params = {
            "subject_id": subject_payload["id"],
            "subject_props": subject_payload["properties"],
            "object_id": object_payload["id"],
            "object_props": object_payload["properties"],
            "event_id": str(triplet.event_id or ""),
            "action": str(triplet.action or ""),
            "timestamp": triplet.timestamp or datetime.now(timezone.utc).isoformat(),
        }

        with self._driver.session(database=self._database) as session:
            record = session.execute_write(self._run_single, query, params)

        return dict(record) if record else {}

    def attach_roots_to_technique(self, technique_name: str, root_node_ids: list[str]) -> int:
        safe_technique_name = (technique_name or "technique").strip() or "technique"
        technique_token = self._sanitize_cypher_token(safe_technique_name, "technique")
        technique_id = f"Technique:{technique_token}"

        # Keep root list stable and unique while preserving order.
        deduped_root_ids = list(dict.fromkeys(node_id for node_id in root_node_ids if node_id))

        with self._driver.session(database=self._database) as session:
            if not deduped_root_ids:
                session.execute_write(
                    self._run_single,
                    """
                    MERGE (t:Technique {id: $technique_id})
                    SET t.name = $technique_name,
                        t.display_name = $technique_name,
                        t.type = \"Technique\",
                        t.entity_class = \"Technique\"
                    RETURN t.id AS technique_id
                    """,
                    {
                        "technique_id": technique_id,
                        "technique_name": safe_technique_name,
                    },
                )
                return 0

            result = session.execute_write(
                self._run_single,
                self.DEFAULT_ATTACH_ROOTS_TO_TECHNIQUE_QUERY,
                {
                    "technique_id": technique_id,
                    "technique_name": safe_technique_name,
                    "root_ids": deduped_root_ids,
                },
            )

        return int(result.get("attached_count", 0)) if result else 0

    def is_insert_success(self, result: Dict[str, Any], triplet: "Triplet") -> bool:
        if not result or not triplet or not triplet.subject or not triplet.object:
            return False

        return (
            result.get("subject_id") == triplet.subject.get_id()
            and result.get("object_id") == triplet.object.get_id()
            and str(result.get("event_id", "")) == str(triplet.event_id or "")
        )

    def get_triplets(
        self,
        limit: int = 100,
        query: Optional[str] = None,
    ) -> list[Dict[str, Any]]:
        safe_limit = max(1, int(limit))
        run_query = query or self.DEFAULT_GET_TRIPLETS_QUERY

        with self._driver.session(database=self._database) as session:
            return session.execute_read(self._run_all, run_query, {"limit": safe_limit})

    def get_graph_stats(self) -> Dict[str, int]:
        node_count_query = """
        MATCH (n)
        RETURN count(n) AS node_count
        """
        relationship_count_query = """
        MATCH ()-[r]->()
        RETURN count(r) AS relationship_count
        """

        with self._driver.session(database=self._database) as session:
            node_record = session.execute_read(self._run_single, node_count_query, {})
            relationship_record = session.execute_read(
                self._run_single,
                relationship_count_query,
                {},
            )

        return {
            "node_count": int(node_record.get("node_count", 0)) if node_record else 0,
            "relationship_count": int(relationship_record.get("relationship_count", 0))
            if relationship_record
            else 0,
        }

    def get_relationship_samples(self, limit: int = 5) -> list[Dict[str, Any]]:
        safe_limit = max(1, int(limit))
        query = """
        MATCH (s)-[r]->(o)
        RETURN s.id AS subject_id,
               labels(s) AS subject_labels,
               type(r) AS relation,
               r.event_id AS event_id,
               o.id AS object_id,
               labels(o) AS object_labels
        LIMIT $limit
        """

        with self._driver.session(database=self._database) as session:
            return session.execute_read(self._run_all, query, {"limit": safe_limit})

    def migrate_legacy_entity_labels(self) -> Dict[str, int]:
        relabel_count = 0
        with self._driver.session(database=self._database) as session:
            for label in get_known_graph_labels():
                relabel_query = f"""
                MATCH (n:Entity)
                WHERE n.type = $node_type
                SET n:{label}
                RETURN count(n) AS count
                """
                result = session.execute_write(
                    self._run_single,
                    relabel_query,
                    {"node_type": label},
                )
                relabel_count += int(result.get("count", 0)) if result else 0

            remove_query = """
            MATCH (n:Entity)
            REMOVE n:Entity
            RETURN count(n) AS count
            """
            remove_result = session.execute_write(self._run_single, remove_query, {})
            removed_count = int(remove_result.get("count", 0)) if remove_result else 0

        return {
            "relabel_count": relabel_count,
            "removed_entity_label_count": removed_count,
        }

    def get_label_distribution(self) -> list[Dict[str, Any]]:
        query = """
        MATCH (n)
        RETURN labels(n) AS labels, count(*) AS count
        ORDER BY count DESC
        """
        with self._driver.session(database=self._database) as session:
            return session.execute_read(self._run_all, query, {})

    @staticmethod
    def _run_single(tx: Any, query: str, params: Dict[str, Any]) -> Any:
        return tx.run(query, params).single()

    @staticmethod
    def _run_all(tx: Any, query: str, params: Dict[str, Any]) -> list[Dict[str, Any]]:
        result = tx.run(query, params)
        return [dict(row) for row in result]

    @classmethod
    def _build_entity_payload(cls, entity: BaseEntity) -> Dict[str, Any]:
        entity_id = entity.get_id()
        graph_type = resolve_graph_entity_type(entity)

        properties = cls._extract_entity_properties(entity)
        properties["id"] = entity_id
        properties["type"] = graph_type.value
        properties["entity_class"] = entity.__class__.__name__
        display_name = cls._build_display_name(entity, entity_id)
        properties["display_name"] = display_name
        properties["name"] = display_name

        return {
            "id": entity_id,
            "label": graph_type.value,
            "properties": properties,
        }

    @classmethod
    def _extract_entity_properties(cls, entity: BaseEntity) -> Dict[str, Any]:
        properties: Dict[str, Any] = {}

        for key, value in vars(entity).items():
            if key.startswith("_"):
                continue

            if isinstance(value, BaseEntity):
                properties[f"{key}_id"] = value.get_id()
                continue

            if cls._is_primitive(value):
                properties[key] = value
                continue

            if isinstance(value, (list, tuple, set)):
                serialized_list = []
                for item in value:
                    if isinstance(item, BaseEntity):
                        serialized_list.append(item.get_id())
                    elif cls._is_primitive(item):
                        serialized_list.append(item)
                if serialized_list:
                    properties[key] = serialized_list

        return properties

    @classmethod
    def _build_display_name(cls, entity: BaseEntity, entity_id: str) -> str:
        if isinstance(entity, NetworkEntity):
            return cls._first_non_empty(entity.destination_ip, entity.domain_name, entity_id)

        if isinstance(entity, ProcessEntity):
            image_name = Path(entity.image_path).name if entity.image_path else ""
            return cls._first_non_empty(entity.process_name, image_name, entity_id)

        if isinstance(entity, FileEntity):
            file_name = Path(entity.file_path).name if entity.file_path else ""
            return cls._first_non_empty(file_name, entity.file_path, entity_id)

        if isinstance(entity, RegistryEntity):
            return cls._first_non_empty(entity.value_name, entity.key_path, entity_id)

        if isinstance(entity, UserEntity):
            return cls._first_non_empty(entity.username, entity.sid, entity_id)

        if isinstance(entity, WmiEntity):
            return cls._first_non_empty(
                getattr(entity, "wmi_name", ""),
                getattr(entity, "wmi_filter_path", ""),
                entity_id,
            )

        return entity_id

    @staticmethod
    def _first_non_empty(*values: Any) -> str:
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return ""

    @classmethod
    def _sanitize_cypher_token(cls, value: str, fallback: str) -> str:
        if not value:
            return fallback

        token = re.sub(r"[^A-Za-z0-9_]", "_", str(value).strip())
        if token and token[0].isdigit():
            token = f"N_{token}"

        if cls._SAFE_CYPHER_TOKEN.match(token):
            return token

        return fallback

    @staticmethod
    def _is_primitive(value: Any) -> bool:
        return value is None or isinstance(value, (str, int, float, bool))

    @staticmethod
    def _ensure_driver_available() -> None:
        if GraphDatabase is None:
            raise ImportError(
                "neo4j package is required. Install it with: pip install neo4j"
            ) from _neo4j_import_error
