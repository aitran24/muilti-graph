from dataclasses import dataclass
import json
from .format_parser import *
from typing import List, Dict, Optional, Tuple
from abc import ABC, abstractmethod
from class_define.object_definition import *
from class_define.data_normalizer import DataNormalizer
import globals.global_object as globals
from globals.logger_manager import LoggerManager
from entity_filter.merge_entity  import *


logger = LoggerManager.get_logger(__name__)
g_whitelist = json.load(open("analyzing/global_whitelist.json", "r"))


class Parser(ABC):
    def __init__(self):
        self.xml_format_parser = XMLParser() 
        self.plaintext_format_parser = PlainTextParser() 
        self.normalizer = DataNormalizer()
        self.entity_merger = EntityMerger()

    def parse_from_file(self, file_path: str) -> List[Dict]:
        parsed_logs = []
        parsed_logs = self.xml_format_parser.parse_from_file(file_path) 
        # logger.info(f"[Parser] XML parsing completed | file: {file_path} | logs_parsed: {len(parsed_logs)}")
        if parsed_logs is None:
            parsed_logs = self.plaintext_format_parser.parse_from_file(file_path) 

        return parsed_logs
    
    def parse_from_rawlog(self, raw_log: str) -> List[Dict]:
        parsed_logs = []
        parsed_logs = self.xml_format_parser.parse_raw_log(raw_log) 
        if parsed_logs is None:
            parsed_logs = self.plaintext_format_parser.parse_raw_log(raw_log) 

        return parsed_logs

class SysmonLogParser(Parser):
    def __init__(self):
        super().__init__()
        pass 

    @staticmethod
    def _pick(data: Dict, *keys: str) -> str:
        for key in keys:
            value = data.get(key)
            if value is not None and value != "":
                return str(value)
        return ""

    @staticmethod
    def _split_registry_target(target_object: str) -> Tuple[str, str]:
        if not target_object:
            return "", ""

        if "\\" not in target_object:
            return target_object, ""

        key_path, value_name = target_object.rsplit("\\", 1)
        return key_path, value_name

    def _resolve_user(self, log_entry: Dict, event_data: Dict) -> Optional[UserEntity]:
        sid = ((log_entry.get("System") or {}).get("Security") or {}).get("UserID", "")
        sid = sid.strip() if sid else ""
        existing = globals.get_user(f"User:{sid}") if sid else None
        if existing:
            return existing

        user_text = self._pick(event_data, "User", "SourceUser", "TargetUser")
        if not user_text and not sid:
            return None

        user = UserEntity()
        user.sid = sid

        if "\\" in user_text:
            user.domain, user.username = user_text.split("\\", 1)
        else:
            user.username = user_text

        globals.add_user(user)
        return user

    def map_entity(self, log_entry: Dict) -> Optional[BaseEntity]:
        try:
            eventID = log_entry.get("EventCode")
            if not eventID:
                return None

            event_data = log_entry.get("EventData") or {}

            match str(eventID):
                case "1" | "8" | "10":
                    try: 
                        entity = ProcessEntity()
                        entity.event_id = str(eventID)
                        entity.guid = self._pick(event_data, "ProcessGuid", "TargetProcessGUID")
                        entity.pid = self._pick(event_data, "ProcessId", "TargetProcessId")
                        entity.image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "Image", "TargetImage"))
                        entity.process_name = (self._pick(event_data, "Description") or Path(entity.image_path).name).lower()
                        for whitelist_entry in g_whitelist.get("ignore_processes", []):
                            if whitelist_entry in entity.image_path:
                                # logger.info(f"[ProcessCreation] Whitelisted process skipped | image_path: {entity.image_path}")
                                return None
                        entity.command_line = self.normalizer.normalize(['command_line', 'file_path'], self._pick(event_data, "CommandLine"))
                        if self._pick(event_data, "NewThreadId"):
                            entity.command_line += f" [NewThreadId: {self._pick(event_data, 'NewThreadId')}]"
                        if self._pick(event_data, "StartAddress"):
                            entity.command_line += f" [StartAddress: {self._pick(event_data, 'StartAddress')}]" 
                        if self._pick(event_data, "StartFunction"):
                            entity.command_line += f" [StartFunction: {self._pick(event_data, 'StartFunction')}]"
                        if self._pick(event_data, "GrantedAccess"):
                            entity.command_line = f"GrantedAccess with bitmask: {self._pick(event_data, 'GrantedAccess')} for " + entity.process_name
                        entity.original_file_name = self.normalizer.normalize(['file_path'], self._pick(event_data, "OriginalFileName"))
                        entity.image_hash = self._pick(event_data, "Hashes")
                        parent_guid = self._pick(event_data, "ParentProcessGuid", "SourceProcessGuid")
                        entity.parent_process = globals.get_process(parent_guid.strip()) or None
                        if not entity.parent_process:
                            stub_process = ProcessEntity() 
                            stub_process.guid = parent_guid.strip()
                            stub_process.pid = self._pick(event_data, "ParentProcessId", "SourceProcessId")
                            stub_process.image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "ParentImage"))
                            for whitelist_entry in g_whitelist.get("ignore_processes", []):
                                if whitelist_entry in stub_process.image_path:
                                    # logger.info(f"[ProcessCreation] Whitelisted process skipped | image_path: {entity.image_path}")
                                    return None
                            stub_process.command_line = self.normalizer.normalize(['command_line', 'file_path'], self._pick(event_data, "ParentCommandLine"))
                            stub_process.event_id = "1"
                            entity.parent_process = stub_process

                            globals.add_process(stub_process)

                        entity.user = self._resolve_user(log_entry, event_data)
                        entity.command_hash = self.normalizer.normalize(['hash_command'], entity.command_line)

                        if entity.get_id():
                            existing_entity = globals.get_process(entity.get_id())
                            if not existing_entity and entity.command_hash:
                                existing_entity = globals.get_process_by_command_hash(entity.command_hash)
                            if existing_entity:
                                merged_entity = self.entity_merger.merge_and_update(existing_entity, entity)
                                if not isinstance(merged_entity, tuple):
                                    entity = merged_entity 
                                    globals.update_process(entity.get_id(), entity)
                                    return None 
                                else:
                                    ent1, ent2 = merged_entity
                                    logger.warning(f"Conflict, ent_current.get_id(): {ent2.get_id()} | ent_exist.get_id(): {ent1.get_id()} | image_path: {entity.image_path} | command_line: {entity.command_line}")
                                    globals.add_process(entity)
                                    # logger.warning(f"[ProcessCreation] Conflict detected when merging process entity | guid: {entity.guid} | image_path: {entity.image_path} | command_line: {entity.command_line}")
                            else:
                                globals.add_process(entity)
                        else: 
                            logger.warning(f"[ProcessCreation] Missing GUID for process event | image_path: {entity.image_path} | command_line: {entity.command_line}")
                            return None 
                        if entity.parent_process:
                            logger.info(f"[ProcessCreation] parent_guid: {entity.parent_process.guid} | child_guid: {entity.guid} | child_image: {entity.image_path}")
                        
                        return entity
                    
                    except Exception as e:
                        logger.error(f"[Error][ProcessCreation] {e}")
                        return None

                case "2" | "11" | "15" | "17" | "18" | "23" | "26" | "29":
                    try:
                        entity = FileEntity()
                        entity.event_id = str(eventID)
                        entity.file_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "TargetFilename", "PipeName"))
                        entity.source_image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "Image"))
                        parent_process_guid = self._pick(event_data, "ProcessGuid")
                        entity.parent_process = globals.get_process_from_guid(parent_process_guid.strip()) if parent_process_guid else None
                        entity.content_hash = self._pick(event_data, "Hash", "Hashes")

                        if str(eventID) == "11":
                            existing_entity = globals.get_file_by_path_ext(entity)
                            if existing_entity:
                                old_id = existing_entity.get_id()
                                merged_entity = self.entity_merger.merge_and_update(existing_entity, entity)
                                if not isinstance(merged_entity, tuple):
                                    entity = merged_entity
                                    globals.update_file(old_id, entity)
                                    return None
                            globals.add_file(entity)
                        else:
                            if entity.get_id():
                                existing_entity = globals.get_file(entity.get_id())
                                if existing_entity:
                                    merged_entity = self.entity_merger.merge_and_update(existing_entity, entity)
                                    if not isinstance(merged_entity, tuple):
                                        entity = merged_entity 
                                        globals.update_file(entity.get_id(), entity)
                                        return None 
                                    else:
                                        logger.warning(f"[FileEvent] Conflict, existing id: {existing_entity.get_id()} | new id: {entity.get_id()} | file_path: {entity.file_path} | source_image: {entity.source_image_path}")
                                else:
                                    globals.add_file(entity)
                            else:
                                logger.warning(f"[FileEvent] Missing file identifier for file event | source_image: {entity.source_image_path} | target_file: {entity.file_path}")
                                return None

                        if entity.parent_process:
                            logger.info(f"[FileEvent] parent_process_guid: {entity.parent_process.guid} | source_image: {entity.source_image_path} | target_file: {entity.file_path}")

                        return entity
                    except Exception as e:
                        logger.error(f"[Error][FileEvent] {e}")
                        return None

                case "3" | "22":
                    try: 
                        entity = NetworkEntity()
                        entity.event_id = str(eventID)
                        if self._pick(event_data, "QueryName"):
                            entity.domain_name = self.normalizer.normalize(['domain'], self._pick(event_data, "QueryName"))
                        entity.destination_ip = self.normalizer.normalize(['ip'], self._pick(event_data, "DestinationIp", "QueryResults"))
                        entity.destination_port = self._pick(event_data, "DestinationPort")
                        raw_protocol = self._pick(event_data, "Protocol").lower()
                        if raw_protocol == "6":
                            entity.protocol = "tcp"
                        elif raw_protocol == "17":
                            entity.protocol = "udp"
                        else:
                            entity.protocol = raw_protocol or "tcp"
                        entity.domain_name = self.normalizer.normalize(['domain'], entity.domain_name or self._pick(event_data, "DestinationHostname"))
                        entity.source_image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "Image"))
                        parent_process_guid = self._pick(event_data, "ProcessGuid")
                        entity.parent_process = globals.get_process_from_guid(parent_process_guid.strip()) if parent_process_guid else None

                        if entity.get_id():
                            existing_entity = globals.get_network(entity.get_id())
                            if existing_entity:
                                merged_entity = self.entity_merger.merge_and_update(existing_entity, entity)
                                if not isinstance(merged_entity, tuple):
                                    entity = merged_entity 
                                    globals.update_network(entity.get_id(), entity)
                                    return None 
                                else:
                                    logger.warning(f"[NetworkConnection] Conflict detected when merging network entity | source_image: {entity.source_image_path} | destination_ip: {entity.destination_ip} | destination_port: {entity.destination_port}")
                            else:
                                globals.add_network(entity) 
                        else:
                            logger.warning(f"[NetworkConnection] Missing network identifier for network event | source_image: {entity.source_image_path} | destination_ip: {entity.destination_ip} | destination_port: {entity.destination_port}")
                            return None

                        if entity.parent_process:
                            logger.info(f"[NetworkConnection] parent_process_guid: {entity.parent_process.guid} | source_image: {entity.source_image_path} | protocol: {entity.protocol.upper()} | destination: {entity.destination_ip}:{entity.destination_port}")
                        
                        return entity
                    except Exception as e:
                        logger.error(f"[Error][NetworkConnection] {e}")
                        return None

                case "6" | "7" | "9":
                    try: 
                        entity = FileEntity()
                        entity.event_id = str(eventID)
                        file_target = self._pick(event_data, "ImageLoaded", "Device")
                        entity.file_path = self.normalizer.normalize(['file_path'], file_target)
                        entity.content_hash = self._pick(event_data, "Hashes")
                        entity.source_image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "Image"))
                        parent_process_guid = self._pick(event_data, "ProcessGuid")
                        entity.parent_process = globals.get_process_from_guid(parent_process_guid.strip()) if parent_process_guid else None

                        if entity.get_id():
                            existing_entity = globals.get_file(entity.get_id())
                            if existing_entity:
                                merged_entity = self.entity_merger.merge_and_update(existing_entity, entity)
                                if not isinstance(merged_entity, tuple):
                                    entity = merged_entity 
                                    globals.update_file(entity.get_id(), entity)
                                    return None 
                                else:
                                    logger.warning(f"[FileLoad] Conflict, existing id: {existing_entity.get_id()} | new id: {entity.get_id()} | file_path: {entity.file_path} | source_image: {entity.source_image_path}")
                            else:
                                # logger.warning(f"[FileLoad] Conflict detected when merging file entity | file_path: {entity.file_path} | source_image: {entity.source_image_path}") 
                                globals.add_file(entity)
                        else:
                            logger.warning(f"[FileLoad] Missing file identifier for file load event | source_image: {entity.source_image_path} | loaded_file: {entity.file_path}")
                            return None

                        if entity.parent_process:
                            logger.info(f"[FileLoad] parent_process_guid: {entity.parent_process.guid} | source_image: {entity.source_image_path} | loaded_file: {entity.file_path}")

                        return entity 
                    except Exception as e:
                        logger.error(f"[Error][FileLoad] {e}")
                        return None

                case "12" | "13" | "14":
                    try:
                        entity = RegistryEntity()
                        entity.event_id = str(eventID)
                        target_object = self._pick(event_data, "TargetObject")
                        key_path, value_name = self._split_registry_target(target_object)
                        entity.key_path = self.normalizer.normalize(['registry'], key_path)
                        entity.value_name = value_name
                        entity.value_data = self._pick(event_data, "Details", "NewName", "EventType")
                        parent_process_guid = self._pick(event_data, "ProcessGuid")
                        entity.parent_process = globals.get_process_from_guid(parent_process_guid.strip()) if parent_process_guid else None
                        entity.source_image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "Image"))

                        if entity.get_id():
                            existing_entity = globals.get_registry(entity.get_id())
                            if existing_entity:
                                merged_entity = self.entity_merger.merge_and_update(existing_entity, entity)
                                if not isinstance(merged_entity, tuple):
                                    entity = merged_entity 
                                    globals.update_registry(entity.get_id(), entity)
                                    return None 
                            else:
                                globals.add_registry(entity)
                        else:
                            logger.warning(f"[RegistryEvent] Missing registry identifier for registry event | source_image: {entity.source_image_path} | key_path: {entity.key_path} | value_name: {entity.value_name}")
                            return None

                        if entity.parent_process:
                            logger.info(f"[RegistryEvent] parent_process_guid: {entity.parent_process.guid} | source_image: {entity.source_image_path} | key: {entity.key_path} | value: {entity.value_name}")
                            
                        return entity 
                    except Exception as e:
                        logger.error(f"[Error][RegistryEvent] {e}")
                        return None
                    
                case "19" | "20" | "21":
                    try:
                        entity = WmiEntity()
                        entity.event_id = str(eventID)
                        entity.wmi_name = self._pick(event_data, "Name")
                        entity.wmi_namespace = self._pick(event_data, "EventNamespace")
                        entity.wmi_query = self._pick(event_data, "Query")
                        entity.wmi_payload = self._pick(event_data, "Destination")
                        entity.wmi_filter_path = self._pick(event_data, "Filter")
                        entity.wmi_consumer_path = self._pick(event_data, "Consumer")

                        if entity.get_id():
                            existing_entity = globals.get_wmi(entity.get_id())
                            if existing_entity:
                                merged_entity = self.entity_merger.merge_and_update(existing_entity, entity)
                                if not isinstance(merged_entity, tuple):
                                    entity = merged_entity 
                                    globals.update_wmi(entity.get_id(), entity)
                                    return None 
                                else:
                                    logger.warning(f"[WMIEvent] Conflict detected when merging WMI entity | name: {entity.wmi_name} | namespace: {entity.wmi_namespace} | query: {entity.wmi_query}")
                            else:
                                globals.add_wmi(entity)
                            
                        else:
                            logger.warning(f"[WMIEvent] Missing WMI identifier for WMI event | name: {entity.wmi_name} | namespace: {entity.wmi_namespace} | query: {entity.wmi_query}")
                            return None

                        logger.info(f"[WMIEvent] namespace: {entity.wmi_namespace} | name: {entity.wmi_name} | query: {entity.wmi_query} | payload: {entity.wmi_payload}")

                        return entity
                    except Exception as e:
                        logger.error(f"[Error][WMIEvent] {e}")
                        return None

                case _:
                    return None

        except:
            return None
    
    def _get_or_create_process(self, process_guid: str, image_path: str = "") -> Optional[ProcessEntity]:
        if not process_guid:
            return None
        
        guid = process_guid.strip()
        existing_process = globals.get_process(guid)

        if existing_process:
            return existing_process

class ETWBasedLogParser(Parser):
    def __init__(self):
        super().__init__()
        self.xml_format_parser = XMLParser() 
        self.plaintext_format_parser = PlainTextParser() 
        pass 