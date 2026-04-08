from dataclasses import dataclass
from .format_parser import *
from typing import List, Dict, Optional, Tuple
from abc import ABC, abstractmethod
from class_define.object_definition import *
from class_define.data_normalizer import DataNormalizer
import globals.global_object as globals


class Parser(ABC):
    def __init__(self):
        self.xml_format_parser = XMLParser() 
        self.plaintext_format_parser = PlainTextParser() 
        self.normalizer = DataNormalizer()

    def parse_from_file(self, file_path: str) -> List[Dict]:
        parsed_logs = []
        parsed_logs = self.xml_format_parser.parse_from_file(file_path) 
        print(f"[Parser] XML parsing completed | file: {file_path} | logs_parsed: {len(parsed_logs)}")
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
                case "1":
                    try: 
                        entity = ProcessEntity()
                        entity.event_id = str(eventID)
                        entity.guid = self._pick(event_data, "ProcessGuid")
                        entity.pid = self._pick(event_data, "ProcessId")
                        entity.image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "Image"))
                        entity.command_line = self.normalizer.normalize(['command_line', 'file_path'], self._pick(event_data, "CommandLine"))
                        entity.original_file_name = self.normalizer.normalize(['file_path'], self._pick(event_data, "OriginalFileName"))
                        entity.image_hash = self._pick(event_data, "Hashes")
                        parent_guid = self._pick(event_data, "ParentProcessGuid")
                        entity.parent_process = globals.get_process(parent_guid.strip()) or None
                        entity.user = self._resolve_user(log_entry, event_data)
                        entity.command_hash = self.normalizer.normalize(['hash_command'], entity.command_line)
                        entity.process_name = (self._pick(event_data, "Description") or Path(entity.image_path).name).lower()

                        if entity.guid:
                            globals.add_process(entity)

                        if entity.parent_process:
                            print(f"[ProcessCreation] parent_guid: {entity.parent_process.guid} | child_guid: {entity.guid} | child_image: {entity.image_path}")
                        # else:
                        #     print(f"[ProcessCreation] child_guid: {entity.guid} | child_image: {entity.image_path}")
                    except Exception as e:
                        print(f"[Error][ProcessCreation] {e}")

                    return entity

                case "2" | "11" | "15" | "17" | "18" | "23" | "26", "29":
                    try:
                        entity = FileEntity()
                        entity.event_id = str(eventID)
                        entity.file_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "TargetFilename", "PipeName"))
                        entity.source_image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "Image"))
                        parent_process_guid = self._pick(event_data, "ProcessGuid")
                        entity.parent_process = globals.get_process(parent_process_guid.strip()) if parent_process_guid else None
                        entity.content_hash = self._pick(event_data, "Hash", "Hashes")

                        if entity.file_path:
                            globals.add_file(entity)

                        if entity.parent_process:
                            print(f"[FileEvent] parent_process_guid: {entity.parent_process.guid} | source_image: {entity.source_image_path} | target_file: {entity.file_path}")
                        # else:
                        #     print(f"[FileEvent] target_file: {entity.file_path}")
                    except Exception as e:
                        print(f"[Error][FileEvent] {e}")

                    return entity 

                case "3" | "22":
                    try: 
                        entity = NetworkEntity()
                        entity.event_id = str(eventID)
                        entity.destination_ip = self.normalizer.normalize(['ip'], self._pick(event_data, "DestinationIp", "QueryResults"))
                        if self._pick(event_data, "QueryName"):
                            entity.destination_ip += ":" + self._pick(event_data, "QueryName")
                        entity.destination_port = self._pick(event_data, "DestinationPort")
                        raw_protocol = self._pick(event_data, "Protocol").lower()
                        if raw_protocol == "6":
                            entity.protocol = "tcp"
                        elif raw_protocol == "17":
                            entity.protocol = "udp"
                        else:
                            entity.protocol = raw_protocol or "tcp"
                        entity.domain_name = self.normalizer.normalize(['domain'], self._pick(event_data, "DestinationHostname"))
                        entity.source_image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "Image"))
                        parent_process_guid = self._pick(event_data, "ProcessGuid")
                        entity.parent_process = globals.get_process(parent_process_guid.strip()) if parent_process_guid else None

                        if entity.source_image_path:
                            globals.add_network(entity)

                        if entity.parent_process:
                            print(f"[NetworkConnection] parent_process_guid: {entity.parent_process.guid} | source_image: {entity.source_image_path} | protocol: {entity.protocol.upper()} | destination: {entity.destination_ip}:{entity.destination_port}")
                        # else:
                        #     print(f"[NetworkConnection] protocol: {entity.protocol.upper()} | destination: {entity.destination_ip}:{entity.destination_port}")
                    except Exception as e:
                        print(f"[Error][NetworkConnection] {e}")

                    return entity

                case "6" | "7" | "9":
                    try: 
                        entity = FileEntity()
                        entity.event_id = str(eventID)
                        file_target = self._pick(event_data, "ImageLoaded", "Device")
                        entity.file_path = self.normalizer.normalize(['file_path'], file_target)
                        entity.content_hash = self._pick(event_data, "Hashes")
                        entity.source_image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "Image"))
                        parent_process_guid = self._pick(event_data, "ProcessGuid")
                        entity.parent_process = globals.get_process(parent_process_guid.strip()) if parent_process_guid else None

                        if entity.file_path:
                                globals.add_file(entity)

                        if entity.parent_process:
                            print(f"[FileLoad] parent_process_guid: {entity.parent_process.guid} | source_image: {entity.source_image_path} | loaded_file: {entity.file_path}")
                        # else:
                        #     print(f"[FileLoad] loaded_file: {entity.file_path}")
                    except Exception as e:
                        print(f"[Error][FileLoad] {e}")
                    return entity if entity.file_path else None

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
                        entity.parent_process = globals.get_process(parent_process_guid.strip()) if parent_process_guid else None
                        entity.source_image_path = self.normalizer.normalize(['file_path'], self._pick(event_data, "Image"))

                        if entity.key_path:
                            globals.add_registry(entity)

                        if entity.parent_process:
                            print(f"[RegistryEvent] parent_process_guid: {entity.parent_process.guid} | source_image: {entity.source_image_path} | key: {entity.key_path} | value: {entity.value_name}")
                        # else:
                        #     print(f"[RegistryEvent] key: {entity.key_path} | value: {entity.value_name}")
                            
                        return entity 
                    except Exception as e:
                        print(f"[Error][RegistryEvent] {e}")
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

                        if hasattr(globals, 'add_wmi'):
                            globals.add_wmi(entity)

                        print(f"[WMIEvent] namespace: {entity.wmi_namespace} | name: {entity.wmi_name} | query: {entity.wmi_query} | payload: {entity.wmi_payload}")

                        return entity
                    except Exception as e:
                        print(f"[Error][WMIEvent] {e}")
                        return None

                case _:
                    return None

        except:
            return None
    
class ETWBasedLogParser(Parser):
    def __init__(self):
        super().__init__()
        self.xml_format_parser = XMLParser() 
        self.plaintext_format_parser = PlainTextParser() 
        pass 