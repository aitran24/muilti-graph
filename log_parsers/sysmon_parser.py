from dataclasses import dataclass
from .format_parser import *
from typing import List, Dict
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
        """
        Parse Sysmon Logs from a given file path, return a list of dictionaries representing each log entry.
        """

        parsed_logs = []
        parsed_logs =self.xml_format_parser.parse_from_file(file_path) 
        print (f"XML format parsing result: {len(parsed_logs)} logs parsed.")
        if parsed_logs is None:
            parsed_logs = self.plaintext_format_parser.parse_from_file(file_path) 

        return parsed_logs
    
    def parse_from_rawlog(self, raw_log: str) -> List[Dict]:
        """
        Parse Sysmon Logs from a given raw log string, return a list of dictionaries representing each log entry.
        """
        parsed_logs = []
        parsed_logs = self.xml_format_parser.parse_raw_log(raw_log) 
        if parsed_logs is None:
            parsed_logs = self.plaintext_format_parser.parse_raw_log(raw_log) 

        return parsed_logs

class SysmonLogParser(Parser):
    def __init__(self):
        super().__init__()
        pass 

    def map_entity(self, log_entry: Dict) -> BaseEntity:
        try:
            eventID = log_entry.get("EventCode")
            if not eventID:
                return None
            match str(eventID):
                case "1": # Process Creation 
                    try: 
                        # print("Mapping Process Creation event to ProcessEntity...")
                        entity = ProcessEntity()
                        entity.guid = log_entry.get("EventData").get("ProcessGuid")
                        # print(f"Extracted ProcessGuid: {entity.guid}")
                        entity.pid = log_entry.get("EventData").get("ProcessId")
                        # print(f"Extracted ProcessId: {entity.pid}")
                        entity.image_path = self.normalizer.normalize_file_path(log_entry.get("EventData").get("Image"))
                        # print(f"Extracted Image Path: {entity.image_path}")
                        entity.command_line = self.normalizer.normalize_command_line(log_entry.get("EventData").get("CommandLine"))
                        entity.command_line = self.normalizer.normalize_file_path(entity.command_line)
                        # print(f"Extracted Command Line: {entity.command_line}")
                        entity.original_file_name = self.normalizer.normalize_file_path(log_entry.get("EventData").get("OriginalFileName"))
                        # print(f"Extracted Original File Name: {entity.original_file_name}")
                        entity.image_hash = log_entry.get("EventData").get("Hashes")
                        # print(f"Extracted Image Hash: {entity.image_hash}")
                        entity.parent_process = globals.get_process(log_entry.get("EventData").get("ParentProcessGuid", "").strip()) or None
                        # print(f"Extracted Parent Process: {log_entry.get("EventData").get("ParentProcessGuid", "").strip()}")
                        entity.user = globals.get_user((log_entry.get("System").get("Security") or {}).get("UserID", "").strip()) or None
                        # print(f"Extracted User: {entity.user}")
                        entity.command_hash = self.normalizer.command_line.hash_command(entity.command_line)
                        # print(f"Computed Command Hash: {entity.command_hash}")
                        entity.process_name = self.normalizer.normalize_file_path(log_entry.get("EventData").get("Description"))

                        globals.add_process(entity)

                        if entity.parent_process:
                            print(entity.parent_process.guid + " -> " + entity.guid) 
                    except Exception as e:
                        print(f"Error mapping Process Creation event: {e}")

                    return None
                case _:
                    # print(f"EventCode {eventID} is not mapped to any entity type yet.")
                    return None

        except:
            pass
    
class ETWBasedLogParser(Parser):
    def __init__(self):
        super().__init__()
        self.xml_format_parser = XMLParser() 
        self.plaintext_format_parser = PlainTextParser() 
        pass 

    


# def main():
#     parser = SysmonLogParser()
#     file_path = r"test_log\windows-sysmon.log" 
#     parsed_logs = parser.parse_from_file(file_path)
#     print(f"Parsed {len(parsed_logs)} logs from file: {file_path}")
#     for log in parsed_logs:
#         print(log)


# if __name__ == "__main__":    main()