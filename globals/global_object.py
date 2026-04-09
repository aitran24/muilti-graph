from typing import Dict
from class_define.object_definition import *

_process_map: Dict[str, ProcessEntity] = {}

def add_process(process: ProcessEntity):
    _process_map[process.guid] = process

def get_process(guid: str) -> ProcessEntity | None:
    return _process_map.get(guid)

def exists_process(guid: str) -> bool:
    return guid in _process_map

def get_all_processes() -> Dict[str, ProcessEntity]:
    return _process_map


_user_map: Dict[str, UserEntity] = {}

def add_user(user: UserEntity):
    _user_map[user.get_id()] = user

def get_user(user_id: str) -> UserEntity | None:
    return _user_map.get(user_id)

def exists_user(user_id: str) -> bool:
    return user_id in _user_map

def get_all_users() -> Dict[str, UserEntity]:
    return _user_map



_file_map: Dict[str, FileEntity] = {}
def add_file(file: FileEntity):
    _file_map[file.get_id()] = file

def get_file(file_id: str) -> FileEntity | None:
    return _file_map.get(file_id)

def exists_file(file_id: str) -> bool:
    return file_id in _file_map

def get_all_files() -> Dict[str, FileEntity]:
    return _file_map

_network_map: Dict[str, NetworkEntity] = {} 

def add_network(network: NetworkEntity):
    _network_map[network.get_id()] = network

def get_network(network_id: str) -> NetworkEntity | None:
    return _network_map.get(network_id)

def exists_network(network_id: str) -> bool:
    return network_id in _network_map

def get_all_networks() -> Dict[str, NetworkEntity]:
    return _network_map


_registry_map: Dict[str, RegistryEntity] = {}
def add_registry(registry: RegistryEntity):
    _registry_map[registry.get_id()] = registry

def get_registry(registry_id: str) -> RegistryEntity | None:
    return _registry_map.get(registry_id)

def exists_registry(registry_id: str) -> bool:
    return registry_id in _registry_map

def get_all_registries() -> Dict[str, RegistryEntity]:
    return _registry_map


_wmi_map: Dict[str, WmiEntity] = {}
def add_wmi(wmi: WmiEntity):
    _wmi_map[wmi.get_id()] = wmi

def get_wmi(wmi_id: str) -> WmiEntity | None:
    return _wmi_map.get(wmi_id)

def exists_wmi(wmi_id: str) -> bool:
    return wmi_id in _wmi_map

def get_all_wmis() -> Dict[str, WmiEntity]:
    return _wmi_map



SYSMON_BEHAVIOR_MAP = {
    "1": "Process Create",
    "2": "File Creation Time Changed",
    "3": "Network Connection",
    "4": "Sysmon Service State Changed",
    "5": "Process Terminated",
    "6": "Driver Loaded",
    "7": "Image Loaded",
    "8": "CreateRemoteThread",
    "9": "RawAccessRead",
    "10": "ProcessAccess",
    "11": "File Create",
    "12": "Registry Object Create/Delete",
    "13": "Registry Value Set",
    "14": "Registry Key/Value Rename",
    "15": "FileCreateStreamHash",
    "16": "ServiceConfigurationChange",
    "17": "Pipe Created",
    "18": "Pipe Connected",
    "19": "WmiEventFilter Activity",
    "20": "WmiEventConsumer Activity",
    "21": "WmiEventConsumerToFilter Activity",
    "22": "DNS Query",
    "23": "File Delete (archived)",
    "24": "ClipboardChange",
    "25": "ProcessTampering",
    "26": "File Delete (logged)",
    "27": "FileBlockExecutable",
    "28": "FileBlockShredding",
    "29": "FileExecutableDetected",
    "255": "Error"
}