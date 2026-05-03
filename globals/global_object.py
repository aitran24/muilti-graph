from typing import Dict
from pathlib import Path
from class_define.object_definition import *

_process_map: Dict[str, ProcessEntity] = {}
_process_command_hash_map: Dict[str, ProcessEntity] = {}
_ignored_process_guids: set[str] = set()
_ignored_process_ids: set[str] = set()
_returned_node_ids: set[str] = set()


def _normalize_process_guid(guid: str) -> str:
    return (guid or "").strip().lower()


def _normalize_process_id(process_id: str) -> str:
    return (process_id or "").strip().lower()


def _index_process_command_hash(process: ProcessEntity):
    if not process or not process.command_hash:
        return

    _process_command_hash_map[process.command_hash] = process


def _unindex_process_command_hash(process: ProcessEntity):
    if not process or not process.command_hash:
        return

    existing_process = _process_command_hash_map.get(process.command_hash)
    if existing_process and existing_process.get_id() == process.get_id():
        _process_command_hash_map.pop(process.command_hash, None)

def add_process(process: ProcessEntity):
    _process_map[process.get_id()] = process
    _index_process_command_hash(process)

def get_process(process_id: str) -> ProcessEntity | None:
    return _process_map.get(process_id)


def get_process_by_command_hash(command_hash: str) -> ProcessEntity | None:
    return _process_command_hash_map.get(command_hash)

def update_process(process_id: str, updated_process: ProcessEntity):
    exist_entity = get_process(process_id)
    if exist_entity:
        _unindex_process_command_hash(exist_entity)
        _process_map[process_id] = updated_process
        _index_process_command_hash(updated_process)
    else:
        add_process(updated_process)

def exists_process(process_id: str) -> bool:
    return process_id in _process_map

def get_all_processes() -> Dict[str, ProcessEntity]:
    return _process_map

def get_process_from_guid(guid: str) -> ProcessEntity | None:
    normalized_guid = _normalize_process_guid(guid)
    if not normalized_guid:
        return None

    for process in _process_map.values():
        if process.get_id().endswith(":1"):
            if _normalize_process_guid(process.guid) == normalized_guid:
                return process
    return None


def add_ignored_process_guid(guid: str):
    normalized_guid = _normalize_process_guid(guid)
    if normalized_guid:
        _ignored_process_guids.add(normalized_guid)


def add_ignored_process_id(process_id: str):
    normalized_process_id = _normalize_process_id(process_id)
    if normalized_process_id:
        _ignored_process_ids.add(normalized_process_id)


def add_ignored_process(process: ProcessEntity | None):
    if not process:
        return
    add_ignored_process_guid(process.guid)
    add_ignored_process_id(process.get_id())


def is_ignored_process_guid(guid: str) -> bool:
    normalized_guid = _normalize_process_guid(guid)
    if not normalized_guid:
        return False
    return normalized_guid in _ignored_process_guids


def is_ignored_process_id(process_id: str) -> bool:
    normalized_process_id = _normalize_process_id(process_id)
    if not normalized_process_id:
        return False
    return normalized_process_id in _ignored_process_ids


def get_all_ignored_process_guids() -> set[str]:
    return set(_ignored_process_guids)


def get_all_ignored_process_ids() -> set[str]:
    return set(_ignored_process_ids)


def add_returned_node_id(node_id: str):
    if node_id:
        _returned_node_ids.add(node_id)


def is_returned_node_id(node_id: str) -> bool:
    return bool(node_id) and node_id in _returned_node_ids


def get_all_returned_node_ids() -> set[str]:
    return set(_returned_node_ids)


_user_map: Dict[str, UserEntity] = {}

def add_user(user: UserEntity):
    _user_map[user.get_id()] = user

def get_user(user_id: str) -> UserEntity | None:
    return _user_map.get(user_id)

def update_user(user_id: str, updated_user: UserEntity):
    exist_entity = get_user(user_id)
    if exist_entity:
        _user_map[user_id] = updated_user
    else:
        add_user(updated_user)

def exists_user(user_id: str) -> bool:
    return user_id in _user_map

def get_all_users() -> Dict[str, UserEntity]:
    return _user_map



_file_map: Dict[str, FileEntity] = {}
_file_path_ext_map: Dict[str, FileEntity] = {}
_file_id_redirect_map: Dict[str, str] = {}


def _get_file_path_ext_key(file: FileEntity) -> str | None:
    if not file or not file.file_path or not file.extension:
        return None
    parent_path = file.directory.lower()
    ext = file.extension
    if parent_path in (".", "") or not ext:
        return None
    return f"{parent_path}:{ext}"

def add_file(file: FileEntity):
    _file_map[file.get_id()] = file
    if file.event_id == "11":
        key = _get_file_path_ext_key(file)
        if key:
            _file_path_ext_map[key] = file

def get_file(file_id: str) -> FileEntity | None:
    return _file_map.get(file_id)

def get_file_by_path_ext(file: FileEntity) -> FileEntity | None:
    key = _get_file_path_ext_key(file)
    return _file_path_ext_map.get(key) if key else None

def get_file_id_redirects() -> Dict[str, str]:
    return _file_id_redirect_map

def update_file(file_id: str, updated_file: FileEntity):
    new_id = updated_file.get_id()
    _file_map.pop(file_id, None)
    _file_map[new_id] = updated_file
    if file_id != new_id:
        _file_id_redirect_map[file_id] = new_id
    if updated_file.event_id == "11":
        key = _get_file_path_ext_key(updated_file)
        if key:
            _file_path_ext_map[key] = updated_file



def exists_file(file_id: str) -> bool:
    return file_id in _file_map

def get_all_files() -> Dict[str, FileEntity]:
    return _file_map

_network_map: Dict[str, NetworkEntity] = {} 

def add_network(network: NetworkEntity):
    _network_map[network.get_id()] = network

def get_network(network_id: str) -> NetworkEntity | None:
    return _network_map.get(network_id)

def update_network(network_id: str, updated_network: NetworkEntity):
    exist_entity = get_network(network_id)
    if exist_entity:
        _network_map[network_id] = updated_network
    else:
        add_network(updated_network)

def exists_network(network_id: str) -> bool:
    return network_id in _network_map

def get_all_networks() -> Dict[str, NetworkEntity]:
    return _network_map


_registry_map: Dict[str, RegistryEntity] = {}
def add_registry(registry: RegistryEntity):
    _registry_map[registry.get_id()] = registry

def get_registry(registry_id: str) -> RegistryEntity | None:
    return _registry_map.get(registry_id)

def update_registry(registry_id: str, updated_registry: RegistryEntity):
    exist_entity = get_registry(registry_id)
    if exist_entity:
        _registry_map[registry_id] = updated_registry
    else:
        add_registry(updated_registry)

def exists_registry(registry_id: str) -> bool:
    return registry_id in _registry_map

def get_all_registries() -> Dict[str, RegistryEntity]:
    return _registry_map


_wmi_map: Dict[str, WmiEntity] = {}
def add_wmi(wmi: WmiEntity):
    _wmi_map[wmi.get_id()] = wmi

def get_wmi(wmi_id: str) -> WmiEntity | None:
    return _wmi_map.get(wmi_id)

def update_wmi(wmi_id: str, updated_wmi: WmiEntity):
    exist_entity = get_wmi(wmi_id)
    if exist_entity:
        _wmi_map[wmi_id] = updated_wmi
    else:
        add_wmi(updated_wmi)

def exists_wmi(wmi_id: str) -> bool:
    return wmi_id in _wmi_map

def get_all_wmis() -> Dict[str, WmiEntity]:
    return _wmi_map

def clear_all_globals():
    _process_map.clear()
    _process_command_hash_map.clear()
    _ignored_process_guids.clear()
    _ignored_process_ids.clear()
    _returned_node_ids.clear()
    _user_map.clear()
    _file_map.clear()
    _file_path_ext_map.clear()
    _file_id_redirect_map.clear()
    _network_map.clear()
    _registry_map.clear()
    _wmi_map.clear()

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