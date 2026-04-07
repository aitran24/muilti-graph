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