import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Union, List
from abc import ABC, abstractmethod

class BaseEntity(ABC):
    @abstractmethod
    def get_id(self) -> str:
        pass

    @property
    @abstractmethod
    def entity_type(self) -> str:
        pass


@dataclass
class UserEntity(BaseEntity):
    username: str = ""
    domain: str = ""
    sid: str = ""
    logon_type: str = ""
    logon_id: str = ""

    # Set SID as unique identifier
    def get_id(self) -> str:
        if self.sid:
            return f"User:{self.sid}"
        return f"User:{self.domain}\\{self.username}".lower() 
    
    def get_session(self) -> Optional[str]:
        return self.logon_id if self.logon_id else None
    
    @property
    def entity_type(self) -> str:
        return "User"
    

@dataclass 
class ProcessEntity(BaseEntity):
    process_name: str = ""
    guid: str = ""
    pid: str = ""
    image_path: str = ""
    command_line: str = ""
    original_file_name: str = ""
    image_hash: str = ""       # hash of the executable file
    command_hash: str = ""     # hash of the command line arguments

    parent_process: Optional['ProcessEntity'] = field(default=None, repr=False)
    user: Optional[UserEntity] = field(default=None, repr=False) 


    # set GUID as unique identifier in Sysmon, using combination of process name and PID as fallback in Security logs
    def get_id(self) -> str:
        if self.guid:
            return f"Process:{self.guid}"
        return f"Process:{self.process_name}/{self.pid}".lower() 
    
    @property
    def entity_type(self) -> str:
        return "Process"
    

    @property
    def image_name(self) -> str:
        return Path(self.image_path).name if self.image_path else ""
    

    def is_masquerading(self) -> bool:
        if self.original_file_name and self.image_name:
            return self.original_file_name.lower() != self.image_name.lower()
        return False
    

    # Recursively get all ancestor processes
    def get_ancestors(self) -> List['ProcessEntity']:
        ancestors = []
        current = self.parent_process
        while current:
            ancestors.append(current)
            current = current.parent_process
        return ancestors 
    


@dataclass 
class FileEntity(BaseEntity):
    file_path: str = ""
    content_hash: str = ""

    # Hash file name as unique identifier 
    def get_id(self) -> str:
        path_hash = hashlib.sha256(self.file_path.lower().encode()).hexdigest()
        return f"File:{path_hash}"
    
    @property
    def entity_type(self) -> str:
        return "File"
    
    @property
    def file_name(self) -> str:
        return Path(self.file_path).name if self.file_path else ""
    
    @property
    def extension(self) -> str:
        return Path(self.file_path).suffix.lower() if self.file_path else ""
    


@dataclass
class RegistryEntity(BaseEntity):
    key_path: str = ""
    value_name: str = ""
    value_data: str = ""

    # Hash registry key path as unique identifier
    def get_id(self) -> str:
        full_path = f"{self.key_path}\\{self.value_name}" if self.value_name else self.key_path
        reg_hash = hashlib.sha256(full_path.lower().encode()).hexdigest()
        return f"Registry:{reg_hash}" 
    
    @property
    def entity_type(self) -> str:
        return "Registry"
    
    @property
    def key_name(self) -> str:
        return Path(self.key_path).name if self.key_path else ""
    


@dataclass
class NetworkEntity(BaseEntity):
    destination_ip: str = ""
    destination_port: str = ""
    protocol: str = "tcp"
    domain_name: str = ""

    # set combination of IP, port, and protocol as unique identifier for network connections
    def get_id(self) -> str:
        return f"Network:{self.destination_ip}:{self.destination_port}:{self.protocol}".lower()
    
    @property
    def entity_type(self) -> str:
        return "Network"
    
    def is_external_connection(self) -> bool:
        if self.destination_ip.startswith(('10.', '192.168.', '127.')):
            return False
        return True


    
