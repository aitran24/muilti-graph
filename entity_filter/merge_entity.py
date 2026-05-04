from pathlib import Path
from class_define.object_definition import BaseEntity, ProcessEntity, FileEntity
from globals.logger_manager import LoggerManager


logger = LoggerManager.get_logger(__name__)


class EntityMerger:
    FILE_EVENT_IDS_EXCLUDED_FROM_PATH_MERGE = {"7", "17", "18"}

    COMMON_FILE_EXTENSIONS = {
        # Common document/text/config
        ".txt", ".log", ".csv", ".json", ".xml", ".ini", ".cfg", ".conf", ".config",
        ".yml", ".yaml", ".md", ".rst", ".rtf", ".pdf",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp",

        # Common executable / library / installer
        ".exe", ".dll", ".sys", ".drv", ".com", ".ocx", ".cpl", ".scr", ".mui",
        ".msi", ".msp", ".appx", ".msix", ".lnk",

        # Common script / command / web
        ".bat", ".cmd", ".cmdline", ".ps1", ".psm1", ".psd1", ".ps1xml", ".pssc", ".psrc",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sct", ".scf", ".url",
        ".reg", ".inf", ".msc", ".sh", ".bash", ".zsh", ".ksh", ".py", ".rb", ".pl",
        ".php", ".asp", ".aspx", ".jsp", ".htm", ".html", ".css", ".xsl", ".xhtml",

        # Common archives / packages / disk images
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".img",
        ".vhd", ".vhdx", ".jar", ".war", ".ear", ".nupkg",

        # Common media
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tif", ".tiff",
        ".mp3", ".wav", ".wma", ".aac", ".ogg", ".flac", ".mp4", ".avi", ".mkv", ".mov",
        ".wmv", ".flv", ".webm",

        # Common data/runtime artifacts
        ".dat", ".db", ".sqlite", ".edb", ".evtx", ".etl", ".dmp", ".tmp", ".temp",
        ".cache", ".bak", ".old", ".crdownload", ".partial", ".swp",
    }

    @staticmethod
    def is_file_event_mergeable(event_id: str) -> bool:
        normalized_event_id = str(event_id or "").strip()
        if not normalized_event_id:
            return False
        return normalized_event_id not in EntityMerger.FILE_EVENT_IDS_EXCLUDED_FROM_PATH_MERGE

    @staticmethod
    def merge_and_update(entity1: BaseEntity, entity2: BaseEntity):
        event_id_1 = str(getattr(entity1, "event_id", "") or "").strip()
        event_id_2 = str(getattr(entity2, "event_id", "") or "").strip()

        if (
            isinstance(entity1, FileEntity)
            and isinstance(entity2, FileEntity)
            and event_id_1
            and event_id_1 == event_id_2
            and EntityMerger.is_file_event_mergeable(event_id_1)
        ):
            if not entity1.file_path or not entity2.file_path:
                return (entity1, entity2)

            path1 = Path(entity1.file_path)
            path2 = Path(entity2.file_path)

            parent1 = str(path1.parent).lower()
            parent2 = str(path2.parent).lower()
            ext1 = path1.suffix.lower()
            ext2 = path2.suffix.lower()

            if (
                parent1 in (".", "")
                or parent2 in (".", "")
                or not ext1
                or not ext2
                or parent1 != parent2
            ):
                return (entity1, entity2)

            # Same extension in same directory: collapse to MULTI_FILE.<ext>
            if ext1 == ext2:
                entity1.file_path = str(path1.parent) + "\\MULTI_FILE" + ext1
                return entity1

            # Different name + different extension in same directory:
            # if both extensions are uncommon, collapse into STRANGE_EXT bucket.
            stem1 = path1.stem.lower()
            stem2 = path2.stem.lower()
            if (
                stem1 != stem2
                and ext1 != ext2
                and ext1 not in EntityMerger.COMMON_FILE_EXTENSIONS
                and ext2 not in EntityMerger.COMMON_FILE_EXTENSIONS
            ):
                entity1.file_path = str(path1.parent) + "\\MULTI_FILE.STRANGE_EXT"
                logger.debug(
                    "Merged uncommon file extensions under STRANGE_EXT: %s and %s",
                    path1.name,
                    path2.name,
                )
                return entity1

            return (entity1, entity2)

        if (
            isinstance(entity1, ProcessEntity)
            and isinstance(entity2, ProcessEntity)
        ):
            if entity1.get_id() == entity2.get_id():
                for key, value in entity1.__dict__.items():
                    if key not in ("event_id", "guid", "pid"):
                        incoming_value = getattr(entity2, key)
                        if not value and incoming_value:
                            setattr(entity1, key, incoming_value)
                return entity1

            # Merge ProcessEntity instances that share the same command_hash.
            # command_hash already encodes process-name/extension semantics.
            if entity1.command_hash and entity1.command_hash == entity2.command_hash:
                preserved_guid = entity1.guid
                preserved_pid = entity1.pid
                for key, value in entity1.__dict__.items():
                    if key not in ("event_id", "guid", "pid"):
                        incoming_value = getattr(entity2, key)
                        if not value and incoming_value:
                            setattr(entity1, key, incoming_value)
                entity1.guid = preserved_guid
                entity1.pid = preserved_pid
                logger.debug(
                    "Merged ProcessEntity with command_hash %s: %s and %s",
                    entity1.command_hash,
                    entity1.get_id(),
                    entity2.get_id(),
                )
                return entity1

        # Fallback: same-id merge for all entity types.
        if entity1.get_id() == entity2.get_id():
            for key, value in entity1.__dict__.items():
                if key != "event_id":
                    incoming_value = getattr(entity2, key)
                    if not value and incoming_value:
                        setattr(entity1, key, incoming_value)
            return entity1

        return (entity1, entity2)

