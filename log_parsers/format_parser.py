import re
from typing import Any
from xml.etree import ElementTree
from pathlib import Path
from abc import ABC, abstractmethod
from globals.logger_manager import LoggerManager


logger = LoggerManager.get_logger(__name__)


class Format(ABC):
    @abstractmethod
    def parse_raw_log(self, logs: Any) -> list:
        pass

    @abstractmethod
    def parse_from_file(self, file_path: str | Path) -> list:
        pass


class XMLParser(Format):
    def __init__(self):
        pass

    @staticmethod
    def _local_name(tag: str) -> str:
        if "}" in tag:
            return tag.rsplit("}", 1)[1]
        return tag

    @staticmethod
    def _element_to_tree(elem: ElementTree.Element) -> dict:
        node: dict = {"tag": XMLParser._local_name(elem.tag)}

        if elem.attrib:
            node["attributes"] = dict(elem.attrib)

        text = (elem.text or "").strip()
        if text:
            node["text"] = text

        children = list(elem)
        if children:
            node["children"] = [XMLParser._element_to_tree(child) for child in children]

        return node

    @staticmethod
    def _safe_put(container: dict, key: str, value: Any) -> None:
        if key in container:
            existing = container[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                container[key] = [existing, value]
        else:
            container[key] = value

    def parse_event(self, log: str) -> dict | None:
        if not self.check_XMLFormat(log):
            return None

        root = ElementTree.fromstring(log)
        parsed: dict = {}

        system_section: dict = {}
        event_data_section: dict = {}
        user_data_section: dict = {}
        rendering_info_section: dict = {}

        for child in list(root):
            name = self._local_name(child.tag)

            if name == "System":
                for node in list(child):
                    n = self._local_name(node.tag)

                    if n == "Provider":
                        provider_name = node.attrib.get("Name", "")
                        if provider_name:
                            parsed["SourceName"] = provider_name
                        system_section["Provider"] = dict(node.attrib)
                    elif n == "EventID":
                        event_id = (node.text or "").strip()
                        if event_id:
                            parsed["EventCode"] = event_id
                            system_section["EventID"] = event_id
                    elif n == "TimeCreated":
                        ts = node.attrib.get("SystemTime", "")
                        if ts:
                            parsed["Timestamp"] = ts
                        system_section["TimeCreated"] = dict(node.attrib)
                    elif n == "Channel":
                        ch = (node.text or "").strip()
                        if ch:
                            parsed["LogName"] = ch
                            system_section["Channel"] = ch
                    elif n == "Computer":
                        comp = (node.text or "").strip()
                        if comp:
                            parsed["ComputerName"] = comp
                            system_section["Computer"] = comp
                    elif n == "Execution":
                        system_section["Execution"] = dict(node.attrib)
                    elif n == "Security":
                        system_section["Security"] = dict(node.attrib)
                    else:
                        text = (node.text or "").strip()
                        if node.attrib and text:
                            system_section[n] = {"attributes": dict(node.attrib), "text": text}
                        elif node.attrib:
                            system_section[n] = dict(node.attrib)
                        elif text:
                            system_section[n] = text
                        else:
                            system_section[n] = ""

            elif name == "EventData":
                for node in list(child):
                    n = self._local_name(node.tag)
                    text = (node.text or "").strip()

                    if n == "Data":
                        key = node.attrib.get("Name", "Data")
                        self._safe_put(event_data_section, key, text)

                        if key == "UtcTime" and text and "Timestamp" not in parsed:
                            parsed["Timestamp"] = text
                    else:
                        if node.attrib and text:
                            self._safe_put(event_data_section, n, {"attributes": dict(node.attrib), "text": text})
                        elif node.attrib:
                            self._safe_put(event_data_section, n, dict(node.attrib))
                        else:
                            self._safe_put(event_data_section, n, text)

            elif name == "UserData":
                for node in list(child):
                    key = self._local_name(node.tag)
                    user_data_section[key] = self._element_to_tree(node)

            elif name == "RenderingInfo":
                for node in list(child):
                    key = self._local_name(node.tag)
                    text = (node.text or "").strip()
                    if text:
                        rendering_info_section[key] = text
                    elif node.attrib:
                        rendering_info_section[key] = dict(node.attrib)
                    else:
                        rendering_info_section[key] = self._element_to_tree(node)

        if system_section:
            parsed["System"] = system_section
        if event_data_section:
            parsed["EventData"] = event_data_section
        if user_data_section:
            parsed["UserData"] = user_data_section
        if rendering_info_section:
            parsed["RenderingInfo"] = rendering_info_section

        return parsed

    @staticmethod
    def check_XMLFormat(log: any) -> bool:
        try:
            ElementTree.fromstring(log)
            return True
        except ElementTree.ParseError:
            return False

    def parse_log(self, logs: any) -> list: 
        parsed_logs = []
        raw_logs = []
        if not isinstance(logs, list):
            try:
                xml_format = False 
                raw_logs = []
                for line in logs:
                    line = line.strip()
                    if not xml_format:
                        xml_format = self.check_XMLFormat(line)
                        if not xml_format:
                            return None
                    raw_logs.append(line)
            except Exception as e:
                logger.error(f"Error processing logs: {e}")
                return None
        logs = raw_logs if raw_logs else logs
        xml_format = False
        for log in logs:
            if not xml_format:
                xml_format = self.check_XMLFormat(log)
                if not xml_format:
                    return None 
            try:
                parsed = self.parse_event(log)
                if parsed is not None:
                    parsed_logs.append(parsed)
            except ElementTree.ParseError as e:
                with open("error.log", "a") as f:
                    f.write(f"Error parsing XML log: {e}\n")
                    f.write(f"Log content: {log}\n\n")
                logger.error(f"Error parsing XML log: {e}")
                logger.error(f"Log content: {log}")
                continue
        return parsed_logs

    def parse_raw_log(self, logs: Any) -> list:
        return self.parse_log(logs)

    def parse_from_file(self, file_path: str | Path) -> list:
        logs = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    logs.append(line)
        return self.parse_raw_log(logs)


class PlainTextParser(Format):
    TIMESTAMP_RE = re.compile(
        r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}(?: (?:AM|PM))?$"
    )
    TOP_LEVEL_EQUAL_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _./()\-]{0,120})=(.*)$")
    TOP_LEVEL_COLON_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _./()\-]{0,120}):\s*(.*)$")

    @staticmethod
    def check_format(log: Any) -> bool:
        if not log:
            return False
        text = log if isinstance(log, str) else str(log)
        lines = text.strip().splitlines()
        if not lines:
            return False

        has_timestamp = any(PlainTextParser.TIMESTAMP_RE.match(ln.strip()) for ln in lines[:20])
        has_eventcode = any(ln.strip().startswith("EventCode=") for ln in lines)
        has_logname = any(ln.strip().startswith("LogName=") for ln in lines)
        return has_timestamp and (has_eventcode or has_logname)

    def split_events(self, text: str) -> list[str]:
        lines = text.splitlines(keepends=True)
        events: list[list[str]] = []
        current: list[str] = []

        for line in lines:
            if self.TIMESTAMP_RE.match(line.strip()) and current:
                events.append(current)
                current = [line]
            else:
                current.append(line)

        if current:
            events.append(current)

        return ["".join(chunk) for chunk in events if "".join(chunk).strip()]

    def parse_event(self, text: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        lines = text.splitlines()
        n = len(lines)
        i = 0

        while i < n and not lines[i].strip():
            i += 1

        if i < n and self.TIMESTAMP_RE.match(lines[i].strip()):
            result["Timestamp"] = lines[i].strip()
            i += 1

        free_text: list[str] = []

        while i < n:
            line = lines[i]
            stripped = line.strip()

            if not stripped:
                i += 1
                continue

            depth = self._indent_depth(line)

            if depth > 0:
                free_text.append(line.rstrip())
                i += 1
                continue

            if "=" in line and not self._looks_like_colon_kv(line):
                kv = self._split_equal(line)
                if kv is None:
                    free_text.append(line.rstrip())
                    i += 1
                    continue
                key, val = kv

                if self._is_multiline_value_key(key):
                    block, next_i = self._collect_multiline_value(lines, i + 1, n)
                    if block:
                        val = f"{val}\n" + "\n".join(block) if val else "\n".join(block)
                    i = next_i
                else:
                    i += 1

                self._store_value(result, key, val)

            elif ":" in line:
                kv = self._split_colon(line)
                if kv is None:
                    free_text.append(line.rstrip())
                    i += 1
                    continue

                key, after_stripped = kv

                if after_stripped == "":
                    next_nonblank = i + 1
                    while next_nonblank < n and not lines[next_nonblank].strip():
                        next_nonblank += 1

                    next_depth = (
                        self._indent_depth(lines[next_nonblank])
                        if next_nonblank < n and lines[next_nonblank].strip()
                        else 0
                    )

                    if next_depth > 0:
                        section, i = self._parse_section(lines, i + 1, n)
                        self._store_value(result, key, section)
                    elif self._is_multiline_value_key(key):
                        block, i = self._collect_multiline_value(lines, i + 1, n)
                        self._store_value(result, key, "\n".join(block))
                    else:
                        self._store_value(result, key, "")
                        i += 1
                else:
                    if self._is_multiline_value_key(key):
                        block, next_i = self._collect_multiline_value(lines, i + 1, n)
                        if block:
                            after_stripped = f"{after_stripped}\n" + "\n".join(block)
                        i = next_i
                    else:
                        i += 1

                    self._store_value(result, key, after_stripped)

            else:
                free_text.append(line.rstrip())
                i += 1

        if free_text:
            result["_free_text"] = "\n".join(free_text)

        return result

    def parse_raw_log(self, log_text: str) -> list[dict[str, Any]]:
        if not isinstance(log_text, str) or not log_text.strip():
            return []

        chunks = self.split_events(log_text)
        out: list[dict[str, Any]] = []

        for chunk in chunks:
            if not chunk.strip():
                continue
            if not self.check_format(chunk):
                continue
            out.append(self.parse_event(chunk))

        return out

    def parse_from_file(self, file_path: str | Path) -> list[dict[str, Any]]:
        text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        return self.parse_raw_log(text)

    def _parse_section(self, lines: list[str], start: int, n: int) -> tuple[dict[str, Any], int]:
        section: dict[str, Any] = {}
        extras: list[str] = []

        cur_key: str | None = None
        cur_vals: list[str] = []

        i = start
        while i < n:
            line = lines[i]
            stripped = line.strip()

            if not stripped:
                i += 1
                continue

            depth = self._indent_depth(line)
            if depth == 0:
                break

            content = line.lstrip("\t").lstrip(" ")

            if depth == 1:
                kv = self._split_colon(content)
                if kv is not None:
                    self._flush(section, cur_key, cur_vals)
                    cur_key, init_val = kv
                    cur_vals = [init_val] if init_val else []
                else:
                    self._flush(section, cur_key, cur_vals)
                    cur_key = None
                    cur_vals = []
                    extras.append(stripped)
            else:
                if cur_key is not None:
                    cur_vals.append(stripped)
                else:
                    extras.append(stripped)

            i += 1

        self._flush(section, cur_key, cur_vals)

        if extras:
            section["_extras"] = extras

        return section, i

    @staticmethod
    def _indent_depth(line: str) -> int:
        prefix = len(line) - len(line.lstrip(" \t"))
        if prefix <= 0:
            return 0

        tabs = 0
        spaces = 0
        for ch in line[:prefix]:
            if ch == "\t":
                tabs += 1
            elif ch == " ":
                spaces += 1

        levels = tabs + (spaces // 4)
        if levels == 0 and spaces > 0:
            levels = 1
        return levels

    @staticmethod
    def _split_equal(text: str) -> tuple[str, str] | None:
        m = PlainTextParser.TOP_LEVEL_EQUAL_RE.match(text.strip())
        if not m:
            return None
        return m.group(1).strip(), m.group(2).strip()

    @staticmethod
    def _looks_like_colon_kv(line: str) -> bool:
        ci = line.find(":")
        ei = line.find("=")
        return ci != -1 and ci < ei

    @staticmethod
    def _split_colon(text: str) -> tuple[str, str] | None:
        m = PlainTextParser.TOP_LEVEL_COLON_RE.match(text.strip())
        if not m:
            return None
        return m.group(1).strip(), m.group(2).strip()

    @staticmethod
    def _is_multiline_value_key(key: str) -> bool:
        k = key.strip().lower()
        markers = (
            "script",
            "payload",
            "command line",
            "commandline",
            "message",
            "description",
            "details",
            "text",
            "content",
            "body",
            "query",
            "statement",
        )
        return any(m in k for m in markers)

    def _collect_multiline_value(self, lines: list[str], start: int, n: int) -> tuple[list[str], int]:
        collected: list[str] = []
        i = start

        while i < n:
            line = lines[i]
            stripped = line.strip()

            if self.TIMESTAMP_RE.match(stripped):
                break

            if stripped and self._indent_depth(line) == 0 and self._is_top_level_field_candidate(line):
                break

            collected.append(line.rstrip())
            i += 1

        while collected and not collected[0].strip():
            collected.pop(0)
        while collected and not collected[-1].strip():
            collected.pop()

        return collected, i

    @staticmethod
    def _is_top_level_field_candidate(line: str) -> bool:
        stripped = line.strip()
        if not stripped:
            return False
        return bool(
            PlainTextParser.TOP_LEVEL_EQUAL_RE.match(stripped)
            or PlainTextParser.TOP_LEVEL_COLON_RE.match(stripped)
        )

    @staticmethod
    def _store_value(container: dict[str, Any], key: str, value: Any) -> None:
        if key in container:
            existing = container[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                container[key] = [existing, value]
        else:
            container[key] = value

    @staticmethod
    def _flush(container: dict[str, Any], key: str | None, value_lines: list[str]) -> None:
        if key is None:
            return
        value = "\n".join(v for v in value_lines if v)
        if key in container:
            existing = container[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                container[key] = [existing, value]
        else:
            container[key] = value