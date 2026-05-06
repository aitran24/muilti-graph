from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass(slots=True)
class EventRecord:
    record_id: int
    xml: str


class SysmonEventLogSource:
    def __init__(self, channel: str = "Microsoft-Windows-Sysmon/Operational") -> None:
        self.channel = channel

    @staticmethod
    def max_record_id(records: list[EventRecord]) -> int | None:
        if not records:
            return None
        return max(record.record_id for record in records)

    def _run_wevtutil(self, args: list[str]) -> str:
        result = subprocess.run(
            ["wevtutil", *args],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip() or (result.stdout or "").strip()
            raise RuntimeError(stderr or f"wevtutil failed with exit code {result.returncode}")
        return result.stdout or ""

    def clear_channel(self) -> None:
        self._run_wevtutil([
            "cl",
            self.channel,
        ])

    def _parse_events_xml(self, xml_text: str) -> list[EventRecord]:
        payload = str(xml_text or "").strip()
        if not payload:
            return []

        if payload.startswith("No events were found"):
            return []

        records: list[EventRecord] = []

        def append_if_valid(event_element: ET.Element) -> None:
            record_id_text = event_element.findtext(".//{*}EventRecordID", default="").strip()
            if not record_id_text.isdigit():
                return

            event_xml = ET.tostring(event_element, encoding="unicode")
            records.append(EventRecord(record_id=int(record_id_text), xml=event_xml))

        try:
            root = ET.fromstring(payload)
        except ET.ParseError:
            # Some wevtutil outputs are concatenated <Event> documents without <Events> root.
            fragments = re.findall(r"(<Event\b[\s\S]*?</Event>)", payload)
            for fragment in fragments:
                try:
                    event = ET.fromstring(fragment)
                except ET.ParseError:
                    continue
                if event.tag.endswith("Event"):
                    append_if_valid(event)
        else:
            if root.tag.endswith("Event"):
                append_if_valid(root)
            else:
                for event in root.findall("{*}Event"):
                    append_if_valid(event)

        records.sort(key=lambda item: item.record_id)
        return records

    def read_latest_record_id(self) -> int | None:
        xml_text = self._run_wevtutil([
            "qe",
            self.channel,
            "/f:xml",
            "/c:1",
            "/rd:true",
        ])
        records = self._parse_events_xml(xml_text)
        return records[-1].record_id if records else None

    def read_recent_events(self, max_count: int) -> list[EventRecord]:
        safe_count = max(1, int(max_count))
        xml_text = self._run_wevtutil([
            "qe",
            self.channel,
            "/f:xml",
            f"/c:{safe_count}",
            "/rd:true",
        ])
        return self._parse_events_xml(xml_text)

    def read_events_after(self, record_id: int, max_count: int) -> list[EventRecord]:
        safe_count = max(1, int(max_count))
        query = (
            "<QueryList>"
            f"<Query Id='0' Path='{self.channel}'>"
            f"<Select Path='{self.channel}'>*[System[(EventRecordID &gt; {int(record_id)})]]</Select>"
            "</Query>"
            "</QueryList>"
        )

        xml_text = self._run_wevtutil([
            "qe",
            self.channel,
            f"/q:{query}",
            "/f:xml",
            f"/c:{safe_count}",
            "/rd:false",
        ])
        return self._parse_events_xml(xml_text)
