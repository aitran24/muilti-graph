import json
from pathlib import Path


INPUT_FILE = Path(__file__).with_name("etw_five_logs_per_eventcode.json")
OUTPUT_FILE = Path(__file__).with_name("event_structure_only.json")


def empty_structure(value):
    if isinstance(value, dict):
        return {k: empty_structure(v) for k, v in value.items()}
    if isinstance(value, list):
        return []
    return ""


def main():
    with INPUT_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)

    events = data.get("events", {})
    structure_only = {}

    for event_id, event_data in events.items():
        samples = event_data.get("samples", [])
        if not samples:
            continue

        longest_sample = max(
            samples,
            key=lambda s: (
                s.get("length", 0),
                len(s.get("raw", "")),
            ),
        )

        parsed_log = longest_sample.get("parsed", {})
        if not isinstance(parsed_log, dict):
            parsed_log = {}

        log_name = parsed_log.get("LogName", "UnknownLog")
        if not isinstance(log_name, str) or not log_name.strip():
            log_name = "UnknownLog"

        task_category = parsed_log.get("TaskCategory", "UnknownTaskCategory")
        if not isinstance(task_category, str) or not task_category.strip():
            task_category = "UnknownTaskCategory"

        structure_key = f"{log_name}_{task_category}_{event_id}"
        structure_only[structure_key] = empty_structure(parsed_log)

    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(structure_only, f, indent=2, ensure_ascii=False)

    print(f"Wrote structure-only output to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
