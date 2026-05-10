from __future__ import annotations

import json
import re
from collections import Counter, defaultdict, deque
from functools import lru_cache
from pathlib import Path
from time import perf_counter
from typing import Iterable

from .base import BaseMatcher
from ..models import GraphData, GraphEdge, GraphNode, TechniqueMatch


_TOKEN_RE = re.compile(r"[a-z0-9_./\\:-]+")
_TERM_TOKEN_RE = re.compile(r"[a-z0-9_.-]+")
_EXTENSION_PATTERN_RE = re.compile(r"^\.[a-z0-9]{1,16}$")
_EXTENSION_FOLLOW_CHAR_RE = re.compile(r"[a-z0-9_.-]")
_CORE_EFFECT_COMMAND_HEAD_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}(?:\.exe)?$")
_STRICT_CORE_COMMAND_SEED_TERMS = {
    "net",
    "net1",
    "cmd",
    "powershell",
    "pwsh",
    "reg",
    "sc",
    "wevtutil",
    "wmic",
    "schtasks",
    "netsh",
    "arp",
    "at",
    "ipconfig",
    "route",
    "nltest",
    "nslookup",
    "ping",
    "whoami",
    "klist",
    "netstat",
    "quser",
    "runas",
    "rundll32",
    "mshta",
    "msiexec",
    "wscript",
    "cscript",
    "diskpart",
    "diskshadow",
    "vssadmin",
    "wbadmin",
    "certutil",
    "bcdedit",
    "takeown",
    "icacls",
    "cacls",
    "findstr",
    "forfiles",
    "mountvol",
    "ftp",
    "bitsadmin",
    "taskkill",
    "dsquery",
    "sqlcmd",
    "winrs",
    "winrm",
    "sam"
}
_DEFAULT_SYSTEM_COMPONENTS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "reg.exe",
    "regedit.exe",
    "fodhelper.exe",
    "wmic.exe",
    "wmiprvse.exe",
    "schtasks.exe",
    "rundll32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "wevtutil.exe",
    "sc.exe",
    "net.exe",
    "net1.exe",
    "services.exe",
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "explorer.exe",
    "conhost.exe",
    "dllhost.exe",
}

_OFFICE_HOST_PROCESS_TOKENS = {
    "excel.exe",
    "winword.exe",
    "outlook.exe",
    "powerpnt.exe",
    "onenote.exe",
    "acrord32.exe",
    "acrord64.exe",
}

_SCRIPT_EXECUTION_HOST_TOKENS = {
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

_LURE_ARTIFACT_TERMS = {
    ".lnk",
    ".doc",
    ".docx",
    "docm",
    ".eml",
    ".pdf",
    ".zip",
    ".ppt",
    ".pptx",
    ".xls",
    ".xlsm",
    "content.inf",
    "hta",
}

_LURE_ARTIFACT_EXTENSION_TERMS = {
    ".lnk",
    ".doc",
    ".docx",
    "docm",
    ".eml",
    ".pdf",
    ".zip",
    ".ppt",
    ".pptx",
    ".xls",
    ".xlsm",
}

_LURE_ARTIFACT_EXECUTION_TERMS = {
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "wscript",
    "wscript.exe",
    "cscript",
    "cscript.exe",
    "mshta",
    "mshta.exe",
    "cmd",
    "cmd.exe",
    "rundll32",
    "rundll32.exe",
    "regsvr32",
    "regsvr32.exe",
    "hta",
}

_STRUCTURAL_HINT_STOPWORDS = {
    "windows",
    "microsoft",
    "software",
    "currentversion",
    "control",
    "system32",
    "system",
    "program",
    "programs",
    "users",
    "machine",
    "local",
    "process",
    "registry",
    "value",
    "event",
    "operational",
}


def _normalize_component_name(value: object) -> str:
    text = str(value or "").strip().lower().strip("\"'")
    if not text:
        return ""
    text = text.split("\\")[-1].split("/")[-1].strip().strip("\"'")
    return text


def _component_aliases(value: object) -> set[str]:
    normalized = _normalize_component_name(value)
    if not normalized:
        return set()
    aliases = {normalized}
    if "." in normalized:
        aliases.add(normalized.rsplit(".", 1)[0])
    else:
        aliases.add(f"{normalized}.exe")
    return aliases


@lru_cache(maxsize=1)
def _load_system_component_index() -> set[str]:
    whitelist_path = Path(__file__).resolve().parents[3] / "analyzing" / "global_whitelist.json"
    payload: dict[str, object] = {}

    if whitelist_path.exists():
        try:
            payload = json.loads(whitelist_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}

    components: set[str] = set()

    for key in (
        "system_components",
        "lolbins",
        "low_priority_system_processes",
    ):
        values = payload.get(key) if isinstance(payload, dict) else None
        if not isinstance(values, list):
            continue
        for raw in values:
            components.update(_component_aliases(raw))

    if not components:
        for value in _DEFAULT_SYSTEM_COMPONENTS:
            components.update(_component_aliases(value))

    return {component for component in components if component}


def _is_command_like_head(token: str, system_component_index: set[str]) -> bool:
    normalized = token.strip().lower().strip("\"'")
    if not normalized:
        return False
    if not _CORE_EFFECT_COMMAND_HEAD_RE.fullmatch(normalized):
        return False

    base = normalized[:-4] if normalized.endswith(".exe") else normalized
    if base in _STRICT_CORE_COMMAND_SEED_TERMS:
        return True

    aliases = _component_aliases(normalized)
    aliases.update(_component_aliases(base))
    return bool(aliases & system_component_index)


@lru_cache(maxsize=1)
def _load_strict_core_command_terms() -> set[str]:
    """Discover strict command terms from all clean_attack_tree core_effect lists.

    We only collect command-like *heads* (e.g. "net" from "net use") and
    standalone command terms. This keeps strict-boundary matching focused on
    system command tokens and avoids unrelated core_effect values.
    """
    strict_terms: set[str] = set(_STRICT_CORE_COMMAND_SEED_TERMS)
    system_components = _load_system_component_index()

    catalog_dir = Path(__file__).resolve().parents[3] / "inspect_log_gui" / "clean_attack_tree"
    if not catalog_dir.exists():
        return strict_terms

    for path in catalog_dir.glob("T*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            continue

        patterns = payload.get("patterns") if isinstance(payload, dict) else None
        core_effect = patterns.get("core_effect") if isinstance(patterns, dict) else None
        if not isinstance(core_effect, list):
            continue

        for raw_term in core_effect:
            term = str(raw_term or "").strip().lower()
            if not term or _is_extension_pattern(term):
                continue

            head = term.split()[0] if term.split() else ""
            if not head:
                continue
            if not _is_command_like_head(head, system_components):
                continue

            strict_terms.add(head)
            if head.endswith(".exe"):
                strict_terms.add(head[:-4])

    return strict_terms


def _normalize_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True).lower()
        except TypeError:
            return str(value).lower()
    return str(value).lower()


def _tokens(value: str) -> list[str]:
    return [token for token in _TOKEN_RE.findall(value.lower()) if len(token) >= 2]


def _term_tokens(value: str) -> list[str]:
    normalized = value.lower().replace("\\", " ").replace("/", " ").replace(":", " ")
    return [token for token in _TERM_TOKEN_RE.findall(normalized) if len(token) >= 2]


def _node_blob(node: GraphNode) -> str:
    parts = [node.id, node.label, node.node_type, node.group]
    for key, value in sorted(node.properties.items()):
        parts.append(key)
        parts.append(_normalize_text(value))
    return " ".join(parts).lower()


# Per-entity-type whitelist of property fields used for *pattern matching*.
# Restricting matching to semantically meaningful fields prevents noise like
# the literal string "Network" inside `properties.type` matching a core_effect
# term such as "net". The general-purpose `_node_blob` above is still used for
# graph-shape feature extraction where richer text is desirable.
_ENTITY_MATCH_FIELDS: dict[str, tuple[str, ...]] = {
    "process": (
        "process_name",
        "image_path",
        "command_line",
        "original_file_name",
    ),
    "file": (
        "file_path",
        "source_image_path",
    ),
    "registry": (
        "key_path",
        "value_name",
        "value_data",
        "source_image_path",
    ),
    "network": (
        "domain_name",
        "destination_ip",
        "destination_port",
    ),
    "user": (
        "username",
        "domain",
    ),
    "wmi": (
        "wmi_name",
        "wmi_namespace",
        "wmi_query",
        "wmi_payload",
        "wmi_filter_path",
        "wmi_consumer_path",
    ),
}


def _node_match_blob(node: GraphNode) -> str:
    """Restricted text blob used for pattern/core_effect matching only.

    Includes the human-readable label plus a per-entity-type whitelist of
    properties (see `_ENTITY_MATCH_FIELDS`). Excludes node.id (carries a type
    prefix), node_type, group, and `properties.type` to avoid matches against
    generic type strings (e.g. core term 'net' matching the type 'Network').
    """
    parts: list[str] = []
    if node.label:
        parts.append(str(node.label))

    node_type_key = (node.node_type or "").strip().lower()
    fields = _ENTITY_MATCH_FIELDS.get(node_type_key)

    if fields:
        for key in fields:
            value = node.properties.get(key)
            if value is None or value == "":
                continue
            parts.append(_normalize_text(value))
    else:
        # Unknown entity type: fall back to scanning only string-valued
        # properties whose key is not a generic descriptor.
        for key, value in sorted(node.properties.items()):
            if key.lower() in {"type", "node_type", "group", "id", "guid", "pid"}:
                continue
            if value is None or value == "":
                continue
            parts.append(_normalize_text(value))

    return " ".join(parts).lower()


def _term_matches_blob(term: str, blob: str) -> bool:
    normalized = term.strip().lower()
    if not normalized:
        return False
    if normalized in blob:
        return True

    slash_normalized = normalized.replace("\\", "/")
    slash_blob = blob.replace("\\", "/")
    if slash_normalized in slash_blob:
        return True

    significant = [token for token in _term_tokens(normalized) if len(token) >= 3]
    if not significant:
        return False
    blob_terms = set(_term_tokens(blob))
    return all(token in blob_terms or token in blob for token in significant[:6])


def _is_extension_pattern(term: str) -> bool:
    return bool(_EXTENSION_PATTERN_RE.fullmatch(term.strip().lower()))


def _is_strict_core_command_term(term: str) -> bool:
    return term.strip().lower() in _load_strict_core_command_terms()


def _extension_term_matches_blob(term: str, blob: str) -> bool:
    normalized = term.strip().lower()
    if not normalized:
        return False

    haystack = blob.lower()
    start = 0
    while True:
        idx = haystack.find(normalized, start)
        if idx < 0:
            return False
        follow_index = idx + len(normalized)
        if follow_index >= len(haystack):
            return True
        # Extension core terms (e.g. .sh) only count if the next character is
        # a separator/end, not part of a longer token (e.g. make.show).
        if not _EXTENSION_FOLLOW_CHAR_RE.match(haystack[follow_index]):
            return True
        start = idx + 1


def _strict_core_command_term_matches_blob(term: str, blob: str) -> bool:
    normalized = term.strip().lower()
    if not normalized:
        return False

    haystack = blob.lower()
    left_boundary_chars = {"\"", "'", "`", "(", "[", "{", ";", "&", "|", "\\", "/", ":", "="}
    start = 0
    while True:
        idx = haystack.find(normalized, start)
        if idx < 0:
            return False

        before_char = haystack[idx - 1] if idx > 0 else ""
        # Bare command terms must be standalone command tokens.
        # Disallow matches when preceded by '.' (e.g. domains like x.y.net).
        before_ok = idx == 0 or before_char.isspace() or before_char in left_boundary_chars
        follow_index = idx + len(normalized)
        after_ok = follow_index >= len(haystack) or haystack[follow_index].isspace()
        # For bare system command terms (net/cmd/powershell), require token-like
        # boundaries and only space/end after the term to avoid false matches
        # such as "network".
        if before_ok and after_ok:
            return True

        start = idx + 1


def _is_core_effect_boundary_char(char: str) -> bool:
    if not char:
        return True
    if char.isspace():
        return True
    # Dot is not treated as a separator for standalone core_effect matches.
    if char == ".":
        return False
    return not ("a" <= char <= "z" or "0" <= char <= "9")


def _independent_core_effect_term_matches_blob(term: str, blob: str) -> bool:
    normalized = term.strip().lower()
    if not normalized:
        return False

    haystack = blob.lower()
    start = 0
    while True:
        idx = haystack.find(normalized, start)
        if idx < 0:
            return False

        before_char = haystack[idx - 1] if idx > 0 else ""
        after_index = idx + len(normalized)
        after_char = haystack[after_index] if after_index < len(haystack) else ""

        # core_effect hits must be standalone in context (not embedded inside
        # alphanumeric/dot tokens such as "runtime" or "run.exe").
        if _is_core_effect_boundary_char(before_char) and _is_core_effect_boundary_char(after_char):
            return True

        start = idx + 1


def _phrase_core_effect_term_matches_blob(term: str, blob: str) -> bool:
    normalized = re.sub(r"\s+", " ", term.strip().lower())
    if not normalized:
        return False

    # Split phrase terms with the same token normalization used by term
    # scanners so declarations like "schtasks \\create" stay matchable.
    phrase_parts = [part for part in _term_tokens(normalized) if part]
    if len(phrase_parts) <= 1:
        return _independent_core_effect_term_matches_blob(normalized, blob)

    # Keep phrase semantics intact while tolerating formatting differences
    # between command renderings (extra spaces, quotes, separators).
    joiner = r"(?:[\s\"'`\\/:;=,()\[\]{}\-_.]*)"
    part_patterns = [re.escape(part) for part in phrase_parts]

    # Command heads in core_effect phrases are often declared without suffix
    # (e.g. "wevtutil cl system") while logs can contain ".exe".
    first = phrase_parts[0]
    if "." not in first and _is_command_like_head(first, _load_system_component_index()):
        part_patterns[0] = rf"{re.escape(first)}(?:\.exe)?"

    phrase_pattern = joiner.join(part_patterns)
    pattern = re.compile(rf"(?<![a-z0-9.]){phrase_pattern}(?![a-z0-9.])")
    return bool(pattern.search(blob.lower()))


def _core_effect_term_matches_blob(term: str, blob: str) -> bool:
    normalized = term.strip().lower()
    if not normalized:
        return False
    if _is_extension_pattern(normalized):
        return _extension_term_matches_blob(normalized, blob)
    if _is_strict_core_command_term(normalized):
        return _strict_core_command_term_matches_blob(normalized, blob)
    if " " in normalized:
        return _phrase_core_effect_term_matches_blob(normalized, blob)
    return _independent_core_effect_term_matches_blob(normalized, blob)


def _weighted_jaccard(a: Counter[str], b: Counter[str]) -> float:
    keys = set(a.keys()) | set(b.keys())
    if not keys:
        return 0.0
    numerator = sum(min(a.get(key, 0.0), b.get(key, 0.0)) for key in keys)
    denominator = sum(max(a.get(key, 0.0), b.get(key, 0.0)) for key in keys)
    if denominator <= 0:
        return 0.0
    return float(numerator / denominator)


def _bucket(value: int) -> str:
    if value <= 0:
        return "0"
    if value == 1:
        return "1"
    if value <= 3:
        return "2-3"
    if value <= 7:
        return "4-7"
    return "8+"


def _term_specificity(term: str) -> float:
    normalized = str(term or "").strip().lower()
    if not normalized:
        return 0.0

    tokens = _term_tokens(normalized)
    if not tokens:
        return 0.0

    if len(tokens) == 1:
        token = tokens[0]
        if "-" in token and any(
            token.startswith(prefix)
            for prefix in ("clear-", "get-", "set-", "remove-", "new-", "invoke-")
        ):
            return 0.95
        if token in {"powershell", "cmd", "reg", "sc", "net", "program"}:
            return 0.18
        if re.fullmatch(r"[0-9a-f]{4,8}", token):
            return 0.20
        if token.endswith(".exe"):
            return 0.45
        return 0.30

    weight = 0.55 + min(0.65, 0.10 * len(tokens))
    if any(token.endswith(".exe") for token in tokens):
        weight += 0.25
    if any(token in {"create", "query", "add", "delete", "save", "dump", "lsass", "wdigest"} for token in tokens):
        weight += 0.30
    if "\\" in normalized or "/" in normalized:
        weight += 0.15
    return min(1.5, weight)


def _term_concrete_behavior_weight(term: str) -> float:
    normalized = str(term or "").strip().lower()
    tokens = set(_term_tokens(normalized))
    if not tokens:
        return 0.0

    strong_indicators = {
        "mimikatz.exe",
        "procdump.exe",
        "procdump64.exe",
        "notprocdump.exe",
        "notprocdump64.exe",
        "outflank-dumpert.exe",
        "pypykatz",
        "lsass",
        "lsass.exe",
        "lsass.dmp",
        "wdigest",
        "uselogoncredential",
    }
    if tokens & strong_indicators:
        return 1.0

    if "clear-eventlog" in tokens:
        return 1.0

    powershell_hosts = {
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "windowspowershell",
        "windowspowershell.exe",
    }
    encoded_exec_tokens = {
        "encodedcommand",
        "frombase64string",
        "invoke-expression",
        "iex",
        "decoded_b64",
        "ps_bypass_flag",
    }
    policy_tokens = {"executionpolicy", "bypass", "unrestricted"}
    stealth_tokens = {"noprofile", "noninteractive", "windowstyle", "hidden"}

    if "frombase64string" in tokens and ("invoke-expression" in tokens or "iex" in tokens):
        return 1.0
    if tokens & {"decoded_b64", "ps_bypass_flag"}:
        return 0.95
    if (tokens & powershell_hosts) and (tokens & encoded_exec_tokens):
        return 0.95
    if tokens & {"encodedcommand", "frombase64string", "invoke-expression", "iex"}:
        return 0.85
    if "executionpolicy" in tokens and (tokens & {"bypass", "unrestricted"}):
        return 0.72
    if (tokens & powershell_hosts) and (tokens & stealth_tokens):
        return 0.65
    if tokens & policy_tokens and (tokens & powershell_hosts):
        return 0.60

    action_tokens = {"create", "query", "add", "delete", "save", "dump", "cl", "clear"}
    tool_tokens = {
        "reg",
        "reg.exe",
        "schtasks",
        "schtasks.exe",
        "wevtutil",
        "wevtutil.exe",
        "ntdsutil",
        "ntdsutil.exe",
        "clear-eventlog",
    }
    if ("schtasks" in tokens or "schtasks.exe" in tokens) and ("create" in tokens or "query" in tokens):
        return 1.0
    if ("wevtutil" in tokens or "wevtutil.exe" in tokens) and ("cl" in tokens or "clear" in tokens):
        return 1.0
    if ("reg" in tokens or "reg.exe" in tokens) and tokens & action_tokens:
        return 0.95 if len(tokens) >= 4 else 0.25
    if tokens & action_tokens and tokens & tool_tokens:
        return 1.0

    if "softwareinventorylogging" in tokens and ("reg" in tokens or "reg.exe" in tokens):
        return 0.9

    if tokens & action_tokens and len(tokens) >= 3:
        return 0.55

    return 0.0


def _core_effect_term_confidence(term: str) -> float:
    normalized = str(term or "").strip().lower()
    if not normalized:
        return 0.0

    tokens = _term_tokens(normalized)
    specificity = _term_specificity(normalized)
    concrete = _term_concrete_behavior_weight(normalized)
    confidence = specificity + (0.55 * concrete)

    # Single-token core terms are often generic (e.g. wmi, run, port).
    # Downweight unless reinforced by concrete behavior semantics.
    if len(tokens) == 1 and concrete <= 0.0:
        confidence *= 0.72

    if _is_extension_pattern(normalized):
        confidence *= 0.70

    return max(0.05, min(1.60, confidence))


def _core_effect_evidence_strength(terms: Iterable[str]) -> dict[str, float]:
    """Compute evidence strength from matched core_effect terms only.

    This intentionally avoids "hit/total declared" normalization because
    clean attack trees can aggregate variants and partial slices of behavior.
    """
    normalized_terms = [str(term or "").strip().lower() for term in terms]
    normalized_terms = [term for term in normalized_terms if term]
    if not normalized_terms:
        return {
            "hit_saturation": 0.0,
            "confidence_strength": 0.0,
            "evidence_strength": 0.0,
            "max_confidence": 0.0,
        }

    confidences = sorted(
        (_core_effect_term_confidence(term) for term in normalized_terms),
        reverse=True,
    )
    hits = len(confidences)

    # Diminishing-return count factor: first hits matter most, then saturate.
    hit_saturation = 1.0 - (0.58 ** hits)

    # Weighted confidence emphasizes the strongest matched terms while still
    # accounting for additional evidence.
    weighted_total = 0.0
    weight_sum = 0.0
    for index, confidence in enumerate(confidences[:6]):
        weight = 1.0 / (1.0 + (0.65 * index))
        weighted_total += confidence * weight
        weight_sum += weight

    weighted_confidence = (weighted_total / weight_sum) if weight_sum > 0 else 0.0
    confidence_strength = max(0.0, min(1.0, weighted_confidence / 1.60))
    evidence_strength = (0.42 * hit_saturation) + (0.58 * confidence_strength)

    return {
        "hit_saturation": hit_saturation,
        "confidence_strength": confidence_strength,
        "evidence_strength": evidence_strength,
        "max_confidence": max(confidences, default=0.0),
    }


class BehavioralAnchorFusionMatcher(BaseMatcher):
    name = "behavioral_anchor_fusion"

    def __init__(
        self,
        anchor_depth: int = 2,
        system_component_min_ratio: float = 0.50,
        max_matched_nodes: int = 160,
        structure_precision_soft_floor: float = 0.44,
        structure_precision_hard_floor: float = 0.28,
    ) -> None:
        self.anchor_depth = anchor_depth
        self.system_component_min_ratio = max(0.10, min(1.0, float(system_component_min_ratio or 0.50)))
        self.max_matched_nodes = max(20, int(max_matched_nodes or 20))
        self.structure_precision_soft_floor = max(
            0.30,
            min(0.90, float(structure_precision_soft_floor or 0.52)),
        )
        self.structure_precision_hard_floor = max(
            0.15,
            min(self.structure_precision_soft_floor - 0.04, float(structure_precision_hard_floor or 0.28)),
        )
        self.system_component_index = _load_system_component_index()
        self._target_cache_identity: tuple[int, int, int] | None = None
        self._target_runtime_cache: dict[str, object] = {}
        self._pattern_profile_cache: dict[str, dict[str, object]] = {}
        self._structural_signature_cache: dict[
            tuple[int, int, int, bool],
            tuple[list[tuple[str, int, str, bool]], list[str]],
        ] = {}
        self._execution_component_cache: dict[tuple[int, int, int], list[set[str]]] = {}

    def _graph_identity(self, graph: GraphData) -> tuple[int, int, int]:
        return (id(graph), len(graph.nodes), len(graph.edges))

    def _get_target_runtime_cache(self, graph: GraphData) -> dict[str, object]:
        identity = self._graph_identity(graph)
        if self._target_cache_identity == identity and self._target_runtime_cache:
            return self._target_runtime_cache

        node_match_blobs: dict[str, str] = {}
        node_tokens: dict[str, list[str]] = {}
        node_system_components: dict[str, set[str]] = {}
        for node_id, node in graph.nodes.items():
            node_match_blobs[node_id] = _node_match_blob(node)
            node_tokens[node_id] = [token for token in _tokens(_node_blob(node)) if len(token) > 2]
            node_system_components[node_id] = self._node_system_components(node)

        cache = {
            "node_match_blobs": node_match_blobs,
            "node_tokens": node_tokens,
            "node_system_components": node_system_components,
            "degree_map": self._degree_map(graph.edges),
        }
        self._target_cache_identity = identity
        self._target_runtime_cache = cache
        return cache

    def _get_pattern_profile(
        self,
        pattern_graph: GraphData,
        malicious_patterns: list[str],
        core_effect_patterns: list[str],
    ) -> dict[str, object]:
        profile_key = (
            f"{pattern_graph.technique}|{pattern_graph.name}|"
            f"{len(pattern_graph.nodes)}|{len(pattern_graph.edges)}"
        )
        cached_profile = self._pattern_profile_cache.get(profile_key)
        if cached_profile is not None:
            return cached_profile

        pattern_anchor_ids = self._pattern_anchor_ids(pattern_graph, malicious_patterns)
        pattern_core_anchor_ids = self._pattern_core_effect_ids(pattern_graph, core_effect_patterns)
        pattern_focus_nodes = set(pattern_anchor_ids)
        pattern_focus_nodes.update(pattern_core_anchor_ids)

        pattern_features = self._extract_features(pattern_graph, pattern_anchor_ids)
        pattern_system_components = set(pattern_features["system_components"])
        pattern_system_components.update(self._terms_system_components(malicious_patterns))

        profile = {
            "pattern_anchor_ids": set(pattern_anchor_ids),
            "pattern_core_anchor_ids": set(pattern_core_anchor_ids),
            "pattern_focus_nodes": set(pattern_focus_nodes),
            "pattern_features": pattern_features,
            "pattern_system_components": set(pattern_system_components),
        }

        if len(self._pattern_profile_cache) > 1024:
            self._pattern_profile_cache.clear()
        self._pattern_profile_cache[profile_key] = profile
        return profile

    def _cached_structural_signature_entries(
        self,
        graph: GraphData,
        include_semantic_hint: bool,
    ) -> tuple[list[tuple[str, int, str, bool]], list[str]]:
        key = (*self._graph_identity(graph), bool(include_semantic_hint))
        cached = self._structural_signature_cache.get(key)
        if cached is not None:
            return cached

        computed = self._structural_signature_entries(
            graph,
            include_semantic_hint=include_semantic_hint,
        )
        if len(self._structural_signature_cache) > 4096:
            self._structural_signature_cache.clear()
        self._structural_signature_cache[key] = computed
        return computed

    def match(self, target_graph: GraphData, pattern_graph: GraphData) -> TechniqueMatch:
        start = perf_counter()

        malicious_patterns = self._extract_patterns(pattern_graph)
        core_effect_patterns = self._extract_core_effect(pattern_graph)
        target_cache = self._get_target_runtime_cache(target_graph)
        target_evidence = self._scan_pattern_terms(
            target_graph,
            malicious_patterns,
            core_effect_patterns,
            node_blobs=target_cache.get("node_match_blobs"),
        )
        matched_malicious_terms = set(target_evidence.get("malicious_terms") or set())
        matched_core_terms = set(target_evidence.get("core_effect_terms") or set())

        if not matched_malicious_terms and not matched_core_terms:
            elapsed_ms = (perf_counter() - start) * 1000
            notes = (
                "Behavioral anchor fusion fast-exit: no malicious/core term overlap. "
                f"patterns=0/{len(malicious_patterns)}, "
                f"core_effect_hits=0 declared={len(core_effect_patterns)}"
            )
            return TechniqueMatch(
                algorithm=self.name,
                technique=pattern_graph.technique,
                score=0.0,
                runtime_ms=elapsed_ms,
                matched_node_ids=[],
                notes=notes,
            )

        pattern_profile = self._get_pattern_profile(
            pattern_graph,
            malicious_patterns,
            core_effect_patterns,
        )
        pattern_anchor_ids = set(pattern_profile["pattern_anchor_ids"])
        pattern_focus_nodes = set(pattern_profile["pattern_focus_nodes"])
        structure_focus_nodes = set(target_evidence.get("malicious_node_ids") or set())
        structure_focus_nodes.update(target_evidence.get("core_effect_node_ids") or set())
        structure_evidence = self._structural_consistency(
            target_graph,
            pattern_graph,
            preferred_node_ids=structure_focus_nodes,
            pattern_focus_node_ids=pattern_focus_nodes,
        )
        structure_precision = float(structure_evidence["precision"])
        structure_semantic_coverage = float(structure_evidence["semantic_coverage"])
        structure_type_coverage = float(structure_evidence["type_coverage"])
        structure_root_coverage = float(structure_evidence["root_semantic_coverage"])
        structure_purity = float(structure_evidence.get("purity") or 0.0)
        structure_focus_coverage = float(structure_evidence.get("focus_coverage") or 0.0)
        structure_component_focus_overlap = float(
            structure_evidence.get("component_focus_overlap") or 0.0
        )
        structure_focus_alignment = max(
            structure_focus_coverage,
            0.70 * structure_component_focus_overlap,
        )

        target_features = self._extract_features(
            target_graph,
            target_evidence["malicious_node_ids"],
            precomputed=target_cache,
        )
        pattern_features = pattern_profile["pattern_features"]

        object_score = _weighted_jaccard(target_features["object"], pattern_features["object"])
        relation_score = _weighted_jaccard(target_features["relation"], pattern_features["relation"])
        shape_score = _weighted_jaccard(target_features["shape"], pattern_features["shape"])
        anchor_score = _weighted_jaccard(target_features["anchor"], pattern_features["anchor"])
        system_relation_score = _weighted_jaccard(
            target_features["system_relation"],
            pattern_features["system_relation"],
        )

        pattern_system_components = set(pattern_profile["pattern_system_components"])
        target_system_components = set(target_features["system_components"])
        system_overlap = sorted(pattern_system_components & target_system_components)
        system_component_ratio = self._system_component_ratio(pattern_system_components, system_overlap)
        system_gate = self._system_gate_factor(system_component_ratio, bool(pattern_system_components))

        pattern_score = self._pattern_score(target_evidence, len(malicious_patterns))
        pattern_support = self._pattern_support(target_evidence)
        concrete_score = self._concrete_behavior_score(target_evidence)
        strongest_concrete = self._strongest_matched_concrete(target_evidence)
        supported_pattern_score_raw = pattern_score * pattern_support
        shared_behavior_terms = matched_malicious_terms & matched_core_terms
        if shared_behavior_terms:
            shared_strength_payload = _core_effect_evidence_strength(shared_behavior_terms)
            shared_behavior_strength = float(shared_strength_payload.get("evidence_strength") or 0.0)
        else:
            shared_behavior_strength = 0.0
        shared_behavior_support = max(
            0.0,
            min(
                1.0,
                shared_behavior_strength * (0.55 + (0.45 * concrete_score)),
            ),
        )
        shared_pattern_bonus = 0.18 * shared_behavior_support
        supported_pattern_score = min(1.0, supported_pattern_score_raw + shared_pattern_bonus)
        artifact_execution_lure_strength = self._artifact_execution_lure_strength(
            target_evidence,
            target_cache.get("node_match_blobs"),
        )
        adaptive_system_ratio_requirement = max(
            0.30,
            min(0.55, 0.55 - (0.45 * shared_behavior_support)),
        )

        fused_score = (
            0.48 * supported_pattern_score
            + 0.12 * anchor_score
            + 0.06 * object_score
            + 0.05 * relation_score
            + 0.03 * shape_score
            + 0.06 * system_relation_score
            + 0.08 * concrete_score
            + 0.12 * structure_precision
        )

        if malicious_patterns:
            fused_score *= 0.20 + (0.80 * (supported_pattern_score ** 2))
            if not target_evidence["malicious_terms"]:
                fused_score *= 0.02
            elif concrete_score <= 0.0:
                fused_score *= 0.20
            elif strongest_concrete < 0.50:
                fused_score *= 0.65
            elif strongest_concrete >= 0.90:
                fused_score += 0.06 * strongest_concrete

        fused_score *= system_gate

        core_terms_total = len(core_effect_patterns)
        core_terms_matched = set(matched_core_terms)
        core_hits = len(core_terms_matched)
        core_strength = _core_effect_evidence_strength(core_terms_matched)
        core_hit_saturation = float(core_strength["hit_saturation"])
        core_confidence_strength = float(core_strength["confidence_strength"])
        core_boost_ratio = float(core_strength["evidence_strength"])
        core_max_confidence = float(core_strength["max_confidence"])
        behavioral_confirmation_strength = max(
            0.0,
            min(
                1.0,
                (0.46 * supported_pattern_score)
                + (0.24 * concrete_score)
                + (0.18 * core_boost_ratio)
                + (0.07 * system_component_ratio)
                + (0.05 * strongest_concrete),
            ),
        )
        system_alignment_ok = (not pattern_system_components) or (system_component_ratio >= 0.18)
        if core_terms_total == 1:
            # Single-core catalogs are highly sensitive to generic tokens.
            # Require stronger intrinsic term confidence before allowing
            # confirmation-floor behavior.
            core_confirmation_eligible = (
                core_hits == 1
                and core_max_confidence >= 0.60
            )
        else:
            core_confirmation_eligible = (
                core_hits >= 2
                or core_boost_ratio >= 0.70
                or core_max_confidence >= 0.85
            )
        structure_gate = self._structure_gate_factor(
            structure_precision,
            structure_purity,
            core_terms_total > 0,
            focus_alignment=structure_focus_alignment,
            core_evidence_strength=core_boost_ratio,
            component_focus_overlap=structure_component_focus_overlap,
        )
        fused_score *= structure_gate
        core_mode = "not_declared"

        if core_terms_total > 0:
            if core_hits == 0:
                fused_score *= 0.05
                core_mode = "declared_no_hit"
            else:
                weak_structure = structure_precision < self.structure_precision_hard_floor
                partial_structure = structure_precision < self.structure_precision_soft_floor

                if weak_structure:
                    variant_focus_alignment = max(
                        structure_focus_alignment,
                        0.85 * structure_component_focus_overlap,
                    )
                    normalized_precision = max(
                        0.0,
                        min(1.0, structure_precision / max(self.structure_precision_hard_floor, 1e-6)),
                    )
                    weak_penalty = (
                        0.52
                        + (0.30 * normalized_precision)
                        + (0.10 * structure_purity)
                        + (0.12 * variant_focus_alignment)
                        + (0.06 * core_boost_ratio)
                    )
                    fused_score *= max(0.30, min(0.95, weak_penalty))

                    recovery_bonus = (
                        0.03
                        * core_boost_ratio
                        * (0.40 + (0.60 * supported_pattern_score))
                        * (0.80 + (0.20 * variant_focus_alignment))
                    )
                    fused_score = min(1.0, fused_score + recovery_bonus)

                    fragmented_confirmation = (
                        core_confirmation_eligible
                        and supported_pattern_score >= 0.40
                        and concrete_score >= 0.35
                        and structure_purity >= 0.35
                        and system_alignment_ok
                        and variant_focus_alignment >= 0.20
                        and (core_hits >= 2 or core_boost_ratio >= 0.80)
                    )
                    core_behavioral_confirmation = (
                        core_confirmation_eligible
                        and core_hits >= 2
                        and core_confidence_strength >= 0.75
                        and pattern_support >= 0.70
                        and supported_pattern_score >= 0.20
                        and concrete_score >= 0.45
                        and strongest_concrete >= 0.90
                        and (structure_precision >= 0.12 or structure_focus_alignment >= 0.34)
                        and structure_purity >= 0.45
                        and system_component_ratio >= adaptive_system_ratio_requirement
                    )
                    if fragmented_confirmation or core_behavioral_confirmation:
                        fragmented_floor = (
                            0.10
                            + (0.22 * behavioral_confirmation_strength)
                            + (0.07 * core_boost_ratio)
                            + (0.07 * supported_pattern_score)
                            + (0.06 * structure_precision)
                            + (0.04 * structure_purity)
                            + (0.04 * system_component_ratio)
                            + (0.04 * variant_focus_alignment)
                            + (0.04 * shared_behavior_support)
                        )
                        if core_behavioral_confirmation:
                            fragmented_floor = max(
                                fragmented_floor,
                                0.18
                                + (0.14 * behavioral_confirmation_strength)
                                + (0.08 * core_boost_ratio)
                                + (0.05 * pattern_support)
                                + (0.04 * supported_pattern_score)
                                + (0.05 * structure_precision)
                                + (0.05 * structure_purity)
                                + (0.05 * system_component_ratio)
                                + (0.04 * variant_focus_alignment)
                            )
                        if strongest_concrete >= 0.90:
                            fragmented_floor += 0.02
                        if core_hits >= 3:
                            fragmented_floor += 0.02

                        # Fragmented execution trees can still be high-confidence
                        # true positives when core evidence is dense and concrete.
                        fragmented_high_signal_confirmation = (
                            core_confirmation_eligible
                            and core_hits >= 4
                            and core_hit_saturation >= 0.85
                            and core_boost_ratio >= 0.65
                            and pattern_support >= 0.85
                            and supported_pattern_score >= 0.48
                            and concrete_score >= 0.55
                            and strongest_concrete >= 0.90
                            and structure_purity >= 0.50
                            and variant_focus_alignment >= 0.70
                            and structure_component_focus_overlap >= 0.80
                            and system_component_ratio >= 0.20
                        )
                        if fragmented_high_signal_confirmation:
                            fragmented_floor = max(
                                fragmented_floor,
                                0.26
                                + (0.20 * behavioral_confirmation_strength)
                                + (0.12 * core_boost_ratio)
                                + (0.10 * supported_pattern_score)
                                + (0.08 * concrete_score)
                                + (0.06 * structure_purity)
                                + (0.06 * variant_focus_alignment)
                                + (0.04 * system_component_ratio)
                                + (0.05 * shared_behavior_support)
                                + (0.03 if core_hits >= 6 else 0.0)
                                + (0.02 if core_hit_saturation >= 0.95 else 0.0)
                                + (0.02 if core_behavioral_confirmation else 0.0)
                            )

                        fragmented_cohesive_confirmation = (
                            core_confirmation_eligible
                            and core_hits >= 3
                            and core_hit_saturation >= 0.75
                            and core_boost_ratio >= 0.55
                            and pattern_support >= 0.90
                            and supported_pattern_score >= 0.36
                            and concrete_score >= 0.60
                            and strongest_concrete >= 0.90
                            and structure_purity >= 0.55
                            and variant_focus_alignment >= 0.80
                            and structure_component_focus_overlap >= 0.90
                            and system_component_ratio >= 0.50
                            and shared_behavior_support >= 0.45
                        )
                        if fragmented_cohesive_confirmation:
                            fragmented_floor = max(
                                fragmented_floor,
                                0.20
                                + (0.16 * behavioral_confirmation_strength)
                                + (0.09 * core_boost_ratio)
                                + (0.06 * supported_pattern_score)
                                + (0.05 * concrete_score)
                                + (0.05 * structure_purity)
                                + (0.05 * variant_focus_alignment)
                                + (0.04 * system_component_ratio)
                                + (0.08 * shared_behavior_support)
                                + (0.02 if core_hit_saturation >= 0.90 else 0.0)
                                + (0.02 if core_hits >= 4 else 0.0)
                            )

                        core_effect_dominant_confirmation = (
                            core_confirmation_eligible
                            and core_hits >= 3
                            and core_hit_saturation >= 0.75
                            and core_boost_ratio >= 0.60
                            and core_confidence_strength >= 0.50
                            and behavioral_confirmation_strength >= 0.55
                            and pattern_support >= 0.95
                            and supported_pattern_score >= 0.45
                            and concrete_score >= 0.65
                            and strongest_concrete >= 0.95
                            and structure_precision >= max(0.20, 0.72 * self.structure_precision_hard_floor)
                            and structure_purity >= 0.55
                            and variant_focus_alignment >= 0.80
                            and structure_component_focus_overlap >= 0.95
                            and system_component_ratio >= 0.50
                            and shared_behavior_support >= 0.50
                        )
                        if core_effect_dominant_confirmation:
                            core_effect_dominant_floor = (
                                0.30
                                + (0.18 * behavioral_confirmation_strength)
                                + (0.13 * core_boost_ratio)
                                + (0.09 * core_confidence_strength)
                                + (0.08 * supported_pattern_score)
                                + (0.06 * concrete_score)
                                + (0.05 * shared_behavior_support)
                                + (0.04 * system_component_ratio)
                                + (0.03 * structure_precision)
                                + (0.03 * structure_purity)
                                + (0.03 if core_hits >= 4 else 0.0)
                                + (0.02 if core_hit_saturation >= 0.90 else 0.0)
                            )
                            fragmented_floor = max(
                                fragmented_floor,
                                min(0.78, core_effect_dominant_floor),
                            )

                        fused_score = max(fused_score, fragmented_floor)
                        core_mode = (
                            "core_hit_behaviorally_confirmed"
                            if core_behavioral_confirmation
                            else (
                                "core_hit_core_effect_dominant"
                                if core_effect_dominant_confirmation
                                else (
                                    "core_hit_supported_fragmented_structure_high_signal"
                                    if fragmented_high_signal_confirmation
                                    else "core_hit_supported_fragmented_structure"
                                )
                            )
                        )
                    else:
                        variant_focus_confirmation = (
                            core_confirmation_eligible
                            and core_hits >= 2
                            and supported_pattern_score >= 0.34
                            and concrete_score >= 0.32
                            and strongest_concrete >= 0.60
                            and structure_component_focus_overlap >= 0.75
                            and structure_purity >= 0.45
                            and system_component_ratio >= 0.20
                        )
                        if variant_focus_confirmation:
                            variant_focus_floor = (
                                0.10
                                + (0.16 * behavioral_confirmation_strength)
                                + (0.06 * core_boost_ratio)
                                + (0.05 * supported_pattern_score)
                                + (0.04 * structure_precision)
                                + (0.05 * structure_purity)
                                + (0.08 * structure_component_focus_overlap)
                                + (0.04 * system_component_ratio)
                                + (0.05 * shared_behavior_support)
                            )
                            if strongest_concrete >= 0.90:
                                variant_focus_floor += 0.02
                            if core_hits >= 3:
                                variant_focus_floor += 0.02
                            fused_score = max(fused_score, min(0.52, variant_focus_floor))
                            core_mode = "core_hit_supported_variant_focus"
                        else:
                            focus_supported_confirmation = (
                                core_confirmation_eligible
                                and core_hits >= 2
                                and core_confidence_strength >= 0.75
                                and supported_pattern_score >= 0.20
                                and concrete_score >= 0.45
                                and strongest_concrete >= 0.90
                                and structure_focus_alignment >= 0.60
                                and structure_purity >= 0.50
                                and system_component_ratio >= 0.35
                            )
                            if focus_supported_confirmation:
                                focus_supported_floor = (
                                    0.05
                                    + (0.08 * behavioral_confirmation_strength)
                                    + (0.04 * core_boost_ratio)
                                    + (0.03 * supported_pattern_score)
                                    + (0.02 * structure_precision)
                                    + (0.03 * structure_purity)
                                    + (0.03 * structure_focus_alignment)
                                    + (0.02 * system_component_ratio)
                                    + (0.04 * shared_behavior_support)
                                )
                                focus_supported_cap = min(
                                    0.42,
                                    0.18
                                    + (0.26 * shared_behavior_support)
                                    + (0.08 * core_boost_ratio),
                                )
                                focus_supported_floor = min(focus_supported_cap, focus_supported_floor)
                                fused_score = max(fused_score, focus_supported_floor)
                                core_mode = "core_hit_supported_focus_structure"
                            else:
                                single_core_shared_confirmation = (
                                    core_hits == 1
                                    and supported_pattern_score >= 0.30
                                    and pattern_support >= 0.95
                                    and shared_behavior_support >= 0.16
                                    and core_max_confidence >= 0.28
                                    and structure_purity >= 0.55
                                    and structure_component_focus_overlap >= 0.90
                                    and variant_focus_alignment >= 0.70
                                    and system_component_ratio
                                    >= max(0.28, adaptive_system_ratio_requirement - 0.05)
                                )
                                if single_core_shared_confirmation:
                                    single_core_shared_floor = (
                                        0.10
                                        + (0.14 * behavioral_confirmation_strength)
                                        + (0.06 * core_boost_ratio)
                                        + (0.08 * supported_pattern_score)
                                        + (0.13 * shared_behavior_support)
                                        + (0.07 * structure_purity)
                                        + (0.06 * structure_component_focus_overlap)
                                        + (0.04 * system_component_ratio)
                                        + (0.03 * core_confidence_strength)
                                        + (0.02 * variant_focus_alignment)
                                    )
                                    if strongest_concrete >= 0.90:
                                        single_core_shared_floor += 0.02
                                    fused_score = max(
                                        fused_score,
                                        min(0.46, single_core_shared_floor),
                                    )
                                    core_mode = "core_hit_supported_shared_behavior"
                                else:
                                    core_mode = "core_hit_blocked_by_structure"
                elif partial_structure or not core_confirmation_eligible:
                    additive_bonus = 0.04 * core_boost_ratio * (0.55 + 0.45 * structure_precision)
                    fused_score = min(1.0, fused_score + additive_bonus)
                    fragmented_partial_confirmation = (
                        partial_structure
                        and core_confirmation_eligible
                        and core_hits >= 2
                        and supported_pattern_score >= 0.72
                        and concrete_score >= 0.65
                        and system_alignment_ok
                        and system_component_ratio >= 0.20
                        and structure_purity >= 0.45
                        and structure_focus_alignment >= 0.16
                    )
                    if fragmented_partial_confirmation:
                        fragmented_partial_floor = (
                            0.11
                            + (0.20 * behavioral_confirmation_strength)
                            + (0.06 * core_boost_ratio)
                            + (0.06 * supported_pattern_score)
                            + (0.07 * structure_precision)
                            + (0.04 * structure_purity)
                            + (0.03 * system_component_ratio)
                            + (0.04 * structure_focus_alignment)
                        )
                        if strongest_concrete >= 0.90:
                            fragmented_partial_floor += 0.02
                        fused_score = max(fused_score, fragmented_partial_floor)
                        core_mode = "core_hit_supported_fragmented_structure"
                    else:
                        artifact_core_density_ok = (
                            core_hits >= 3
                            or (
                                core_hits >= 2
                                and core_hit_saturation >= 0.60
                                and core_boost_ratio >= 0.30
                                and pattern_support >= 0.95
                                and supported_pattern_score >= 0.50
                                and shared_behavior_support >= 0.20
                                and artifact_execution_lure_strength >= 0.95
                            )
                        )
                        artifact_system_alignment_ok = (
                            system_alignment_ok
                            or (
                                artifact_execution_lure_strength >= 0.95
                                and system_component_ratio >= 0.16
                                and pattern_support >= 0.95
                                and shared_behavior_support >= 0.20
                                and structure_component_focus_overlap >= 0.98
                            )
                        )
                        artifact_execution_confirmation = (
                            partial_structure
                            and core_confirmation_eligible
                            and artifact_core_density_ok
                            and pattern_support >= 0.90
                            and supported_pattern_score >= 0.45
                            and shared_behavior_support >= 0.20
                            and structure_precision >= self.structure_precision_hard_floor
                            and structure_purity >= 0.60
                            and structure_component_focus_overlap >= 0.90
                            and artifact_system_alignment_ok
                            and system_component_ratio >= 0.16
                            and strongest_concrete < 0.50
                            and artifact_execution_lure_strength >= 0.65
                        )
                        if artifact_execution_confirmation:
                            artifact_execution_floor = (
                                0.18
                                + (0.18 * supported_pattern_score)
                                + (0.08 * pattern_support)
                                + (0.07 * core_boost_ratio)
                                + (0.06 * structure_precision)
                                + (0.07 * structure_purity)
                                + (0.07 * structure_component_focus_overlap)
                                + (0.04 * system_component_ratio)
                                + (0.17 * artifact_execution_lure_strength)
                                + (0.06 * shared_behavior_support)
                            )
                            if core_hits >= 4:
                                artifact_execution_floor += 0.02
                            if artifact_execution_lure_strength >= 0.85:
                                artifact_execution_floor += 0.02
                            fused_score = max(fused_score, min(0.72, artifact_execution_floor))
                            core_mode = "core_hit_supported_artifact_execution"
                        else:
                            core_mode = (
                                "core_hit_limited_by_structure"
                                if partial_structure
                                else "core_hit_limited_by_core_quality"
                            )
                else:
                    confirmation_floor = (
                        0.26
                        + (0.16 * core_boost_ratio)
                        + (0.18 * structure_precision)
                        + (0.05 * structure_purity)
                        + (0.06 * structure_focus_alignment)
                    )
                    if strongest_concrete >= 0.90:
                        confirmation_floor += 0.04
                    additive_bonus = 0.07 * core_boost_ratio * structure_precision
                    fused_score = max(fused_score, confirmation_floor)
                    fused_score = min(1.0, fused_score + additive_bonus)
                    core_mode = "core_hit_confirmed_with_structure"

        score = max(0.0, min(1.0, fused_score))

        matched_node_ids = self._matched_node_ids(
            target_graph,
            target_evidence["malicious_node_ids"],
            target_features["node_scores"],
            core_node_ids=target_evidence.get("core_effect_node_ids"),
            structural_node_ids=structure_evidence.get("matched_node_ids"),
        )
        elapsed_ms = (perf_counter() - start) * 1000

        expected_system_preview = ", ".join(sorted(pattern_system_components)[:6]) or "-"
        overlap_system_preview = ", ".join(system_overlap[:6]) or "-"
        structure_segment = (
            f"structure={structure_precision:.3f} "
            f"(semantic={structure_semantic_coverage:.3f}, "
            f"type={structure_type_coverage:.3f}, "
            f"root={structure_root_coverage:.3f}, "
            f"purity={structure_purity:.3f}, "
            f"focus={structure_focus_coverage:.3f}, "
            f"comp_focus={structure_component_focus_overlap:.3f}, "
            f"gate={structure_gate:.3f})"
        )

        if core_terms_total > 0:
            core_preview = ", ".join(sorted(core_terms_matched)[:6]) or "-"
            core_segment = (
                f"core_effect_hits={core_hits} declared={core_terms_total} "
                f"(evidence={core_boost_ratio:.2f}, hit_sat={core_hit_saturation:.2f}, "
                f"conf_strength={core_confidence_strength:.2f}, "
                f"beh_strength={behavioral_confirmation_strength:.2f}, "
                f"max_conf={core_max_confidence:.2f}, mode={core_mode}) "
                f"hits=[{core_preview}]"
            )
        else:
            core_segment = "core_effect=not_declared"

        notes = (
            "Behavioral anchor fusion: malicious-pattern anchors + object tokens + "
            "edge semantics + graph shape. "
            f"patterns={len(target_evidence['malicious_terms'])}/{len(malicious_patterns)}, "
            f"pattern_score={pattern_score:.3f}, support={pattern_support:.3f}, "
            f"anchor={anchor_score:.3f}, object={object_score:.3f}, "
            f"relation={relation_score:.3f}, shape={shape_score:.3f}, "
            f"system_relation={system_relation_score:.3f}, "
            f"concrete={concrete_score:.3f}, "
            f"strong_concrete={strongest_concrete:.3f}, "
            f"artifact_signal={artifact_execution_lure_strength:.3f}, "
            f"shared_core_malicious={len(shared_behavior_terms)} "
            f"(strength={shared_behavior_strength:.3f}, support={shared_behavior_support:.3f}, "
            f"bonus={shared_pattern_bonus:.3f}), "
            f"system_ratio={system_component_ratio:.3f}, gate={system_gate:.3f}, "
            f"system_overlap={len(system_overlap)}/{len(pattern_system_components)}. "
            f"{structure_segment}. "
            f"expected_system=[{expected_system_preview}] overlap_system=[{overlap_system_preview}]. "
            f"{core_segment}"
        )

        return TechniqueMatch(
            algorithm=self.name,
            technique=pattern_graph.technique,
            score=float(score),
            runtime_ms=elapsed_ms,
            matched_node_ids=matched_node_ids,
            notes=notes,
        )

    def _sanitize_structural_token(self, value: object) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return ""

        for token in _term_tokens(text):
            if len(token) < 3:
                continue
            if token in _STRUCTURAL_HINT_STOPWORDS:
                continue
            if token.isdigit():
                continue
            if re.fullmatch(r"[0-9a-f]{8,64}", token):
                continue
            return token[:40]
        return ""

    def _node_structural_hint(self, node: GraphNode) -> str:
        node_type = str(node.node_type or "").strip().lower()
        properties = node.properties if isinstance(node.properties, dict) else {}

        if node_type == "process":
            for value in (
                properties.get("original_file_name"),
                properties.get("image_path"),
                node.label,
                properties.get("process_name"),
            ):
                normalized = _normalize_component_name(value)
                if normalized:
                    return normalized

            command_line = str(properties.get("command_line") or "").strip().lower().strip("\"'")
            if command_line:
                head = command_line.split()[0]
                normalized = _normalize_component_name(head)
                if normalized:
                    return normalized

        if node_type == "file":
            for value in (properties.get("file_path"), node.label, properties.get("name")):
                normalized = _normalize_component_name(value)
                if normalized:
                    return normalized

        if node_type == "registry":
            key_path = str(properties.get("key_path") or "").strip().lower().replace("\\", "/")
            key_tokens = [self._sanitize_structural_token(part) for part in key_path.split("/") if part]
            key_tokens = [token for token in key_tokens if token]
            value_name = self._sanitize_structural_token(properties.get("value_name"))
            if key_tokens:
                hint = ":".join(key_tokens[-2:])
                if value_name and value_name not in key_tokens:
                    hint = f"{hint}:{value_name}"
                return hint
            if value_name:
                return value_name

        if node_type == "network":
            port = str(properties.get("destination_port") or "").strip()
            if port.isdigit():
                return f"port:{port}"
            for value in (properties.get("domain_name"), properties.get("destination_ip")):
                token = self._sanitize_structural_token(value)
                if token:
                    return token

        if node_type == "user":
            token = self._sanitize_structural_token(
                properties.get("username") or properties.get("domain") or node.label
            )
            if token:
                return token

        blob = _node_match_blob(node)
        for token in _term_tokens(blob):
            cleaned = self._sanitize_structural_token(token)
            if cleaned:
                return cleaned
        return ""

    def _structural_node_key(self, node: GraphNode, include_semantic_hint: bool) -> str:
        base = str(node.node_type or "").strip().lower() or "unknown"
        if not include_semantic_hint:
            return base

        hint = self._node_structural_hint(node)
        if hint:
            return f"{base}:{hint[:64]}"
        return base

    def _structural_signature_entries(
        self,
        graph: GraphData,
        include_semantic_hint: bool,
    ) -> tuple[list[tuple[str, int, str, bool]], list[str]]:
        if not graph.nodes:
            return [], []

        children_map: dict[str, list[tuple[str, str]]] = defaultdict(list)
        incoming_count: Counter[str] = Counter()
        explicit_roots: list[str] = []

        for edge in graph.edges:
            source = edge.source
            target = edge.target
            if source not in graph.nodes or target not in graph.nodes:
                continue

            edge_type = edge.edge_type.strip().lower() or "related_to"
            if edge_type == "has_root":
                explicit_roots.append(target)
                continue

            children_map[source].append((edge_type, target))
            incoming_count[target] += 1

        roots = [node_id for node_id in explicit_roots if node_id in graph.nodes]
        if not roots:
            roots = [node_id for node_id in graph.nodes if incoming_count.get(node_id, 0) == 0]
        if not roots:
            roots = sorted(graph.nodes.keys())[:1]

        memo: dict[str, tuple[str, int]] = {}

        def canonical(node_id: str, path: set[str]) -> tuple[str, int]:
            if node_id not in graph.nodes:
                return "missing", 0

            if node_id in path:
                node_key = self._structural_node_key(graph.nodes[node_id], include_semantic_hint)
                return f"{node_key}#cycle", 1

            cached = memo.get(node_id)
            if cached is not None:
                return cached

            node_key = self._structural_node_key(graph.nodes[node_id], include_semantic_hint)
            next_path = set(path)
            next_path.add(node_id)

            child_signatures: list[str] = []
            subtree_size = 1
            for edge_type, child_id in sorted(
                children_map.get(node_id, []),
                key=lambda item: (item[0], item[1]),
            ):
                child_signature, child_size = canonical(child_id, next_path)
                child_signatures.append(f"{edge_type}>{child_signature}")
                subtree_size += child_size

            signature = f"{node_key}[{'|'.join(child_signatures)}]" if child_signatures else node_key
            memo[node_id] = (signature, subtree_size)
            return signature, subtree_size

        root_set = set(roots)
        entries: list[tuple[str, int, str, bool]] = []
        for node_id in graph.nodes:
            signature, subtree_size = canonical(node_id, set())
            entries.append((signature, subtree_size, node_id, node_id in root_set))

        root_signatures = [canonical(root_id, set())[0] for root_id in roots if root_id in graph.nodes]
        return entries, root_signatures

    def _execution_components(self, graph: GraphData) -> list[set[str]]:
        identity = self._graph_identity(graph)
        cached_components = self._execution_component_cache.get(identity)
        if cached_components is not None:
            return cached_components

        execution_nodes = {
            node_id
            for node_id, node in graph.nodes.items()
            if str(node.node_type or "").strip().lower() != "technique"
        }
        if not execution_nodes:
            return []

        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in graph.edges:
            source = edge.source
            target = edge.target
            if source not in execution_nodes or target not in execution_nodes:
                continue
            if str(edge.edge_type or "").strip().lower() == "has_root":
                continue
            adjacency[source].add(target)
            adjacency[target].add(source)

        components: list[set[str]] = []
        visited: set[str] = set()
        for node_id in sorted(execution_nodes):
            if node_id in visited:
                continue
            stack = [node_id]
            component: set[str] = set()
            visited.add(node_id)
            while stack:
                current = stack.pop()
                component.add(current)
                for neighbor in adjacency.get(current, set()):
                    if neighbor in visited:
                        continue
                    visited.add(neighbor)
                    stack.append(neighbor)
            components.append(component)

        components.sort(key=len, reverse=True)
        if len(self._execution_component_cache) > 512:
            self._execution_component_cache.clear()
        self._execution_component_cache[identity] = components
        return components

    def _subgraph_from_nodes(
        self,
        graph: GraphData,
        node_ids: set[str],
        name_suffix: str,
    ) -> GraphData:
        nodes = {node_id: graph.nodes[node_id] for node_id in node_ids if node_id in graph.nodes}
        if not nodes:
            return GraphData(
                name=f"{graph.name}:{name_suffix}",
                technique=graph.technique,
                nodes={},
                edges=[],
                raw_payload=graph.raw_payload,
            )

        edges = [
            edge
            for edge in graph.edges
            if edge.source in nodes and edge.target in nodes
        ]
        return GraphData(
            name=f"{graph.name}:{name_suffix}",
            technique=graph.technique,
            nodes=nodes,
            edges=edges,
            raw_payload=graph.raw_payload,
        )

    def _focused_pattern_graph(
        self,
        pattern_graph: GraphData,
        focus_node_ids: Iterable[str] | None,
    ) -> GraphData | None:
        if not pattern_graph.nodes:
            return None

        focus_nodes = {
            node_id
            for node_id in (focus_node_ids or [])
            if node_id in pattern_graph.nodes
        }
        if not focus_nodes or len(focus_nodes) >= len(pattern_graph.nodes):
            return None

        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in pattern_graph.edges:
            if edge.source not in pattern_graph.nodes or edge.target not in pattern_graph.nodes:
                continue
            if str(edge.edge_type or "").strip().lower() == "has_root":
                continue
            adjacency[edge.source].add(edge.target)
            adjacency[edge.target].add(edge.source)

        expanded_focus = set(focus_nodes)
        for node_id in list(focus_nodes):
            expanded_focus.update(adjacency.get(node_id, set()))
        focus_nodes = expanded_focus

        if len(focus_nodes) < 2:
            return None

        if len(focus_nodes) >= len(pattern_graph.nodes):
            return None

        return self._subgraph_from_nodes(pattern_graph, focus_nodes, name_suffix="focused")

    def _structural_candidate_score(
        self,
        consistency: dict[str, object],
        component_size: int,
        pattern_size: int,
        preferred_overlap: float,
    ) -> float:
        precision = float(consistency.get("precision") or 0.0)
        semantic = float(consistency.get("semantic_coverage") or 0.0)
        size_ratio = min(1.0, component_size / max(pattern_size, 1))
        size_factor = 0.65 + (0.35 * size_ratio)
        overlap_factor = 0.82 + (0.28 * max(0.0, min(1.0, preferred_overlap)))
        return ((0.74 * precision) + (0.26 * semantic)) * size_factor * overlap_factor

    def _structural_signature_coverage(
        self,
        pattern_entries: list[tuple[str, int, str, bool]],
        target_entries: list[tuple[str, int, str, bool]],
    ) -> tuple[float, set[str]]:
        if not pattern_entries:
            return 1.0, set()

        target_counts = Counter(signature for signature, _, _, _ in target_entries)
        target_ids_by_signature: dict[str, deque[str]] = defaultdict(deque)
        for signature, _subtree_size, node_id, _is_root in sorted(
            target_entries,
            key=lambda item: (1 if item[3] else 0, item[1]),
            reverse=True,
        ):
            target_ids_by_signature[signature].append(node_id)

        weighted_hits = 0.0
        weighted_total = 0.0
        matched_node_ids: set[str] = set()

        for signature, subtree_size, _node_id, is_root in sorted(
            pattern_entries,
            key=lambda item: (1 if item[3] else 0, item[1]),
            reverse=True,
        ):
            root_bonus = 1.60 if is_root else 1.0
            size_bonus = 1.0 + (0.18 * min(max(subtree_size - 1, 0), 6))
            weight = root_bonus * size_bonus
            weighted_total += weight

            if target_counts.get(signature, 0) <= 0:
                continue

            target_counts[signature] -= 1
            weighted_hits += weight
            if target_ids_by_signature[signature]:
                matched_node_ids.add(target_ids_by_signature[signature].popleft())

        if weighted_total <= 0:
            return 0.0, matched_node_ids
        return weighted_hits / weighted_total, matched_node_ids

    def _root_signature_coverage(
        self,
        pattern_root_signatures: list[str],
        target_root_signatures: list[str],
    ) -> float:
        if not pattern_root_signatures:
            return 1.0

        target_counts = Counter(target_root_signatures)
        matched = 0
        for signature in pattern_root_signatures:
            if target_counts.get(signature, 0) <= 0:
                continue
            target_counts[signature] -= 1
            matched += 1

        return matched / max(len(pattern_root_signatures), 1)

    def _structural_consistency_single(self, target_graph: GraphData, pattern_graph: GraphData) -> dict[str, object]:
        if not pattern_graph.nodes:
            return {
                "precision": 1.0,
                "semantic_coverage": 1.0,
                "type_coverage": 1.0,
                "root_semantic_coverage": 1.0,
                "root_type_coverage": 1.0,
                "matched_node_ids": set(),
            }

        pattern_semantic_entries, pattern_semantic_roots = self._cached_structural_signature_entries(
            pattern_graph,
            include_semantic_hint=True,
        )
        target_semantic_entries, target_semantic_roots = self._cached_structural_signature_entries(
            target_graph,
            include_semantic_hint=True,
        )
        semantic_coverage, semantic_matches = self._structural_signature_coverage(
            pattern_semantic_entries,
            target_semantic_entries,
        )
        root_semantic_coverage = self._root_signature_coverage(
            pattern_semantic_roots,
            target_semantic_roots,
        )

        pattern_type_entries, pattern_type_roots = self._cached_structural_signature_entries(
            pattern_graph,
            include_semantic_hint=False,
        )
        target_type_entries, target_type_roots = self._cached_structural_signature_entries(
            target_graph,
            include_semantic_hint=False,
        )
        type_coverage, type_matches = self._structural_signature_coverage(
            pattern_type_entries,
            target_type_entries,
        )
        root_type_coverage = self._root_signature_coverage(
            pattern_type_roots,
            target_type_roots,
        )

        precision = (
            0.68 * semantic_coverage
            + 0.32 * type_coverage
        )

        return {
            "precision": max(0.0, min(1.0, precision)),
            "semantic_coverage": max(0.0, min(1.0, semantic_coverage)),
            "type_coverage": max(0.0, min(1.0, type_coverage)),
            "root_semantic_coverage": max(0.0, min(1.0, root_semantic_coverage)),
            "root_type_coverage": max(0.0, min(1.0, root_type_coverage)),
            "matched_node_ids": semantic_matches | type_matches,
        }

    def _structural_consistency(
        self,
        target_graph: GraphData,
        pattern_graph: GraphData,
        preferred_node_ids: Iterable[str] | None = None,
        pattern_focus_node_ids: Iterable[str] | None = None,
    ) -> dict[str, object]:
        baseline = self._structural_consistency_single(target_graph, pattern_graph)
        if not pattern_graph.nodes:
            return {
                **baseline,
                "purity": 1.0,
                "focus_coverage": 0.0,
                "component_focus_overlap": 0.0,
            }

        preferred = {
            node_id for node_id in (preferred_node_ids or [])
            if node_id in target_graph.nodes
        }
        pattern_size = max(1, len(pattern_graph.nodes))
        target_components = self._execution_components(target_graph)

        if not target_components:
            matched_ids = set(baseline.get("matched_node_ids") or set())
            baseline_purity = len(matched_ids) / max(len(target_graph.nodes), 1)
            focus_coverage = (
                len(preferred & matched_ids) / max(len(preferred), 1)
                if preferred
                else 0.0
            )
            return {
                **baseline,
                "purity": max(0.0, min(1.0, baseline_purity)),
                "focus_coverage": max(0.0, min(1.0, focus_coverage)),
                "component_focus_overlap": 0.0,
            }

        node_to_component: dict[str, int] = {}
        for index, component in enumerate(target_components):
            for node_id in component:
                node_to_component[node_id] = index

        candidate_indexes: list[int] = []
        if preferred:
            candidate_indexes = sorted({
                node_to_component[node_id]
                for node_id in preferred
                if node_id in node_to_component
            })

        if not candidate_indexes:
            candidate_indexes = list(range(min(3, len(target_components))))

        best_consistency = baseline
        best_component_nodes: set[str] = set(target_graph.nodes.keys())
        best_component_graph = target_graph
        baseline_overlap = (
            len(preferred & best_component_nodes) / max(len(preferred), 1)
            if preferred
            else 0.0
        )
        best_score = self._structural_candidate_score(
            baseline,
            len(best_component_nodes),
            pattern_size,
            baseline_overlap,
        )

        for offset, component_index in enumerate(candidate_indexes[:8]):
            component_nodes = target_components[component_index]
            if not component_nodes:
                continue
            component_graph = self._subgraph_from_nodes(
                target_graph,
                component_nodes,
                name_suffix=f"exec{component_index}:{offset}",
            )
            component_consistency = self._structural_consistency_single(component_graph, pattern_graph)
            preferred_overlap = (
                len(preferred & component_nodes) / max(len(preferred), 1)
                if preferred
                else 0.0
            )
            candidate_score = self._structural_candidate_score(
                component_consistency,
                len(component_nodes),
                pattern_size,
                preferred_overlap,
            )
            if candidate_score > best_score:
                best_score = candidate_score
                best_consistency = component_consistency
                best_component_nodes = set(component_nodes)
                best_component_graph = component_graph

        baseline_matched = set(baseline.get("matched_node_ids") or set())
        best_matched = set(best_consistency.get("matched_node_ids") or set())
        if baseline_matched:
            focus_purity = len(best_matched) / max(len(baseline_matched), 1)
        else:
            focus_purity = 1.0 if best_matched else 0.0
        component_density = len(best_matched) / max(len(best_component_nodes), 1)
        purity = (0.55 * focus_purity) + (0.45 * component_density)

        blended_precision = max(
            float(baseline.get("precision") or 0.0),
            (0.30 * float(baseline.get("precision") or 0.0))
            + (0.70 * float(best_consistency.get("precision") or 0.0)),
        )
        blended_semantic = max(
            float(baseline.get("semantic_coverage") or 0.0),
            (0.25 * float(baseline.get("semantic_coverage") or 0.0))
            + (0.75 * float(best_consistency.get("semantic_coverage") or 0.0)),
        )
        blended_type = max(
            float(baseline.get("type_coverage") or 0.0),
            (0.30 * float(baseline.get("type_coverage") or 0.0))
            + (0.70 * float(best_consistency.get("type_coverage") or 0.0)),
        )

        focused_matched: set[str] = set()
        focused_pattern_graph = self._focused_pattern_graph(pattern_graph, pattern_focus_node_ids)
        if focused_pattern_graph and focused_pattern_graph.nodes:
            focused_baseline = self._structural_consistency_single(target_graph, focused_pattern_graph)
            focused_component = self._structural_consistency_single(best_component_graph, focused_pattern_graph)

            focused_precision = max(
                float(focused_baseline.get("precision") or 0.0),
                (0.30 * float(focused_baseline.get("precision") or 0.0))
                + (0.70 * float(focused_component.get("precision") or 0.0)),
            )
            focused_semantic = max(
                float(focused_baseline.get("semantic_coverage") or 0.0),
                (0.25 * float(focused_baseline.get("semantic_coverage") or 0.0))
                + (0.75 * float(focused_component.get("semantic_coverage") or 0.0)),
            )
            focused_type = max(
                float(focused_baseline.get("type_coverage") or 0.0),
                (0.30 * float(focused_baseline.get("type_coverage") or 0.0))
                + (0.70 * float(focused_component.get("type_coverage") or 0.0)),
            )

            focus_fraction = len(focused_pattern_graph.nodes) / max(len(pattern_graph.nodes), 1)
            focus_blend = 0.14 + (0.24 * (1.0 - min(1.0, focus_fraction)))
            if preferred:
                focus_blend += 0.08
            focus_blend = max(0.0, min(0.42, focus_blend))

            blended_precision = max(
                blended_precision,
                ((1.0 - focus_blend) * blended_precision) + (focus_blend * focused_precision),
            )
            blended_semantic = max(
                blended_semantic,
                ((1.0 - focus_blend) * blended_semantic) + (focus_blend * focused_semantic),
            )
            blended_type = max(
                blended_type,
                ((1.0 - focus_blend) * blended_type) + (focus_blend * focused_type),
            )

            focused_matched = set(focused_baseline.get("matched_node_ids") or set())
            focused_matched.update(focused_component.get("matched_node_ids") or set())

        combined_matched = baseline_matched | best_matched | focused_matched
        focus_coverage = (
            len(preferred & combined_matched) / max(len(preferred), 1)
            if preferred
            else 0.0
        )
        component_focus_overlap = (
            len(preferred & best_component_nodes) / max(len(preferred), 1)
            if preferred
            else 0.0
        )

        return {
            "precision": max(0.0, min(1.0, blended_precision)),
            "semantic_coverage": max(0.0, min(1.0, blended_semantic)),
            "type_coverage": max(0.0, min(1.0, blended_type)),
            "root_semantic_coverage": max(
                float(baseline.get("root_semantic_coverage") or 0.0),
                float(best_consistency.get("root_semantic_coverage") or 0.0),
            ),
            "root_type_coverage": max(
                float(baseline.get("root_type_coverage") or 0.0),
                float(best_consistency.get("root_type_coverage") or 0.0),
            ),
            "purity": max(0.0, min(1.0, purity)),
            "focus_coverage": max(0.0, min(1.0, focus_coverage)),
            "component_focus_overlap": max(0.0, min(1.0, component_focus_overlap)),
            "matched_node_ids": combined_matched,
        }

    def _structure_gate_factor(
        self,
        structure_precision: float,
        structure_purity: float,
        has_core_effect: bool,
        focus_alignment: float = 0.0,
        core_evidence_strength: float = 0.0,
        component_focus_overlap: float = 0.0,
    ) -> float:
        precision = max(0.0, min(1.0, structure_precision))
        purity = max(0.0, min(1.0, structure_purity))
        focus = max(0.0, min(1.0, focus_alignment))
        core_evidence = max(0.0, min(1.0, core_evidence_strength))
        component_focus = max(0.0, min(1.0, component_focus_overlap))

        if not has_core_effect:
            gate = 0.06 + (0.66 * precision) + (0.24 * purity) + (0.04 * focus)
            return max(0.05, min(1.0, gate))

        gate = (0.16 + (0.78 * precision) + (0.06 * focus)) * (0.74 + (0.20 * purity) + (0.06 * focus))
        if precision < self.structure_precision_hard_floor:
            gate *= (0.52 + (0.18 * purity) + (0.14 * focus))
            if core_evidence >= 0.45 and component_focus >= 0.60:
                fragmented_relief = (
                    0.16
                    + (0.16 * focus)
                    + (0.12 * purity)
                    + (0.12 * core_evidence)
                    + (0.10 * component_focus)
                )
                gate = max(gate, min(0.50, fragmented_relief))
        elif precision < self.structure_precision_soft_floor:
            gate *= (0.76 + (0.08 * purity) + (0.10 * focus))
            if core_evidence >= 0.50 and component_focus >= 0.55 and focus >= 0.40:
                partial_relief = (
                    0.20
                    + (0.14 * focus)
                    + (0.08 * purity)
                    + (0.12 * core_evidence)
                    + (0.08 * component_focus)
                )
                gate = max(gate, min(0.65, partial_relief))

        return max(0.03, min(1.0, gate))

    def _extract_patterns(self, graph: GraphData) -> list[str]:
        raw_patterns = graph.raw_payload.get("patterns", {})
        malicious: list[str] = []

        if isinstance(raw_patterns, dict):
            malicious = self._dedupe_terms(raw_patterns.get("malicious") or raw_patterns.get("patterns") or [])
        elif isinstance(raw_patterns, list):
            malicious = self._dedupe_terms(raw_patterns)

        return malicious

    def _extract_core_effect(self, graph: GraphData) -> list[str]:
        raw_patterns = graph.raw_payload.get("patterns", {})
        if not isinstance(raw_patterns, dict):
            return []
        return self._dedupe_terms(raw_patterns.get("core_effect") or [])

    def _dedupe_terms(self, values: object) -> list[str]:
        if not isinstance(values, list):
            return []
        seen: set[str] = set()
        terms: list[str] = []
        for raw in values:
            term = str(raw or "").strip()
            key = term.lower()
            if not term or key in seen:
                continue
            seen.add(key)
            terms.append(term)
        return terms

    def _scan_pattern_terms(
        self,
        graph: GraphData,
        malicious_patterns: list[str],
        core_effect_patterns: list[str] | None = None,
        node_blobs: dict[str, str] | None = None,
    ) -> dict[str, object]:
        # Use the restricted per-entity match blob so generic descriptors like
        # node_type='network' or properties.type='Network' do not produce false
        # matches against short core terms (e.g. 'net').
        if node_blobs is None:
            node_blobs = {node_id: _node_match_blob(node) for node_id, node in graph.nodes.items()}
        malicious_terms: set[str] = set()
        malicious_node_ids: set[str] = set()

        for term in malicious_patterns:
            term_hit = False
            for node_id, blob in node_blobs.items():
                if _term_matches_blob(term, blob):
                    term_hit = True
                    malicious_node_ids.add(node_id)
            if term_hit:
                malicious_terms.add(term.lower())

        core_effect_terms: set[str] = set()
        core_effect_node_ids: set[str] = set()
        for term in core_effect_patterns or []:
            term_hit = False
            for node_id, blob in node_blobs.items():
                if _core_effect_term_matches_blob(term, blob):
                    term_hit = True
                    core_effect_node_ids.add(node_id)
            if term_hit:
                core_effect_terms.add(term.lower())

        return {
            "all_malicious_patterns": malicious_patterns,
            "malicious_terms": malicious_terms,
            "malicious_node_ids": malicious_node_ids,
            "all_core_effect_patterns": list(core_effect_patterns or []),
            "core_effect_terms": core_effect_terms,
            "core_effect_node_ids": core_effect_node_ids,
        }

    def _pattern_anchor_ids(self, graph: GraphData, malicious_patterns: list[str]) -> set[str]:
        matching = graph.raw_payload.get("matching", {})
        if isinstance(matching, dict):
            ids = matching.get("malicious_node_ids") or []
            if isinstance(ids, list):
                known_ids = {str(node_id) for node_id in ids if str(node_id) in graph.nodes}
                if known_ids:
                    return known_ids

        evidence = self._scan_pattern_terms(graph, malicious_patterns)
        return set(evidence["malicious_node_ids"])

    def _pattern_core_effect_ids(self, graph: GraphData, core_effect_patterns: list[str]) -> set[str]:
        matching = graph.raw_payload.get("matching", {})
        if isinstance(matching, dict):
            ids = matching.get("core_effect_node_ids") or []
            if isinstance(ids, list):
                known_ids = {str(node_id) for node_id in ids if str(node_id) in graph.nodes}
                if known_ids:
                    return known_ids

        evidence = self._scan_pattern_terms(graph, [], core_effect_patterns)
        return set(evidence["core_effect_node_ids"])

    def _extract_features(
        self,
        graph: GraphData,
        anchor_ids: Iterable[str],
        precomputed: dict[str, object] | None = None,
    ) -> dict[str, object]:
        anchors = {node_id for node_id in anchor_ids if node_id in graph.nodes}
        neighborhoods = self._anchor_neighborhoods(graph, anchors)
        object_features: Counter[str] = Counter()
        relation_features: Counter[str] = Counter()
        system_relation_features: Counter[str] = Counter()
        shape_features: Counter[str] = Counter()
        anchor_features: Counter[str] = Counter()
        node_scores: Counter[str] = Counter()
        cached_degree = (precomputed or {}).get("degree_map") if isinstance(precomputed, dict) else None
        degree = cached_degree if isinstance(cached_degree, Counter) else self._degree_map(graph.edges)
        cached_node_tokens = (precomputed or {}).get("node_tokens") if isinstance(precomputed, dict) else None
        cached_node_system_components = (
            (precomputed or {}).get("node_system_components")
            if isinstance(precomputed, dict)
            else None
        )
        node_system_components: dict[str, set[str]] = {}
        context_system_components: set[str] = set()
        context_node_ids = anchors | neighborhoods if anchors else set(graph.nodes.keys())

        for node_id, node in graph.nodes.items():
            weight = 3 if node_id in anchors else 2 if node_id in neighborhoods else 1
            if isinstance(cached_node_system_components, dict):
                system_components = cached_node_system_components.get(node_id, set())
            else:
                system_components = self._node_system_components(node)
            node_system_components[node_id] = system_components
            if node_id in context_node_ids:
                context_system_components.update(system_components)

            object_features[f"type:{node.node_type}"] += weight
            object_features[f"group:{node.group.lower()}"] += weight
            shape_features[f"degree:{node.node_type}:{_bucket(degree[node_id])}"] += 1

            for component in sorted(system_components):
                object_features[f"sys:{component}"] += 4 * weight
                if node_id in anchors or node_id in neighborhoods:
                    anchor_features[f"sys:{component}"] += 4 * weight
                    node_scores[node_id] += 3

            if isinstance(cached_node_tokens, dict):
                node_tokens = cached_node_tokens.get(node_id, [])
            else:
                node_tokens = [token for token in _tokens(_node_blob(node)) if len(token) > 2]

            for token in node_tokens:
                object_features[f"tok:{token[:96]}"] += weight
                if node_id in anchors or node_id in neighborhoods:
                    anchor_features[f"tok:{token[:96]}"] += weight
                    node_scores[node_id] += 1

        for edge in graph.edges:
            source = graph.nodes.get(edge.source)
            target = graph.nodes.get(edge.target)
            if not source or not target:
                continue
            near_anchor = edge.source in neighborhoods or edge.target in neighborhoods
            weight = 2 if near_anchor else 1
            edge_type = edge.edge_type.strip().lower()
            relation_features[f"edge:{edge_type}"] += weight
            relation_features[f"triple:{source.node_type}>{edge_type}>{target.node_type}"] += weight
            edge_system_signatures: list[tuple[str, int]] = []

            source_system = node_system_components.get(edge.source, set())
            target_system = node_system_components.get(edge.target, set())
            if not near_anchor:
                source_system = set()
                target_system = set()

            if source_system and target_system:
                for source_comp in sorted(source_system)[:2]:
                    for target_comp in sorted(target_system)[:2]:
                        signature = f"sys_triple:{source_comp}>{edge_type}>{target_comp}"
                        delta = 3 * weight
                        system_relation_features[signature] += delta
                        edge_system_signatures.append((signature, delta))
            elif source_system:
                for source_comp in sorted(source_system)[:2]:
                    signature = f"sys_src:{source_comp}>{edge_type}>{target.node_type}"
                    delta = 2 * weight
                    system_relation_features[signature] += delta
                    edge_system_signatures.append((signature, delta))
            elif target_system:
                for target_comp in sorted(target_system)[:2]:
                    signature = f"sys_dst:{source.node_type}>{edge_type}>{target_comp}"
                    delta = 2 * weight
                    system_relation_features[signature] += delta
                    edge_system_signatures.append((signature, delta))

            if near_anchor:
                anchor_features[f"edge:{edge_type}"] += weight
                anchor_features[f"triple:{source.node_type}>{edge_type}>{target.node_type}"] += weight
                node_scores[edge.source] += 1
                node_scores[edge.target] += 1
                for signature, delta in edge_system_signatures:
                    anchor_features[signature] += delta

        shape_features[f"nodes:{_bucket(len(graph.nodes))}"] += 1
        shape_features[f"edges:{_bucket(len(graph.edges))}"] += 1
        shape_features[f"density:{self._density_bucket(graph)}"] += 1

        if not anchor_features:
            anchor_features.update(object_features)

        return {
            "object": object_features,
            "relation": relation_features,
            "system_relation": system_relation_features,
            "shape": shape_features,
            "anchor": anchor_features,
            "system_components": context_system_components,
            "node_scores": node_scores,
            "neighborhoods": neighborhoods,
        }

    def _terms_system_components(self, terms: Iterable[str]) -> set[str]:
        components: set[str] = set()
        for term in terms:
            for token in _term_tokens(str(term or "")):
                token_name = _normalize_component_name(token)
                if token_name in self.system_component_index:
                    components.add(token_name)
                elif "." not in token_name:
                    maybe_exe = f"{token_name}.exe"
                    if maybe_exe in self.system_component_index:
                        components.add(maybe_exe)
        return components

    def _node_system_components(self, node: GraphNode) -> set[str]:
        found: set[str] = set()
        candidates: list[object] = [
            node.label,
            node.id,
            node.properties.get("image_path"),
            node.properties.get("original_file_name"),
            node.properties.get("process_name"),
            node.properties.get("name"),
            node.properties.get("display_name"),
            node.properties.get("command_line"),
        ]

        for value in candidates:
            normalized = _normalize_component_name(value)
            if normalized in self.system_component_index:
                found.add(normalized)

            for token in _tokens(_normalize_text(value)):
                token_name = _normalize_component_name(token)
                if not token_name:
                    continue
                if token_name in self.system_component_index:
                    found.add(token_name)
                elif "." not in token_name:
                    maybe_exe = f"{token_name}.exe"
                    if maybe_exe in self.system_component_index:
                        found.add(maybe_exe)

        return found

    def _system_component_ratio(self, pattern_components: set[str], overlap_components: list[str]) -> float:
        if not pattern_components:
            return 1.0
        return len(overlap_components) / max(len(pattern_components), 1)

    def _contains_any_token(
        self,
        node_blobs: dict[str, str] | None,
        tokens: set[str],
    ) -> bool:
        if not isinstance(node_blobs, dict) or not node_blobs or not tokens:
            return False

        for blob in node_blobs.values():
            haystack = str(blob or "")
            if not haystack:
                continue
            for token in tokens:
                if token in haystack:
                    return True
        return False

    def _artifact_execution_lure_strength(
        self,
        evidence: dict[str, object],
        node_blobs: dict[str, str] | None,
    ) -> float:
        matched_malicious = {
            str(term or "").strip().lower()
            for term in (evidence.get("malicious_terms") or set())
            if str(term or "").strip()
        }
        matched_core = {
            str(term or "").strip().lower()
            for term in (evidence.get("core_effect_terms") or set())
            if str(term or "").strip()
        }
        matched_terms = matched_malicious | matched_core
        if not matched_terms:
            return 0.0

        lure_hits = matched_terms & _LURE_ARTIFACT_TERMS
        if not lure_hits:
            return 0.0

        extension_hits = lure_hits & _LURE_ARTIFACT_EXTENSION_TERMS
        execution_hits = matched_terms & _LURE_ARTIFACT_EXECUTION_TERMS

        office_host_present = self._contains_any_token(node_blobs, _OFFICE_HOST_PROCESS_TOKENS)
        script_host_present = self._contains_any_token(node_blobs, _SCRIPT_EXECUTION_HOST_TOKENS)

        lure_density = min(1.0, len(lure_hits) / 3.0)
        extension_density = min(1.0, len(extension_hits) / 2.0)
        execution_density = min(1.0, len(execution_hits) / 1.0)
        context_density = (0.50 if office_host_present else 0.0) + (
            0.50 if (script_host_present or bool(execution_hits)) else 0.0
        )
        shared_lure = bool((matched_malicious & matched_core) & _LURE_ARTIFACT_TERMS)

        strength = (
            (0.30 * lure_density)
            + (0.22 * extension_density)
            + (0.20 * execution_density)
            + (0.24 * context_density)
            + (0.04 if shared_lure else 0.0)
        )
        return max(0.0, min(1.0, strength))

    def _system_gate_factor(self, ratio: float, has_pattern_system_components: bool) -> float:
        if not has_pattern_system_components:
            return 1.0

        bounded_ratio = max(0.0, min(1.0, ratio))
        if bounded_ratio >= self.system_component_min_ratio:
            return 1.0

        return max(0.05, bounded_ratio / max(self.system_component_min_ratio, 1e-6))

    def _degree_map(self, edges: list[GraphEdge]) -> Counter[str]:
        degree: Counter[str] = Counter()
        for edge in edges:
            degree[edge.source] += 1
            degree[edge.target] += 1
        return degree

    def _density_bucket(self, graph: GraphData) -> str:
        density = len(graph.edges) / max(len(graph.nodes), 1)
        if density < 0.8:
            return "low"
        if density < 1.6:
            return "medium"
        return "high"

    def _anchor_neighborhoods(self, graph: GraphData, anchors: set[str]) -> set[str]:
        if not anchors:
            return set()

        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in graph.edges:
            adjacency[edge.source].add(edge.target)
            adjacency[edge.target].add(edge.source)

        visited = set(anchors)
        queue = deque((node_id, 0) for node_id in anchors)
        while queue:
            node_id, depth = queue.popleft()
            if depth >= self.anchor_depth:
                continue
            for next_id in adjacency.get(node_id, set()):
                if next_id in visited or next_id not in graph.nodes:
                    continue
                visited.add(next_id)
                queue.append((next_id, depth + 1))
        return visited

    def _pattern_score(self, evidence: dict[str, object], total_malicious_patterns: int) -> float:
        if total_malicious_patterns <= 0:
            return 0.0
        matched_nodes = len(evidence["malicious_node_ids"])

        all_terms = list(evidence.get("all_malicious_patterns") or [])
        matched_terms = set(evidence["malicious_terms"])
        total_weight = sum(_term_specificity(term) for term in all_terms)
        matched_weight = sum(_term_specificity(term) for term in all_terms if term.lower() in matched_terms)
        coverage = matched_weight / total_weight if total_weight > 0 else 0.0
        locality = min(1.0, matched_nodes / max(total_malicious_patterns, 1))
        return float((0.78 * coverage) + (0.22 * locality))

    def _pattern_support(self, evidence: dict[str, object]) -> float:
        all_terms = list(evidence.get("all_malicious_patterns") or [])
        matched_terms = set(evidence["malicious_terms"])
        matched_weight = sum(_term_specificity(term) for term in all_terms if term.lower() in matched_terms)
        if matched_weight <= 0:
            return 0.0
        if matched_weight < 0.55:
            return 0.35
        if matched_weight < 1.15:
            return 0.70
        return 1.0

    def _concrete_behavior_score(self, evidence: dict[str, object]) -> float:
        malicious_all_terms = list(evidence.get("all_malicious_patterns") or [])
        malicious_matched_terms = set(evidence.get("malicious_terms") or set())
        core_all_terms = list(evidence.get("all_core_effect_patterns") or [])
        core_matched_terms = set(evidence.get("core_effect_terms") or set())

        malicious_score = 0.0
        if malicious_all_terms and malicious_matched_terms:
            total_weight = sum(_term_concrete_behavior_weight(term) for term in malicious_all_terms)
            if total_weight > 0:
                matched_weight = sum(
                    _term_concrete_behavior_weight(term)
                    for term in malicious_all_terms
                    if term.lower() in malicious_matched_terms
                )
                malicious_score = max(0.0, min(1.0, matched_weight / max(total_weight, 1.0)))

        core_score = 0.0
        if core_matched_terms:
            core_strength = _core_effect_evidence_strength(core_matched_terms)
            core_evidence = float(core_strength.get("evidence_strength") or 0.0)
            core_max_confidence = float(core_strength.get("max_confidence") or 0.0)
            normalized_core_confidence = max(0.0, min(1.0, core_max_confidence / 1.60))

            matched_core_catalog_terms = [
                term for term in core_all_terms if term.lower() in core_matched_terms
            ]
            if not matched_core_catalog_terms:
                matched_core_catalog_terms = sorted(core_matched_terms)

            core_concrete = 0.0
            if matched_core_catalog_terms:
                core_concrete = max(
                    0.0,
                    min(
                        1.0,
                        sum(_term_concrete_behavior_weight(term) for term in matched_core_catalog_terms)
                        / max(len(matched_core_catalog_terms), 1),
                    ),
                )

            core_score = max(
                0.0,
                min(
                    1.0,
                    (0.44 * core_evidence)
                    + (0.22 * normalized_core_confidence)
                    + (0.34 * core_concrete),
                ),
            )

        if malicious_score > 0.0 and core_score > 0.0:
            blended = (0.64 * malicious_score) + (0.36 * core_score)
            if malicious_score >= 0.35 and core_score >= 0.35:
                blended += 0.06 * min(1.0, 0.5 * (malicious_score + core_score))
            return max(0.0, min(1.0, blended))

        return max(malicious_score, core_score)

    def _strongest_matched_concrete(self, evidence: dict[str, object]) -> float:
        all_terms = list(evidence.get("all_malicious_patterns") or [])
        all_terms.extend(list(evidence.get("all_core_effect_patterns") or []))
        matched_terms = set(evidence.get("malicious_terms") or set())
        matched_terms.update(set(evidence.get("core_effect_terms") or set()))
        if not matched_terms:
            return 0.0

        candidate_terms = [term for term in all_terms if term.lower() in matched_terms]
        if not candidate_terms:
            candidate_terms = sorted(matched_terms)

        return max(
            (_term_concrete_behavior_weight(term) for term in candidate_terms),
            default=0.0,
        )

    def _matched_node_ids(
        self,
        graph: GraphData,
        anchor_ids: Iterable[str],
        node_scores: Counter[str],
        core_node_ids: Iterable[str] | None = None,
        structural_node_ids: Iterable[str] | None = None,
    ) -> list[str]:
        anchors = {node_id for node_id in anchor_ids if node_id in graph.nodes}
        core_anchors = {
            node_id for node_id in (core_node_ids or []) if node_id in graph.nodes
        }
        structural_anchors = {
            node_id for node_id in (structural_node_ids or []) if node_id in graph.nodes
        }
        # core_effect node ids are the highest-confidence anchors. Surface them
        # first so downstream UI/logging always sees the technique-defining
        # nodes even when the lexical pattern set is sparse.
        anchors = anchors | core_anchors | structural_anchors
        if anchors:
            if node_scores or core_anchors or structural_anchors:
                ranked_anchors = sorted(
                    anchors,
                    key=lambda node_id: (
                        1 if node_id in core_anchors else 0,
                        1 if node_id in structural_anchors else 0,
                        node_scores.get(node_id, 0),
                    ),
                    reverse=True,
                )
                return ranked_anchors[: self.max_matched_nodes]
            return sorted(anchors)[: self.max_matched_nodes]

        if not node_scores:
            return []
        return [node_id for node_id, _ in node_scores.most_common(self.max_matched_nodes)]