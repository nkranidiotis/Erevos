from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Any


def normalize_function_intel_summary(value: Any) -> Dict[str, Any]:
    """Normalize function intelligence summary payloads to a plain dict.

    Backward compatibility:
    - Older broken payloads may be wrapped as tuple/list containing one dict.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, (list, tuple)):
        if len(value) == 1 and isinstance(value[0], dict):
            return value[0]
        # fallback: first dict-like element, if present
        for item in value:
            if isinstance(item, dict):
                return item
    return {}


def normalize_behavior_summaries(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, (list, tuple)):
        if len(value) == 1 and isinstance(value[0], dict):
            return value[0]
        for item in value:
            if isinstance(item, dict):
                return item
    return {}


def normalize_call_graph_summary(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, (list, tuple)):
        if len(value) == 1 and isinstance(value[0], dict):
            return value[0]
        for item in value:
            if isinstance(item, dict):
                return item
    return {}


def normalize_cfg_intel_summary(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, (list, tuple)):
        if len(value) == 1 and isinstance(value[0], dict):
            return value[0]
        for item in value:
            if isinstance(item, dict):
                return item
    return {}


def normalize_naming_suggestions(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, (list, tuple)):
        if len(value) == 1 and isinstance(value[0], dict):
            return value[0]
        for item in value:
            if isinstance(item, dict):
                return item
    return {}


def normalize_threat_narrative(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, (list, tuple)):
        if len(value) == 1 and isinstance(value[0], dict):
            return value[0]
        for item in value:
            if isinstance(item, dict):
                return item
    return {}


@dataclass
class SessionState:
    renamed_functions: Dict[str, str] = field(default_factory=dict)  # va hex -> new name
    original_functions: Dict[str, str] = field(default_factory=dict)
    comments: Dict[str, str] = field(default_factory=dict)  # va hex -> comment
    labels: Dict[str, str] = field(default_factory=dict)    # va hex -> label
    bookmarks: List[str] = field(default_factory=list)      # list[va hex]
    last_opened_file: str = ""
    triage_metadata: Dict[str, Any] = field(default_factory=dict)
    report_metadata: Dict[str, Any] = field(default_factory=dict)
    function_intel_summary: Dict[str, Any] = field(default_factory=dict)
    behavior_summaries: Dict[str, Any] = field(default_factory=dict)
    call_graph_summary: Dict[str, Any] = field(default_factory=dict)
    cfg_intel_summary: Dict[str, Any] = field(default_factory=dict)
    naming_suggestions: Dict[str, Any] = field(default_factory=dict)
    applied_suggested_names: Dict[str, str] = field(default_factory=dict)
    data_flow_insights: Dict[str, Any] = field(default_factory=dict)
    api_semantics_insights: Dict[str, Any] = field(default_factory=dict)
    behavior_patterns: Dict[str, Any] = field(default_factory=dict)
    threat_narrative: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def session_path_for_sample(sample_path: str) -> Path:
        p = Path(sample_path)
        return p.with_suffix(p.suffix + ".erevos")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionState":
        return cls(
            renamed_functions=dict(data.get("renamed_functions") or {}),
            original_functions=dict(data.get("original_functions") or {}),
            comments=dict(data.get("comments") or {}),
            labels=dict(data.get("labels") or {}),
            bookmarks=list(data.get("bookmarks") or []),
            last_opened_file=str(data.get("last_opened_file") or ""),
            triage_metadata=dict(data.get("triage_metadata") or {}),
            report_metadata=dict(data.get("report_metadata") or {}),
            function_intel_summary=normalize_function_intel_summary(data.get("function_intel_summary")),
            behavior_summaries=normalize_behavior_summaries(data.get("behavior_summaries")),
            call_graph_summary=normalize_call_graph_summary(data.get("call_graph_summary")),
            cfg_intel_summary=normalize_cfg_intel_summary(data.get("cfg_intel_summary")),
            naming_suggestions=normalize_naming_suggestions(data.get("naming_suggestions")),
            applied_suggested_names=dict(data.get("applied_suggested_names") or {}),
            data_flow_insights=dict(data.get("data_flow_insights") or {}),
            api_semantics_insights=dict(data.get("api_semantics_insights") or {}),
            behavior_patterns=dict(data.get("behavior_patterns") or {}),
            threat_narrative=normalize_threat_narrative(data.get("threat_narrative")),
        )

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "SessionState":
        p = Path(path)
        if not p.exists():
            return cls()
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))
