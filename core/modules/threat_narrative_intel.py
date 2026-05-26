from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


def _confidence_rank(v: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(str(v or "").lower(), 0)


def _pick_capabilities(behavior_patterns: Dict[str, Any], api_semantics: Dict[str, Any]) -> List[Dict[str, Any]]:
    caps: Dict[str, Dict[str, Any]] = {}

    for p in (behavior_patterns or {}).get("patterns", []):
        if not isinstance(p, dict):
            continue
        name = str(p.get("pattern") or "").strip()
        if not name:
            continue
        current = caps.setdefault(name, {"capability": name, "confidence": "low", "evidence": []})
        if _confidence_rank(str(p.get("confidence"))) > _confidence_rank(current.get("confidence", "low")):
            current["confidence"] = str(p.get("confidence") or "low")
        for ev in (p.get("evidence_chain") or [])[:3]:
            if isinstance(ev, str) and ev not in current["evidence"]:
                current["evidence"].append(ev)

    for _, row in (api_semantics or {}).items():
        if not isinstance(row, dict):
            continue
        for call in (row.get("high_value_calls") or []):
            if not isinstance(call, dict):
                continue
            for tag in (call.get("capability_tags") or []):
                if not isinstance(tag, str) or not tag:
                    continue
                cap = tag.replace("_", " ")
                current = caps.setdefault(cap, {"capability": cap, "confidence": "medium", "evidence": []})
                if _confidence_rank(str(call.get("confidence"))) > _confidence_rank(current.get("confidence", "medium")):
                    current["confidence"] = str(call.get("confidence") or "medium")
                ev = f"{call.get('api')} @ {call.get('call_site')}"
                if ev not in current["evidence"]:
                    current["evidence"].append(ev)

    rows = list(caps.values())
    rows.sort(key=lambda x: (-_confidence_rank(x.get("confidence", "low")), x.get("capability", "")))
    return rows[:14]


def _build_execution_flow(behavior_patterns: Dict[str, Any]) -> List[str]:
    preferred = {
        "process injection": "opens target process → writes payload bytes → creates remote thread (candidate chain)",
        "downloader behavior": "initializes HTTP client → connects/requests remote content → writes downloaded data to disk (candidate chain)",
        "persistence via registry": "opens/creates registry key → writes autorun-like value (candidate chain)",
        "service installation": "opens SCM → creates service → starts/updates service configuration (candidate chain)",
        "file dropper": "creates output file → writes bytes to disk (candidate chain)",
        "reflective loader": "allocates memory → copies payload into memory → resolves loader APIs/thread start (candidate chain)",
        "network beaconing": "initializes networking → connects outbound → sends request/telemetry (candidate chain)",
    }
    flows: List[str] = []
    for p in (behavior_patterns or {}).get("patterns", []):
        if not isinstance(p, dict):
            continue
        name = str(p.get("pattern") or "")
        if p.get("confidence") == "low":
            continue
        if name in preferred and preferred[name] not in flows:
            flows.append(preferred[name])
    return flows[:8]


def _key_functions(function_intel_summary: Dict[str, Any], behavior_patterns: Dict[str, Any], call_graph_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    risky = (function_intel_summary or {}).get("top_risky_functions") or []
    for row in risky[:8]:
        if not isinstance(row, dict):
            continue
        start = row.get("start")
        if not start:
            continue
        evidence = []
        for indicator in (row.get("risk_indicators") or [])[:3]:
            evidence.append(f"risk indicator: {indicator}")
        for api in (row.get("suspicious_api_usage") or [])[:3]:
            evidence.append(f"suspicious api: {api}")
        rows.append({
            "function": start,
            "role": "high-risk function candidate",
            "evidence": evidence,
            "why_it_matters": "Contains suspicious static indicators and likely contributes to main behavior.",
        })

    related_map: Dict[str, List[str]] = {}
    for p in (behavior_patterns or {}).get("patterns", []):
        if not isinstance(p, dict):
            continue
        for fn in (p.get("involved_functions") or []):
            if not isinstance(fn, str):
                continue
            related_map.setdefault(fn, []).append(str(p.get("pattern") or "pattern"))
    for fn, pats in list(related_map.items())[:8]:
        rows.append({
            "function": fn,
            "role": "pattern-linked function",
            "evidence": [f"linked patterns: {', '.join(sorted(set(pats)))}"],
            "why_it_matters": "Appears directly in behavior-pattern evidence chain.",
        })

    hubs = (call_graph_summary or {}).get("top_hub_functions") or []
    for hub in hubs[:5]:
        if not isinstance(hub, dict):
            continue
        fn = hub.get("address")
        if not isinstance(fn, str):
            continue
        rows.append({
            "function": fn,
            "role": "call-graph hub",
            "evidence": [f"inbound={hub.get('inbound_degree', 0)} outbound={hub.get('outbound_degree', 0)}"],
            "why_it_matters": "Likely orchestrates or fans out behavior based on static call relationships.",
        })

    # dedupe by function keeping first
    seen = set()
    uniq = []
    for r in rows:
        fn = r.get("function")
        if fn in seen:
            continue
        seen.add(fn)
        uniq.append(r)
    return uniq[:12]


def _ioc_extract(strings: List[Any], api_semantics: Dict[str, Any]) -> Dict[str, Any]:
    text_rows = []
    for s in (strings or [])[:1500]:
        if isinstance(s, dict):
            v = str(s.get("text") or s.get("value") or "")
        else:
            v = str(s)
        if v:
            text_rows.append(v)

    url_re = re.compile(r"https?://[^\s'\"]+", re.I)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    path_re = re.compile(r"[A-Za-z]:\\[^\s\0]+|/[A-Za-z0-9_\-./]+")
    mutex_re = re.compile(r"(?:mutex|mtx)[_\-A-Za-z0-9]{2,}", re.I)

    urls, ips, paths, mutexes = set(), set(), set(), set()
    for t in text_rows:
        urls.update(url_re.findall(t))
        ips.update(ip_re.findall(t))
        paths.update(path_re.findall(t))
        for m in mutex_re.findall(t):
            mutexes.add(m)

    related_api = []
    for _, row in (api_semantics or {}).items():
        if not isinstance(row, dict):
            continue
        for call in (row.get("high_value_calls") or []):
            if not isinstance(call, dict):
                continue
            related_api.append(f"{call.get('api')} @ {call.get('call_site')}")

    return {
        "urls": sorted(urls)[:30],
        "ips": sorted(ips)[:30],
        "file_paths": sorted(paths)[:40],
        "mutexes": sorted(mutexes)[:30],
        "relevant_api_usage": related_api[:40],
    }


def _risk_from_patterns(patterns: Dict[str, Any]) -> Tuple[str, str]:
    highs = [p for p in (patterns or {}).get("high_confidence_patterns", []) if isinstance(p, dict)]
    meds = [p for p in (patterns or {}).get("patterns", []) if isinstance(p, dict) and p.get("confidence") == "medium"]
    high_names = {str(p.get("pattern") or "") for p in highs}
    if any(n in high_names for n in {"process injection", "reflective loader"}):
        return "critical", "High-confidence execution-manipulation patterns indicate potentially severe malicious capability candidates."
    if len(highs) >= 2:
        return "high", "Multiple high-confidence behavior candidates indicate elevated threat potential."
    if highs or len(meds) >= 2:
        return "medium", "Some evidence-backed behavior candidates were detected, but chain completeness is limited."
    return "low", "Only limited or low-confidence static indicators are present."


def build_threat_narrative(
    *,
    behavior_patterns: Dict[str, Any],
    api_semantics: Dict[str, Any],
    data_flow_insights: Dict[str, Any],
    function_intelligence: Dict[str, Any],
    call_graph_intelligence: Dict[str, Any],
    cfg_intelligence: Dict[str, Any],
    hashes_and_metadata: Dict[str, Any],
    extracted_strings: List[Any],
) -> Dict[str, Any]:
    capabilities = _pick_capabilities(behavior_patterns, api_semantics)
    flow = _build_execution_flow(behavior_patterns)
    key_functions = _key_functions(function_intelligence, behavior_patterns, call_graph_intelligence)
    iocs = _ioc_extract(extracted_strings, api_semantics)
    risk_level, risk_reason = _risk_from_patterns(behavior_patterns)

    high_patterns = [p for p in (behavior_patterns or {}).get("high_confidence_patterns", []) if isinstance(p, dict)]
    pattern_names = [str(p.get("pattern") or "unknown") for p in high_patterns[:4]]
    if pattern_names:
        short = f"Static evidence suggests possible {', '.join(pattern_names)} behavior candidate(s)."
    elif capabilities:
        short = "Static evidence indicates possible suspicious capabilities, but confidence remains limited."
    else:
        short = "Static analysis found limited high-confidence threat behavior indicators."

    overview_evidence = []
    for p in high_patterns[:5]:
        ev = (p.get("evidence_chain") or [])
        if ev:
            overview_evidence.append(f"{p.get('pattern')}: {ev[0]}")

    cfg_high = 0
    for _, row in (cfg_intelligence or {}).items():
        if not isinstance(row, dict):
            continue
        a = row.get("analysis") if isinstance(row.get("analysis"), dict) else row
        if any([
            a.get("abnormal_high_branch_density"),
            a.get("possible_opaque_predicate_hints"),
            a.get("unreachable_block_hints"),
        ]):
            cfg_high += 1

    narrative = {
        "threat_overview": {
            "summary": short,
            "evidence": overview_evidence[:8],
        },
        "capability_summary": capabilities,
        "execution_flow_summary": flow,
        "key_functions": key_functions,
        "indicators_of_compromise": iocs,
        "risk_assessment": {
            "level": risk_level,
            "reason": risk_reason,
            "supporting_factors": {
                "high_confidence_patterns": len(high_patterns),
                "total_patterns": len((behavior_patterns or {}).get("patterns") or []),
                "cfg_suspicious_functions": cfg_high,
                "metadata": {
                    "path": hashes_and_metadata.get("path"),
                    "entry_point": hashes_and_metadata.get("entry_point"),
                    "hashes": hashes_and_metadata.get("hashes") or {},
                },
            },
        },
        "caveats": [
            "Static analysis only: these findings indicate possible behavior and do not confirm runtime execution.",
            "Evidence is heuristic and based on recovered API/data-flow/call-graph artifacts, which may be incomplete.",
            "No malware-family attribution is made without explicit signature-backed evidence.",
        ],
        "heuristic_note": "Narrative is evidence-backed and uses cautious language (suggests/indicates/possible).",
    }

    # Ensure output includes data-flow anchor count for traceability.
    narrative["data_flow_anchor_count"] = sum(
        len((row.get("high_confidence_findings") or []))
        for _, row in (data_flow_insights or {}).items()
        if isinstance(row, dict)
    )
    return narrative
