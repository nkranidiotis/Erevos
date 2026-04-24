from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class PatternDefinition:
    name: str
    required_groups: Sequence[Sequence[str]]
    optional_apis: Sequence[str]
    ordered: bool
    minimum_evidence: int
    caveat: str


_PATTERN_DEFINITIONS: Sequence[PatternDefinition] = (
    PatternDefinition(
        name="process injection",
        required_groups=(("openprocess",), ("writeprocessmemory",), ("createremotethread", "ntcreatethreadex", "rtlcreateuserthread")),
        optional_apis=("virtualallocex", "virtualprotectex", "queueuserapc"),
        ordered=True,
        minimum_evidence=3,
        caveat="Static sequence suggests injection behavior candidate, but target process/runtime success is not proven.",
    ),
    PatternDefinition(
        name="downloader behavior",
        required_groups=(("winhttpopen", "internetopena", "internetopenw"), ("winhttpconnect", "internetconnecta", "internetconnectw", "internetopenurla", "internetopenurlw"), ("winhttpreaddata", "internetreadfile", "urlmonikerbindtostream", "urldownloadtofilea", "urldownloadtofilew"), ("createfilea", "createfilew", "writefile")),
        optional_apis=("winhttpsendrequest", "httpsendrequesta", "httpsendrequestw", "urldownloadtofilea", "urldownloadtofilew"),
        ordered=True,
        minimum_evidence=3,
        caveat="Static API chain suggests downloader candidate; payload origin and execution are unverified.",
    ),
    PatternDefinition(
        name="persistence via registry",
        required_groups=(("regopenkeyexa", "regopenkeyexw", "regcreatekeyexa", "regcreatekeyexw"), ("regsetvalueexa", "regsetvalueexw")),
        optional_apis=("regclosekey", "regdeletevaluea", "regdeletevaluew"),
        ordered=True,
        minimum_evidence=2,
        caveat="Registry sequence suggests persistence candidate; autorun impact depends on key/value data.",
    ),
    PatternDefinition(
        name="service installation",
        required_groups=(("openscmanagera", "openscmanagerw"), ("createservicea", "createservicew"), ("startservicea", "startservicew", "startservicectrldispatcherw")),
        optional_apis=("changeserviceconfiga", "changeserviceconfigw", "openservicea", "openservicew"),
        ordered=True,
        minimum_evidence=3,
        caveat="Service-control API chain suggests service installation candidate, not confirmed persistence.",
    ),
    PatternDefinition(
        name="file dropper",
        required_groups=(("createfilea", "createfilew"), ("writefile",)),
        optional_apis=("setfileattributesa", "setfileattributesw", "movefileexa", "movefileexw"),
        ordered=True,
        minimum_evidence=2,
        caveat="File write sequence suggests dropper candidate; dropped content is unknown in static-only context.",
    ),
    PatternDefinition(
        name="reflective loader",
        required_groups=(("virtualalloc", "virtualallocex"), ("writeprocessmemory", "rtlmovememory", "memcpy"), ("createthread", "createremotethread", "ntcreatethreadex"), ("getprocaddress", "loadlibrarya", "loadlibraryw")),
        optional_apis=("virtualprotect", "virtualprotectex", "flushinstructioncache"),
        ordered=False,
        minimum_evidence=3,
        caveat="API combination suggests reflective-loading candidate; in-memory PE mapping is not directly observed.",
    ),
    PatternDefinition(
        name="network beaconing",
        required_groups=(("socket", "wsastartup", "winhttpopen", "internetopena", "internetopenw"), ("connect", "winhttpconnect", "internetconnecta", "internetconnectw"), ("send", "wsasend", "httpsendrequesta", "httpsendrequestw", "winhttpsendrequest", "internetopenurla", "internetopenurlw")),
        optional_apis=("recv", "wsarecv", "sleep", "waitforsingleobject"),
        ordered=True,
        minimum_evidence=3,
        caveat="Outbound sequence suggests beaconing candidate; periodicity/C2 intent is not confirmed statically.",
    ),
)


def _api_key(name: str) -> str:
    raw = (name or "").split("!")[-1].strip().lower()
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _to_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    txt = str(value or "").strip().lower()
    try:
        return int(txt, 16) if txt.startswith("0x") else int(txt)
    except Exception:
        return 0


def _extract_call_rows(api_semantics: Dict[str, Any], data_flow: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    for row in (api_semantics or {}).get("api_semantics_calls", []):
        if not isinstance(row, dict):
            continue
        api = row.get("api")
        site = str(row.get("call_site") or "")
        key = (_api_key(str(api or "")), site)
        if not key[0] or key in seen:
            continue
        seen.add(key)
        rows.append({
            "api": str(api or ""),
            "api_key": key[0],
            "call_site": site,
            "site_value": _to_int(site),
            "arguments": list(row.get("interpreted_arguments") or []),
            "semantic_tags": list(row.get("capability_tags") or []),
        })
    for row in (data_flow or {}).get("api_argument_insights", []):
        if not isinstance(row, dict):
            continue
        api = row.get("api")
        site = str(row.get("call_site") or "")
        key = (_api_key(str(api or "")), site)
        if not key[0] or key in seen:
            continue
        seen.add(key)
        args = [f"{a.get('register')}={a.get('value')} (estimated)" for a in (row.get("arguments") or []) if isinstance(a, dict)]
        rows.append({
            "api": str(api or ""),
            "api_key": key[0],
            "call_site": site,
            "site_value": _to_int(site),
            "arguments": args,
            "semantic_tags": [],
        })
    rows.sort(key=lambda r: (r.get("site_value", 0), r.get("api_key", "")))
    return rows


def _match_group(calls: Sequence[Dict[str, Any]], group: Sequence[str], after: int = -1) -> Optional[Tuple[int, Dict[str, Any]]]:
    aliases = set(group)
    for idx, row in enumerate(calls):
        if idx <= after:
            continue
        if row.get("api_key") in aliases:
            return idx, row
    return None


def _functions_related(functions: Iterable[str], call_graph_model: Optional[Dict[str, Any]], call_graph_summary: Optional[Dict[str, Any]]) -> bool:
    fn = [f for f in functions if f]
    if len(fn) <= 1:
        return True
    edges = {(e.get("caller"), e.get("callee")) for e in (call_graph_model or {}).get("edges", []) if isinstance(e, dict)}
    for i in range(len(fn)):
        for j in range(i + 1, len(fn)):
            a, b = fn[i], fn[j]
            if (a, b) in edges or (b, a) in edges:
                return True
    for row in (call_graph_summary or {}).get("suspicious_call_chains", []):
        chain = row.get("chain") if isinstance(row, dict) else None
        if not isinstance(chain, list):
            continue
        if len(set(fn).intersection(set(chain))) >= 2:
            return True
    return False


def _detect_for_calls(pattern: PatternDefinition, calls: Sequence[Dict[str, Any]]) -> Tuple[int, List[Dict[str, Any]], int]:
    matched: List[Dict[str, Any]] = []
    cursor = -1
    for group in pattern.required_groups:
        hit = _match_group(calls, group, after=cursor if pattern.ordered else -1)
        if not hit:
            continue
        idx, row = hit
        matched.append(row)
        if pattern.ordered:
            cursor = idx

    optional_hits = [row for row in calls if row.get("api_key") in set(pattern.optional_apis)]
    evidence_score = len(matched) + min(2, len(optional_hits))
    return len(matched), (matched + optional_hits[:2]), evidence_score


def detect_behavior_patterns(
    api_semantics_by_function: Dict[str, Any],
    data_flow_by_function: Optional[Dict[str, Any]] = None,
    call_graph_model: Optional[Dict[str, Any]] = None,
    call_graph_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    per_function_calls: Dict[str, List[Dict[str, Any]]] = {}
    for fn, sem in (api_semantics_by_function or {}).items():
        per_function_calls[fn] = _extract_call_rows(sem or {}, (data_flow_by_function or {}).get(fn) or {})

    patterns: List[Dict[str, Any]] = []
    all_calls: List[Tuple[str, Dict[str, Any]]] = []
    for fn, rows in per_function_calls.items():
        for row in rows:
            all_calls.append((fn, row))
    all_calls.sort(key=lambda t: (t[1].get("site_value", 0), t[0]))

    for p in _PATTERN_DEFINITIONS:
        fn_hits: List[Dict[str, Any]] = []
        for fn, calls in per_function_calls.items():
            if not calls:
                continue
            matched_count, evidence_rows, score = _detect_for_calls(p, calls)
            if not evidence_rows:
                continue
            if matched_count >= len(p.required_groups) and score >= p.minimum_evidence:
                conf = "high"
            elif matched_count >= max(1, len(p.required_groups) - 1):
                conf = "medium"
            else:
                conf = "low"
            fn_hits.append({
                "pattern": p.name,
                "confidence": conf,
                "scope": "per-function",
                "involved_functions": [fn],
                "evidence_chain": [f"{r.get('api')} @ {r.get('call_site')} | args={r.get('arguments') or []}" for r in evidence_rows],
                "caveats": [p.caveat],
                "candidate_statement": f"Sequence suggests {p.name} candidate.",
            })

        if fn_hits:
            fn_hits.sort(key=lambda r: {"high": 0, "medium": 1, "low": 2}.get(r.get("confidence"), 9))
            patterns.append(fn_hits[0])
            continue

        # Cross-function path: use global calls only when all required groups are present.
        global_calls = [row for _, row in all_calls]
        matched_count, evidence_rows, score = _detect_for_calls(p, global_calls)
        if matched_count < len(p.required_groups):
            continue
        involved = []
        for ev in evidence_rows:
            for fn, row in all_calls:
                if row is ev and fn not in involved:
                    involved.append(fn)
        related = _functions_related(involved, call_graph_model, call_graph_summary)
        confidence = "high" if related and score >= p.minimum_evidence else "medium"
        patterns.append({
            "pattern": p.name,
            "confidence": confidence,
            "scope": "cross-function",
            "involved_functions": involved,
            "evidence_chain": [f"{r.get('api')} @ {r.get('call_site')} | args={r.get('arguments') or []}" for r in evidence_rows],
            "caveats": [p.caveat, "Cross-function relation inferred from static call graph evidence."],
            "candidate_statement": f"Cross-function sequence suggests {p.name} candidate.",
        })

    patterns.sort(key=lambda r: ({"high": 0, "medium": 1, "low": 2}.get(r.get("confidence"), 9), r.get("pattern", "")))
    return {
        "patterns": patterns,
        "high_confidence_patterns": [p for p in patterns if p.get("confidence") == "high"],
        "heuristic_note": "Behavior patterns are conservative static candidates derived from API/data-flow sequences.",
    }
