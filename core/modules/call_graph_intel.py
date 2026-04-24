from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

from .function_intel import FunctionProfile
from .xrefs_foundation import XrefRecord


def build_call_graph_model(
    profiles: Dict[int, FunctionProfile],
    xrefs: List[XrefRecord],
) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges_map: Dict[Tuple[int, Optional[int]], Dict[str, Any]] = {}

    for va, p in (profiles or {}).items():
        nodes[f"0x{va:08X}"] = {
            "address": f"0x{va:08X}",
            "suspicious": bool(p.suspicious_api_usage or p.risk_indicators),
            "suspicious_api_usage": list(p.suspicious_api_usage or []),
            "risk_indicators": list(p.risk_indicators or []),
            "inbound_degree": 0,
            "outbound_degree": 0,
        }

    for xr in (xrefs or []):
        if xr.xref_type != "call":
            continue
        caller = xr.src_function
        callee = xr.dst_function if xr.dst_function is not None else xr.dst
        if caller is None:
            continue
        key = (int(caller), int(callee) if isinstance(callee, int) else None)
        row = edges_map.setdefault(
            key,
            {
                "caller": f"0x{int(caller):08X}",
                "callee": f"0x{int(callee):08X}" if isinstance(callee, int) else "<unresolved>",
                "call_count": 0,
                "confidence": xr.confidence,
                "unresolved": not isinstance(callee, int),
                "suspicious_indicator": False,
            },
        )
        row["call_count"] += 1
        if xr.confidence == "low":
            row["confidence"] = "low"

    for e in edges_map.values():
        caller = e["caller"]
        callee = e["callee"]
        if caller in nodes:
            nodes[caller]["outbound_degree"] += 1
        if callee in nodes:
            nodes[callee]["inbound_degree"] += 1
        e["suspicious_indicator"] = bool(
            (caller in nodes and nodes[caller]["suspicious"]) or
            (callee in nodes and nodes[callee]["suspicious"]) or
            e.get("unresolved")
        )

    return {
        "nodes": list(nodes.values()),
        "edges": sorted(edges_map.values(), key=lambda x: (x["caller"], x["callee"])),
    }


def analyze_call_graph(graph: Dict[str, Any], entry_point: Optional[int] = None) -> Dict[str, Any]:
    nodes = {n["address"]: n for n in (graph.get("nodes") or []) if isinstance(n, dict)}
    edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]

    adj: Dict[str, List[str]] = defaultdict(list)
    for e in edges:
        if e.get("callee") != "<unresolved>":
            adj[e["caller"]].append(e["callee"])

    ep_hex = f"0x{int(entry_point):08X}" if entry_point is not None else None
    reachable = set()
    if ep_hex and ep_hex in nodes:
        dq = deque([ep_hex])
        reachable.add(ep_hex)
        while dq:
            cur = dq.popleft()
            for nxt in adj.get(cur, []):
                if nxt in nodes and nxt not in reachable:
                    reachable.add(nxt)
                    dq.append(nxt)

    hubs = sorted(
        nodes.values(),
        key=lambda n: (int(n.get("outbound_degree", 0)) + int(n.get("inbound_degree", 0))),
        reverse=True,
    )[:15]
    hub_rows = [
        {
            "address": n["address"],
            "inbound_degree": n.get("inbound_degree", 0),
            "outbound_degree": n.get("outbound_degree", 0),
            "suspicious": n.get("suspicious", False),
        }
        for n in hubs
    ]

    leaf_rows = [
        {"address": n["address"], "inbound_degree": n.get("inbound_degree", 0), "outbound_degree": n.get("outbound_degree", 0)}
        for n in nodes.values()
        if int(n.get("outbound_degree", 0)) == 0 and int(n.get("inbound_degree", 0)) > 0
    ][:25]

    isolated = [
        n["address"]
        for n in nodes.values()
        if int(n.get("outbound_degree", 0)) == 0 and int(n.get("inbound_degree", 0)) == 0
    ][:50]

    suspicious_nodes = {n["address"] for n in nodes.values() if n.get("suspicious")}
    suspicious_chains = []
    for e in edges:
        c1, c2 = e["caller"], e["callee"]
        if c2 == "<unresolved>":
            continue
        if c1 in suspicious_nodes or c2 in suspicious_nodes:
            suspicious_chains.append(
                {
                    "chain": [c1, c2],
                    "reason": "suspicious endpoint in call relation",
                    "confidence": e.get("confidence", "medium"),
                }
            )
    suspicious_chains = suspicious_chains[:25]

    bridges = []
    for n in nodes.values():
        if n.get("suspicious_api_usage") and int(n.get("inbound_degree", 0)) > 0:
            bridges.append(
                {
                    "address": n["address"],
                    "suspicious_apis": n.get("suspicious_api_usage", [])[:5],
                    "inbound_degree": n.get("inbound_degree", 0),
                }
            )
    bridges = bridges[:25]

    return {
        "entry_point": ep_hex,
        "entry_reachable_functions": sorted(reachable),
        "top_hub_functions": hub_rows,
        "leaf_functions": leaf_rows,
        "suspicious_call_chains": suspicious_chains,
        "suspicious_api_bridge_functions": bridges,
        "isolated_or_unreferenced_functions": isolated,
        "heuristic_note": "Call graph is static and heuristic; unresolved/low-confidence edges are explicitly marked.",
    }
